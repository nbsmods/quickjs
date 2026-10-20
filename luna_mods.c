/*
 * Luna mod loader.
 *
 * Discovers mod packages on disk, chooses one loadable copy per package,
 * copies read only (APK asset) copies into the app data directory when
 * needed, resolves the dependency graph declared by manifest.json and
 * evaluates the entrypoint bytecode of every mod in dependency order.
 *
 * Every mod is an ES module, so "exports" are the module exports object and
 * mods consume each other with plain import statements. The registry is also
 * reachable from C through luna_mods_exports() so hosts can expose it to their
 * own scripting surface.
 *
 * manifest.json fields:
 *   name          package name, required, e.g. "com.luna.mods.aim"
 *   version       dotted numeric version with optional -prerelease, required,
 *                 e.g. "1.4.2" or "2.0.0-beta.3"
 *   author        free form
 *   dependencies  array of "name" or "name@range" strings, required deps
 *   optionalDependencies  same shape; soft links, never fail a mod
 *   conflicts     same shape (or "breaks"); refuse to load when a selected
 *                 mod matches
 *   loadBefore    array of package names to evaluate before, when present
 *   loadAfter     array of package names to evaluate after, when present
 *   icon          file name of the mod icon, relative to the mod directory
 *   entrypoint    bytecode file, defaults to "main.luna"
 *
 * A dependency on the synthetic package "luna" checks the loader API
 * version (LUNA_MODS_API_VERSION).
 *
 * Range grammar (space separated terms must all match, "||" separates
 * alternatives):
 *   1.2.3         exactly 1.2.3
 *   1.2 / 1.2.x   [1.2.0, 1.3.0)
 *   1 / 1.x / *   [1.0.0, 2.0.0) / any
 *   =1.2.3        exactly 1.2.3
 *   >1.2.2        1.2.3 and up, excluding 1.2.2
 *   >=1.2.2       at least 1.2.2
 *   <2.0.0        below 2.0.0
 *   <=2.0.0       at most 2.0.0
 *   ~1.2.3        [1.2.3, 1.3.0)   patch level changes
 *   ^1.2.3        [1.2.3, 2.0.0)   leftmost non zero component
 *   ^0.2.3        [0.2.3, 0.3.0)
 *   ^0.0.3        [0.0.3, 0.0.4)
 *
 * A version may carry a semver prerelease ("1.2.3-beta.2"); a release sorts
 * above its prereleases. A range only opts into prereleases through a bound
 * that names one for the same core ("^1.2.3-beta" accepts "1.2.3-rc") or
 * when the dependency omits a range or uses "*" ("any installed copy").
 */
#include "luna_mods.h"
#include "quickjs.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* ------------------------------------------------------------------ */
/* limits and names                                                    */
/* ------------------------------------------------------------------ */

#define LUNA_MANIFEST_MAX      (1024 * 1024)            /* 1 MiB */
#define LUNA_ENTRY_MAX         (256u * 1024 * 1024)     /* 256 MiB */
#define LUNA_MOD_NAME_MAX      127
#define LUNA_MOD_VERSION_MAX   63
#define LUNA_MOD_PATH_MAX      255
#define LUNA_MOD_DEP_MAX       255
#define LUNA_MOD_LIST_MAX      64
#define LUNA_SCAN_ISSUE_MAX    256
#define LUNA_VERSION_COMP_MAX  999999999

/* ------------------------------------------------------------------ */
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

/* bounded copy that always NUL terminates, including the cap == 0 case */
static void luna_copy_str(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (!dst || cap == 0)
        return;
    n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static char *luna_read_file(const char *path, size_t max_size, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long size;

    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = ftell(f);
    if (size < 0 ||
        (max_size != 0 && (unsigned long long)size > (unsigned long long)max_size) ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = (char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[size] = '\0';
    if (len)
        *len = (size_t)size;
    return buf;
}

static int luna_is_dir(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int luna_is_file(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* mkdir -p */
static int luna_mkdir_p(const char *path)
{
    char tmp[1024];
    size_t len;
    char *p;

    len = strlen(path);
    if (len >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, len + 1);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int luna_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);

    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* Package names double as path components (materialization) and module
 * specifiers, so keep them to a conservative, path safe set. */
static int luna_name_syntax_valid(const char *name)
{
    size_t i, n;

    if (!name)
        return 0;
    n = strlen(name);
    if (n == 0 || n > LUNA_MOD_NAME_MAX)
        return 0;
    if (name[0] == '.')
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == '-' || c == '+'))
            return 0;
    }
    return 1;
}

/* "luna" is the synthetic loader API package, so a real package may not
 * shadow it. Dependency names still use the syntax check above. */
static int luna_package_name_valid(const char *name)
{
    return luna_name_syntax_valid(name) &&
           strcmp(name, LUNA_MODS_API_NAME) != 0;
}

/* Relative file names used by the manifest must not escape the package
 * directory: reject absolute paths, backslashes, empty segments and any
 * "." or ".." component. */
static int luna_path_relative_valid(const char *path)
{
    size_t n;

    if (!path || !*path)
        return 0;
    n = strlen(path);
    if (n > LUNA_MOD_PATH_MAX || path[0] == '/' || path[0] == '\\')
        return 0;
    while (*path) {
        const char *segment = path;
        size_t len;

        while (*path && *path != '/') {
            unsigned char c = (unsigned char)*path;

            if (c == '\\' || c < 0x20)
                return 0;
            path++;
        }
        len = (size_t)(path - segment);
        if (len == 0)
            return 0;       /* "//" or a trailing slash */
        if ((len == 1 && segment[0] == '.') ||
            (len == 2 && segment[0] == '.' && segment[1] == '.'))
            return 0;
        if (*path == '/')
            path++;
    }
    return 1;
}

/* Split "com.example.core@^1.2.0" into name and spec. */
static void luna_split_dep(const char *dep, char *name, size_t name_cap, const char **spec)
{
    const char *at = strchr(dep, '@');
    size_t n = at ? (size_t)(at - dep) : strlen(dep);

    if (n >= name_cap)
        n = name_cap - 1;
    memcpy(name, dep, n);
    name[n] = '\0';
    *spec = at ? at + 1 : NULL;
}

static int luna_copy_tree(const char *src, const char *dst)
{
    DIR *d;
    struct dirent *de;

    d = opendir(src);
    if (!d)
        return -1;
    if (!luna_is_dir(dst) && luna_mkdir_p(dst) != 0) {
        closedir(d);
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char spath[1024], dpath[1024];
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (luna_join(spath, sizeof(spath), src, de->d_name) != 0)
            continue;
        if (luna_join(dpath, sizeof(dpath), dst, de->d_name) != 0)
            continue;
        /* do not follow symlinks: a package must not be able to pull an
         * arbitrary host tree into the writable mod directory */
        if (lstat(spath, &st) != 0 || S_ISLNK(st.st_mode))
            continue;
        if (S_ISDIR(st.st_mode)) {
            if (luna_copy_tree(spath, dpath) != 0) {
                closedir(d);
                return -1;
            }
        } else {
            size_t len;
            char *data = luna_read_file(spath, 0, &len);
            FILE *out;

            if (!data)
                continue;
            out = fopen(dpath, "wb");
            if (!out) {
                free(data);
                closedir(d);
                return -1;
            }
            if (len && fwrite(data, 1, len, out) != len) {
                fclose(out);
                free(data);
                closedir(d);
                return -1;
            }
            fclose(out);
            free(data);
        }
    }
    closedir(d);
    return 0;
}

/* ------------------------------------------------------------------ */
/* manifest                                                            */
/* ------------------------------------------------------------------ */

typedef struct LunaManifest {
    char name[256];
    char version[64];
    char author[128];
    char icon[256];
    char entry[256];
    char **deps;
    size_t dep_count;
    char **opt_deps;
    size_t opt_dep_count;
    char **conflicts;
    size_t conflict_count;
    char **before;
    size_t before_count;
    char **after;
    size_t after_count;
} LunaManifest;

static void luna_manifest_free_list(char **items, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        free(items[i]);
    free(items);
}

static void luna_manifest_clear(LunaManifest *m)
{
    luna_manifest_free_list(m->deps, m->dep_count);
    luna_manifest_free_list(m->opt_deps, m->opt_dep_count);
    luna_manifest_free_list(m->conflicts, m->conflict_count);
    luna_manifest_free_list(m->before, m->before_count);
    luna_manifest_free_list(m->after, m->after_count);
    memset(m, 0, sizeof(*m));
}

/* Turn the pending JS exception into a one line manifest error and clear it,
 * so a broken manifest cannot leak a pending exception into the host. */
static void luna_js_error(JSContext *ctx, char *out, size_t cap)
{
    JSValue exc = JS_GetException(ctx);
    const char *s = JS_ToCString(ctx, exc);

    if (s) {
        snprintf(out, cap, "%s", s);
        JS_FreeCString(ctx, s);
    } else {
        snprintf(out, cap, "invalid JSON");
        JS_GetException(ctx);   /* clear a secondary conversion failure */
    }
    JS_FreeValue(ctx, exc);
}

/* Read a string field out of an already parsed manifest object. */
static int luna_manifest_str(JSContext *ctx, JSValueConst obj, const char *field,
                             char *out, size_t out_cap, int required,
                             char *err, size_t err_cap)
{
    JSValue v = JS_GetPropertyStr(ctx, obj, field);
    const char *s;
    size_t len;
    int rc = -1;

    out[0] = '\0';
    if (JS_IsException(v)) {
        snprintf(err, err_cap, "cannot read field '%s'", field);
        luna_js_error(ctx, err, err_cap);
        return -1;
    }
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        if (required) {
            snprintf(err, err_cap, "missing field '%s'", field);
            return -1;
        }
        return 0;
    }
    if (!JS_IsString(v)) {
        snprintf(err, err_cap, "field '%s' must be a string", field);
        goto done;
    }
    s = JS_ToCStringLen(ctx, &len, v);
    if (!s) {
        snprintf(err, err_cap, "cannot read field '%s'", field);
        luna_js_error(ctx, err, err_cap);
        goto done;
    }
    if (strlen(s) != len) {
        snprintf(err, err_cap, "field '%s' contains a NUL byte", field);
        JS_FreeCString(ctx, s);
        goto done;
    }
    if (len >= out_cap) {
        snprintf(err, err_cap, "field '%s' is too long (max %zu bytes)", field, out_cap - 1);
        JS_FreeCString(ctx, s);
        goto done;
    }
    if (required && len == 0) {
        snprintf(err, err_cap, "field '%s' must not be empty", field);
        JS_FreeCString(ctx, s);
        goto done;
    }
    memcpy(out, s, len + 1);
    JS_FreeCString(ctx, s);
    rc = 0;

 done:
    JS_FreeValue(ctx, v);
    return rc;
}

static void luna_free_list(char **items, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        free(items[i]);
    free(items);
}

static int luna_manifest_list(JSContext *ctx, JSValueConst obj, const char *field,
                              char ***out, size_t *out_count,
                              char *err, size_t err_cap)
{
    JSValue arr = JS_GetPropertyStr(ctx, obj, field);
    JSValue len;
    char **items = NULL;
    size_t count = 0;
    int32_t n, i;

    *out = NULL;
    *out_count = 0;
    if (JS_IsException(arr)) {
        snprintf(err, err_cap, "cannot read field '%s'", field);
        luna_js_error(ctx, err, err_cap);
        return -1;
    }
    if (JS_IsUndefined(arr) || JS_IsNull(arr)) {
        JS_FreeValue(ctx, arr);
        return 0;
    }
    if (!JS_IsArray(ctx, arr)) {
        snprintf(err, err_cap, "field '%s' must be an array", field);
        JS_FreeValue(ctx, arr);
        return -1;
    }
    len = JS_GetPropertyStr(ctx, arr, "length");
    if (JS_IsException(len) || JS_ToInt32(ctx, &n, len) != 0 || n < 0) {
        snprintf(err, err_cap, "field '%s' has an invalid length", field);
        JS_FreeValue(ctx, len);
        JS_FreeValue(ctx, arr);
        return -1;
    }
    JS_FreeValue(ctx, len);
    if (n > LUNA_MOD_LIST_MAX) {
        snprintf(err, err_cap, "field '%s' has too many entries (max %d)",
                 field, LUNA_MOD_LIST_MAX);
        JS_FreeValue(ctx, arr);
        return -1;
    }
    for (i = 0; i < n; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, arr, (uint32_t)i);
        const char *s;
        size_t slen;
        char **grown;
        char *copy;

        if (JS_IsException(item)) {
            snprintf(err, err_cap, "cannot read entry %d of '%s'", i, field);
            luna_js_error(ctx, err, err_cap);
            goto fail;
        }
        if (!JS_IsString(item)) {
            snprintf(err, err_cap, "entry %d of '%s' must be a string", i, field);
            JS_FreeValue(ctx, item);
            goto fail;
        }
        s = JS_ToCStringLen(ctx, &slen, item);
        if (!s) {
            snprintf(err, err_cap, "cannot read entry %d of '%s'", i, field);
            luna_js_error(ctx, err, err_cap);
            JS_FreeValue(ctx, item);
            goto fail;
        }
        if (slen == 0 || slen > LUNA_MOD_DEP_MAX || strlen(s) != slen) {
            snprintf(err, err_cap, "entry %d of '%s' has an invalid length", i, field);
            JS_FreeCString(ctx, s);
            JS_FreeValue(ctx, item);
            goto fail;
        }
        copy = strdup(s);
        JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, item);
        if (!copy) {
            snprintf(err, err_cap, "out of memory");
            goto fail;
        }
        grown = (char **)realloc(items, (count + 1) * sizeof(char *));
        if (!grown) {
            free(copy);
            snprintf(err, err_cap, "out of memory");
            goto fail;
        }
        items = grown;
        items[count++] = copy;
    }
    JS_FreeValue(ctx, arr);
    *out = items;
    *out_count = count;
    return 0;

 fail:
    JS_FreeValue(ctx, arr);
    luna_free_list(items, count);
    return -1;
}

static int luna_manifest_load(JSContext *ctx, const char *dir, LunaManifest *m,
                              char *err, size_t err_cap)
{
    char path[1024], *json;
    size_t len;
    JSValue parsed;
    int rc = -1;

    memset(m, 0, sizeof(*m));
    snprintf(m->entry, sizeof(m->entry), "main.luna");

    if (luna_join(path, sizeof(path), dir, LUNA_MODS_MANIFEST) != 0) {
        snprintf(err, err_cap, "manifest path is too long");
        return -1;
    }
    json = luna_read_file(path, LUNA_MANIFEST_MAX, &len);
    if (!json) {
        snprintf(err, err_cap, "cannot read manifest.json (missing or larger than %d bytes)",
                 LUNA_MANIFEST_MAX);
        return -1;
    }
    /* use the engine parser directly: no dependence on a possibly patched
     * global JSON.parse and no JS call overhead per manifest */
    parsed = JS_ParseJSON(ctx, json, len, path);
    free(json);
    if (JS_IsException(parsed)) {
        luna_js_error(ctx, err, err_cap);
        return -1;
    }
    if (!JS_IsObject(parsed)) {
        snprintf(err, err_cap, "manifest.json must contain a JSON object");
        goto done;
    }

    if (luna_manifest_str(ctx, parsed, "name", m->name, sizeof(m->name), 1,
                          err, err_cap) != 0)
        goto done;
    if (luna_manifest_str(ctx, parsed, "version", m->version, sizeof(m->version), 1,
                          err, err_cap) != 0)
        goto done;
    if (luna_manifest_str(ctx, parsed, "author", m->author, sizeof(m->author), 0,
                          err, err_cap) != 0)
        goto done;
    if (luna_manifest_str(ctx, parsed, "icon", m->icon, sizeof(m->icon), 0,
                          err, err_cap) != 0)
        goto done;
    if (luna_manifest_str(ctx, parsed, "entrypoint", m->entry, sizeof(m->entry), 0,
                          err, err_cap) != 0)
        goto done;
    if (!m->entry[0])
        snprintf(m->entry, sizeof(m->entry), "main.luna");
    if (luna_manifest_list(ctx, parsed, "dependencies", &m->deps, &m->dep_count,
                           err, err_cap) != 0)
        goto done;
    if (luna_manifest_list(ctx, parsed, "optionalDependencies", &m->opt_deps,
                           &m->opt_dep_count, err, err_cap) != 0)
        goto done;
    if (luna_manifest_list(ctx, parsed, "conflicts", &m->conflicts,
                           &m->conflict_count, err, err_cap) != 0)
        goto done;
    if (m->conflict_count == 0 &&
        luna_manifest_list(ctx, parsed, "breaks", &m->conflicts,
                           &m->conflict_count, err, err_cap) != 0)
        goto done;
    if (luna_manifest_list(ctx, parsed, "loadBefore", &m->before, &m->before_count,
                           err, err_cap) != 0)
        goto done;
    if (luna_manifest_list(ctx, parsed, "loadAfter", &m->after, &m->after_count,
                           err, err_cap) != 0)
        goto done;
    rc = 0;

 done:
    JS_FreeValue(ctx, parsed);
    if (rc != 0)
        luna_manifest_clear(m);
    return rc;
}

/* ------------------------------------------------------------------ */
/* versions                                                            */
/* ------------------------------------------------------------------ */

/*
 * Versions are one to four dotted numeric components ("1.4.2"), optionally
 * followed by a semver style prerelease ("1.0.0-beta.2") and build metadata
 * ("+build.7", ignored for ordering). Missing components count as zero, so
 * "1.2" equals "1.2.0". A release sorts above its prereleases. A requirement
 * is a set of alternatives separated by "||"; each alternative is a set of
 * whitespace separated terms that must all match. See the file header for the
 * grammar.
 */

typedef struct LunaVersion {
    int comp[4];
    int count;
    char pre[32];       /* empty for a release */
} LunaVersion;

typedef struct LunaRange {
    int has_lower;
    char lower[96];
    int lower_inclusive;
    int has_upper;
    char upper[96];
    int upper_inclusive;
    /* set by a bare "*"/empty requirement: prereleases are eligible too */
    int allow_prerelease;
} LunaRange;

#define LUNA_REQ_MAX_ALTERNATIVES 4

typedef struct LunaRequirement {
    LunaRange alternatives[LUNA_REQ_MAX_ALTERNATIVES];
    int count;
    int valid;
} LunaRequirement;

/* Parse one numeric component; sets *next to NULL when the version ends.
 * Values saturate at LUNA_VERSION_COMP_MAX so hostile input in the loose
 * fallback path cannot overflow. */
static int luna_dot_num(const char *s, const char **next)
{
    int v = 0;
    int digits = 0;

    while (*s >= '0' && *s <= '9') {
        int digit = *s++ - '0';

        if (v > (LUNA_VERSION_COMP_MAX - digit) / 10)
            v = LUNA_VERSION_COMP_MAX;
        else
            v = v * 10 + digit;
        digits = 1;
    }
    if (digits && *s == '.')
        *next = s + 1;
    else
        *next = NULL;
    return v;
}

static int luna_pre_ident_is_numeric(const char *s, size_t len)
{
    size_t i;

    if (len == 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
    }
    return 1;
}

/* Semver prerelease ordering: numeric identifiers compare numerically and
 * sort before alphanumeric ones; a shorter list sorts first when otherwise
 * equal. */
static int luna_pre_cmp(const char *a, const char *b)
{
    for (;;) {
        const char *ea = strchr(a, '.');
        const char *eb = strchr(b, '.');
        size_t la = ea ? (size_t)(ea - a) : strlen(a);
        size_t lb = eb ? (size_t)(eb - b) : strlen(b);
        int na = luna_pre_ident_is_numeric(a, la);
        int nb = luna_pre_ident_is_numeric(b, lb);
        int c;

        if (na && nb) {
            while (la > 1 && *a == '0') {
                a++;
                la--;
            }
            while (lb > 1 && *b == '0') {
                b++;
                lb--;
            }
            if (la != lb)
                return la < lb ? -1 : 1;
            c = memcmp(a, b, la);
            if (c != 0)
                return c < 0 ? -1 : 1;
        } else if (na != nb) {
            return na ? -1 : 1;
        } else {
            size_t n = la < lb ? la : lb;

            c = memcmp(a, b, n);
            if (c != 0)
                return c < 0 ? -1 : 1;
            if (la != lb)
                return la < lb ? -1 : 1;
        }
        if (!ea && !eb)
            return 0;
        if (!ea)
            return -1;
        if (!eb)
            return 1;
        a = ea + 1;
        b = eb + 1;
    }
}

/* Strict parser for a version or a range operand. When wildcard is non-NULL
 * an x, X or * component is allowed as the final component and its index is
 * returned; wildcard ranges cannot have a prerelease. Build metadata is
 * validated and ignored. Returns 0 on success. */
static int luna_version_parse_full(const char *s, LunaVersion *v, int *wildcard)
{
    int n = 0;

    memset(v, 0, sizeof(*v));
    if (wildcard)
        *wildcard = -1;
    if (!s || !*s)
        return -1;
    for (;;) {
        int value = 0;
        int digits = 0;
        int digit;

        if (*s == 'x' || *s == 'X' || *s == '*') {
            if (!wildcard)
                return -1;
            *wildcard = n;
            v->count = n;
            s++;
            return (*s == '\0') ? 0 : -1;
        }
        if (*s < '0' || *s > '9' || n >= 4)
            return -1;
        while (*s >= '0' && *s <= '9') {
            digit = *s - '0';
            if (value > (LUNA_VERSION_COMP_MAX - digit) / 10)
                return -1;
            value = value * 10 + digit;
            digits = 1;
            s++;
        }
        if (!digits)
            return -1;
        v->comp[n++] = value;
        if (*s == '\0')
            break;
        if (*s != '.')
            break;      /* prerelease or build metadata follows */
        s++;
        if (*s == '\0')
            return -1;
    }
    v->count = n;
    if (*s == '-') {
        const char *start;
        size_t len = 0;

        s++;
        start = s;
        while (*s && *s != '+') {
            unsigned char c = (unsigned char)*s;

            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '-' || c == '.'))
                return -1;
            if (c == '.' &&
                (s == start || s[-1] == '.' || s[1] == '\0' || s[1] == '+'))
                return -1;
            len++;
            if (len >= sizeof(v->pre))
                return -1;
            s++;
        }
        if (len == 0)
            return -1;
        memcpy(v->pre, start, len);
        v->pre[len] = '\0';
    }
    if (*s == '+') {
        s++;
        if (!*s)
            return -1;
        while (*s) {
            unsigned char c = (unsigned char)*s++;

            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '-' || c == '.'))
                return -1;
        }
    }
    return (*s == '\0') ? 0 : -1;
}

int luna_version_cmp(const char *a, const char *b)
{
    LunaVersion va, vb;
    int i;

    if (luna_version_parse_full(a, &va, NULL) == 0 &&
        luna_version_parse_full(b, &vb, NULL) == 0) {
        for (i = 0; i < 4; i++) {
            if (va.comp[i] != vb.comp[i])
                return va.comp[i] < vb.comp[i] ? -1 : 1;
        }
        if (!va.pre[0] && !vb.pre[0])
            return 0;
        if (!va.pre[0])
            return 1;       /* a release sorts above its prereleases */
        if (!vb.pre[0])
            return -1;
        return luna_pre_cmp(va.pre, vb.pre);
    }

    /* Loose fallback for non-canonical text passed by external callers. */
    {
        const char *pa = a, *pb = b;

        for (;;) {
            int va2 = pa ? luna_dot_num(pa, &pa) : 0;
            int vb2 = pb ? luna_dot_num(pb, &pb) : 0;

            if (va2 != vb2)
                return va2 < vb2 ? -1 : 1;
            if (!pa && !pb)
                return 0;
        }
    }
}

static int luna_version_valid(const char *version)
{
    LunaVersion v;

    if (!version || strlen(version) > LUNA_MOD_VERSION_MAX)
        return 0;
    return luna_version_parse_full(version, &v, NULL) == 0;
}

static void luna_version_format(const int comp[4], char *out, size_t cap)
{
    snprintf(out, cap, "%d.%d.%d.%d", comp[0], comp[1], comp[2], comp[3]);
}

static void luna_version_format_pre(const LunaVersion *v, char *out, size_t cap)
{
    if (v->pre[0]) {
        snprintf(out, cap, "%d.%d.%d.%d-%s", v->comp[0], v->comp[1],
                 v->comp[2], v->comp[3], v->pre);
    } else {
        luna_version_format(v->comp, out, cap);
    }
}

/* Increment component index, zero everything below it. */
static void luna_version_bump(int comp[4], int index, char *out, size_t cap)
{
    int i;

    if (index < 0)
        index = 0;
    if (index > 3)
        index = 3;
    comp[index]++;
    for (i = index + 1; i < 4; i++)
        comp[i] = 0;
    luna_version_format(comp, out, cap);
}

/* Neutral element for intersecting terms: no bounds, no prereleases. */
static void luna_range_all(LunaRange *r)
{
    memset(r, 0, sizeof(*r));
}

/* A real "any": no bounds, prereleases eligible. */
static void luna_range_any(LunaRange *r)
{
    memset(r, 0, sizeof(*r));
    r->allow_prerelease = 1;
}

static void luna_range_exact(LunaRange *r, const char *version)
{
    luna_range_all(r);
    r->has_lower = 1;
    snprintf(r->lower, sizeof(r->lower), "%s", version);
    r->lower_inclusive = 1;
    r->has_upper = 1;
    snprintf(r->upper, sizeof(r->upper), "%s", version);
    r->upper_inclusive = 1;
}

static void luna_range_lower(LunaRange *r, const char *version, int inclusive)
{
    luna_range_all(r);
    r->has_lower = 1;
    snprintf(r->lower, sizeof(r->lower), "%s", version);
    r->lower_inclusive = inclusive;
}

static void luna_range_upper(LunaRange *r, const char *version, int inclusive)
{
    luna_range_all(r);
    r->has_upper = 1;
    snprintf(r->upper, sizeof(r->upper), "%s", version);
    r->upper_inclusive = inclusive;
}

static void luna_range_between(LunaRange *r, const char *lo, const char *hi)
{
    luna_range_all(r);
    r->has_lower = 1;
    snprintf(r->lower, sizeof(r->lower), "%s", lo);
    r->lower_inclusive = 1;
    r->has_upper = 1;
    snprintf(r->upper, sizeof(r->upper), "%s", hi);
    r->upper_inclusive = 0;
}

static void luna_range_intersect(LunaRange *a, const LunaRange *b)
{
    a->allow_prerelease = a->allow_prerelease || b->allow_prerelease;
    if (b->has_lower) {
        int c;

        if (!a->has_lower) {
            a->has_lower = 1;
            snprintf(a->lower, sizeof(a->lower), "%s", b->lower);
            a->lower_inclusive = b->lower_inclusive;
        } else {
            c = luna_version_cmp(b->lower, a->lower);
            if (c > 0) {
                snprintf(a->lower, sizeof(a->lower), "%s", b->lower);
                a->lower_inclusive = b->lower_inclusive;
            } else if (c == 0) {
                a->lower_inclusive = a->lower_inclusive && b->lower_inclusive;
            }
        }
    }
    if (b->has_upper) {
        int c;

        if (!a->has_upper) {
            a->has_upper = 1;
            snprintf(a->upper, sizeof(a->upper), "%s", b->upper);
            a->upper_inclusive = b->upper_inclusive;
        } else {
            c = luna_version_cmp(b->upper, a->upper);
            if (c < 0) {
                snprintf(a->upper, sizeof(a->upper), "%s", b->upper);
                a->upper_inclusive = b->upper_inclusive;
            } else if (c == 0) {
                a->upper_inclusive = a->upper_inclusive && b->upper_inclusive;
            }
        }
    }
}

/* A prerelease version only satisfies a range when the range opted into
 * prereleases (bare "*"/no requirement) or one of its bounds names a
 * prerelease with the same core. This keeps `^1.2.3` from silently accepting
 * `2.0.0-beta`, while `^1.2.3-beta` can still select `1.2.3-rc`. */
static int luna_bound_prerelease_matches(const char *bound, const int comp[4])
{
    LunaVersion v;

    if (luna_version_parse_full(bound, &v, NULL) != 0 || !v.pre[0])
        return 0;
    return memcmp(v.comp, comp, sizeof(v.comp)) == 0;
}

static int luna_range_allows_prerelease(const LunaRange *r, const char *version)
{
    LunaVersion v;

    if (luna_version_parse_full(version, &v, NULL) != 0 || !v.pre[0])
        return 1;
    if (r->allow_prerelease)
        return 1;
    if (r->has_lower && luna_bound_prerelease_matches(r->lower, v.comp))
        return 1;
    if (r->has_upper && luna_bound_prerelease_matches(r->upper, v.comp))
        return 1;
    return 0;
}

static int luna_range_contains(const LunaRange *r, const char *version)
{
    if (!luna_range_allows_prerelease(r, version))
        return 0;
    if (r->has_lower) {
        int c = luna_version_cmp(version, r->lower);

        if (c < 0 || (c == 0 && !r->lower_inclusive))
            return 0;
    }
    if (r->has_upper) {
        int c = luna_version_cmp(version, r->upper);

        if (c > 0 || (c == 0 && !r->upper_inclusive))
            return 0;
    }
    return 1;
}

/* Index of the component to bump for a caret range. */
static int luna_caret_ceiling(const int comp[4], int count)
{
    int i;

    for (i = 0; i < count && i < 3; i++) {
        if (comp[i] != 0)
            return i;
    }
    if (count <= 0)
        return 0;
    return count - 1 < 3 ? count - 1 : 3;
}

static int luna_parse_term(const char *term, LunaRange *out)
{
    char op = 0;
    const char *v = term;
    LunaVersion ver;
    int comp[4], count, wildcard;
    char floor[96], ceiling[96];

    if (!*term || strcmp(term, "*") == 0 ||
        strcmp(term, "x") == 0 || strcmp(term, "X") == 0) {
        luna_range_any(out);
        return 0;
    }
    if (v[0] == '>' || v[0] == '<') {
        op = v[0];
        v++;
        if (*v == '=') {
            op = (op == '>') ? 'G' : 'L';
            v++;
        }
    } else if (v[0] == '=') {
        op = '=';
        v++;
    } else if (v[0] == '^' || v[0] == '~') {
        op = v[0];
        v++;
    }
    if (luna_version_parse_full(v, &ver, &wildcard) != 0)
        return -1;
    /* "=*", ">=*" and friends are just "any" */
    if (wildcard == 0) {
        luna_range_any(out);
        return 0;
    }
    memcpy(comp, ver.comp, sizeof(comp));
    count = ver.count;
    luna_version_format_pre(&ver, floor, sizeof(floor));

    switch (op) {
    case '>':
        luna_range_lower(out, floor, 0);
        return 0;
    case 'G':
        luna_range_lower(out, floor, 1);
        return 0;
    case '<':
        luna_range_upper(out, floor, 0);
        return 0;
    case 'L':
        luna_range_upper(out, floor, 1);
        return 0;
    case '=':
        luna_range_exact(out, floor);
        return 0;
    case '^':
        luna_version_bump(comp, luna_caret_ceiling(comp, count), ceiling, sizeof(ceiling));
        luna_range_between(out, floor, ceiling);
        return 0;
    case '~': {
        int index = count >= 2 ? 1 : 0;

        luna_version_bump(comp, index, ceiling, sizeof(ceiling));
        luna_range_between(out, floor, ceiling);
        return 0;
    }
    default:
        break;
    }

    /* bare version */
    if (wildcard > 0) {
        luna_version_bump(comp, wildcard - 1, ceiling, sizeof(ceiling));
        luna_range_between(out, floor, ceiling);
    } else if (count >= 3) {
        luna_range_exact(out, floor);
    } else if (count >= 1) {
        luna_version_bump(comp, count - 1, ceiling, sizeof(ceiling));
        luna_range_between(out, floor, ceiling);
    } else {
        luna_range_any(out);
    }
    return 0;
}

static void luna_parse_requirement(const char *spec, LunaRequirement *req)
{
    const char *p = spec;

    memset(req, 0, sizeof(*req));
    req->valid = 1;
    if (!spec || !*spec) {
        req->count = 1;
        luna_range_any(&req->alternatives[0]);
        return;
    }
    for (;;) {
        const char *sep = strstr(p, "||");
        const char *end = sep ? sep : p + strlen(p);
        LunaRange range;
        int any_term = 0;

        luna_range_all(&range);
        while (p < end) {
            const char *start;
            char term[64];
            size_t len;
            LunaRange term_range;

            while (p < end && (*p == ' ' || *p == '\t'))
                p++;
            start = p;
            while (p < end && *p != ' ' && *p != '\t')
                p++;
            if (p == start)
                break;
            len = (size_t)(p - start);
            if (len >= sizeof(term)) {
                req->valid = 0;     /* do not silently truncate a term */
                return;
            }
            memcpy(term, start, len);
            term[len] = '\0';
            if (luna_parse_term(term, &term_range) != 0) {
                req->valid = 0;
                return;
            }
            luna_range_intersect(&range, &term_range);
            any_term = 1;
        }
        /* "1.0 || " and whitespace-only alternatives are typos, not "any" */
        if (!any_term) {
            req->valid = 0;
            return;
        }
        if (req->count >= LUNA_REQ_MAX_ALTERNATIVES) {
            req->valid = 0;
            return;
        }
        req->alternatives[req->count++] = range;
        if (!sep)
            break;
        p = sep + 2;
    }
}

int luna_version_matches(const char *version, const char *spec)
{
    LunaRequirement req;
    int i;

    luna_parse_requirement(spec, &req);
    if (!req.valid)
        return 0;
    for (i = 0; i < req.count; i++) {
        if (luna_range_contains(&req.alternatives[i], version))
            return 1;
    }
    return 0;
}

/* Validate everything the loader will later use as a path, selector or
 * module specifier. Runs before a copy is materialized or any bytecode is
 * read, so an untrusted manifest cannot walk out of its package directory. */
static int luna_dep_spec_valid(const char *dep, char *err, size_t err_cap)
{
    char name[256];
    const char *spec;
    LunaRequirement req;

    luna_split_dep(dep, name, sizeof(name), &spec);
    if (!luna_name_syntax_valid(name)) {
        snprintf(err, err_cap, "invalid dependency name '%s'", name);
        return -1;
    }
    if (spec) {
        if (!*spec) {
            snprintf(err, err_cap, "empty requirement for dependency '%s'", name);
            return -1;
        }
        luna_parse_requirement(spec, &req);
        if (!req.valid) {
            snprintf(err, err_cap, "invalid requirement '%s' for dependency '%s'",
                     spec, name);
            return -1;
        }
    }
    return 0;
}

static int luna_manifest_validate(const LunaManifest *m, char *err, size_t err_cap)
{
    size_t i;

    if (strcmp(m->name, LUNA_MODS_API_NAME) == 0) {
        snprintf(err, err_cap, "package name 'luna' is reserved for the loader API");
        return -1;
    }
    if (!luna_package_name_valid(m->name)) {
        snprintf(err, err_cap,
                 "invalid package name '%s' (allowed: letters, digits, '.', '_', '-', '+'; max %d)",
                 m->name, LUNA_MOD_NAME_MAX);
        return -1;
    }
    if (!luna_version_valid(m->version)) {
        snprintf(err, err_cap,
                 "invalid version '%s' (expected one to four dotted numeric components, optionally -prerelease)",
                 m->version);
        return -1;
    }
    if (!luna_path_relative_valid(m->entry)) {
        snprintf(err, err_cap, "invalid entrypoint path '%s' (must stay inside the package)",
                 m->entry);
        return -1;
    }
    if (m->icon[0] && !luna_path_relative_valid(m->icon)) {
        snprintf(err, err_cap, "invalid icon path '%s' (must stay inside the package)",
                 m->icon);
        return -1;
    }
    for (i = 0; i < m->dep_count; i++) {
        if (luna_dep_spec_valid(m->deps[i], err, err_cap) != 0)
            return -1;
    }
    for (i = 0; i < m->opt_dep_count; i++) {
        if (luna_dep_spec_valid(m->opt_deps[i], err, err_cap) != 0)
            return -1;
    }
    for (i = 0; i < m->conflict_count; i++) {
        if (luna_dep_spec_valid(m->conflicts[i], err, err_cap) != 0)
            return -1;
    }
    for (i = 0; i < m->before_count; i++) {
        if (!luna_name_syntax_valid(m->before[i])) {
            snprintf(err, err_cap, "invalid loadBefore package name '%s'", m->before[i]);
            return -1;
        }
    }
    for (i = 0; i < m->after_count; i++) {
        if (!luna_name_syntax_valid(m->after[i])) {
            snprintf(err, err_cap, "invalid loadAfter package name '%s'", m->after[i]);
            return -1;
        }
    }
    return 0;
}


/* ------------------------------------------------------------------ */
/* registry                                                            */
/* ------------------------------------------------------------------ */

typedef struct LunaLoadedMod {
    char *name;
    char *dir;          /* directory that holds the entrypoint */
    char *entry;        /* entrypoint file name */
    JSValue module;     /* BC_TAG_MODULE value */
    JSValue exports;    /* namespace object, resolved after evaluation */
    int evaluated;
} LunaLoadedMod;

struct LunaMods {
    JSRuntime *rt;
    JSContext *ctx;
    LunaLoadedMod *mods;
    size_t count;
    LunaAntiModData am;
    LunaIntegrityProbe integrity_probe;
    void *integrity_user_data;
    JSModuleNormalizeFunc *prev_normalize;
    JSModuleLoaderFunc *prev_load;
    void *prev_opaque;
    int hooks_installed;
};

LunaMods *luna_mods_create(JSContext *ctx)
{
    LunaMods *m = (LunaMods *)calloc(1, sizeof(*m));

    if (!m)
        return NULL;
    m->ctx = ctx;
    m->rt = JS_GetRuntime(ctx);
    return m;
}

void luna_mods_destroy(LunaMods *m)
{
    size_t i;

    if (!m)
        return;
    /* Opaque points at m, so put the previous hooks back before m goes away;
     * a later import must not call into a destroyed loader. */
    if (m->hooks_installed)
        JS_SetModuleLoaderFunc(m->rt, m->prev_normalize, m->prev_load, m->prev_opaque);
    for (i = 0; i < m->count; i++) {
        free(m->mods[i].name);
        free(m->mods[i].dir);
        free(m->mods[i].entry);
        if (!JS_IsUndefined(m->mods[i].module))
            JS_FreeValue(m->ctx, m->mods[i].module);
        if (!JS_IsUndefined(m->mods[i].exports))
            JS_FreeValue(m->ctx, m->mods[i].exports);
    }
    free(m->mods);
    free(m);
}

static LunaLoadedMod *luna_mods_find(LunaMods *m, const char *name)
{
    size_t i;

    for (i = 0; i < m->count; i++) {
        if (strcmp(m->mods[i].name, name) == 0)
            return &m->mods[i];
    }
    return NULL;
}

static LunaLoadedMod *luna_mods_add(LunaMods *m, const char *name)
{
    LunaLoadedMod *grown = (LunaLoadedMod *)realloc(m->mods, (m->count + 1) * sizeof(*m->mods));
    LunaLoadedMod *mod;

    if (!grown)
        return NULL;
    m->mods = grown;
    mod = &m->mods[m->count++];
    memset(mod, 0, sizeof(*mod));
    mod->module = JS_UNDEFINED;
    mod->exports = JS_UNDEFINED;
    mod->name = strdup(name);
    if (!mod->name) {
        m->count--;
        return NULL;
    }
    return mod;
}

void luna_mods_set_fallback(LunaMods *m, JSModuleNormalizeFunc *normalize,
                           JSModuleLoaderFunc *load, void *opaque)
{
    if (!m)
        return;
    m->prev_normalize = normalize;
    m->prev_load = load;
    m->prev_opaque = opaque;
}

JSValue luna_mods_exports(LunaMods *m, const char *name)
{
    LunaLoadedMod *mod;

    if (!m)
        return JS_UNDEFINED;
    mod = luna_mods_find(m, name);
    if (!mod || JS_IsUndefined(mod->exports))
        return JS_UNDEFINED;
    return JS_DupValue(m->ctx, mod->exports);
}

const char *luna_mods_owner(LunaMods *m, JSValueConst obj)
{
    size_t i;

    if (!m || !JS_VALUE_GET_PTR(obj))
        return NULL;
    for (i = 0; i < m->count; i++) {
        if (!JS_IsUndefined(m->mods[i].exports) &&
            JS_VALUE_GET_PTR(obj) == JS_VALUE_GET_PTR(m->mods[i].exports))
            return m->mods[i].name;
    }
    return NULL;
}

size_t luna_mods_count(LunaMods *m)
{
    return m ? m->count : 0;
}

void luna_mods_free_info(LunaModInfo *info, size_t count)
{
    size_t i;

    if (!info)
        return;
    for (i = 0; i < count; i++) {
        free(info[i].name);
        free(info[i].version);
        free(info[i].author);
        free(info[i].icon);
        free(info[i].entry);
        free(info[i].dir);
        free(info[i].root);
        free(info[i].error);
        if (info[i].warnings) {
            size_t w;

            for (w = 0; w < info[i].warning_count; w++)
                free(info[i].warnings[w]);
            free(info[i].warnings);
        }
    }
    free(info);
}

/* ------------------------------------------------------------------ */
/* mods importing each other                                          */
/* ------------------------------------------------------------------ */

#define LUNA_MOD_PREFIX "luna:mod:"

static const char *luna_strip_prefix(const char *name)
{
    if (strncmp(name, LUNA_MOD_PREFIX, strlen(LUNA_MOD_PREFIX)) == 0)
        return name + strlen(LUNA_MOD_PREFIX);
    return name;
}

/* A specifier that names a registered mod is kept as is, everything else is
 * forwarded to the loader that was installed before us. */
static char *luna_module_normalize(JSContext *ctx, const char *base, const char *name, void *opaque)
{
    LunaMods *m = (LunaMods *)opaque;

    (void)base;
    if (luna_mods_find(m, luna_strip_prefix(name)))
        return js_strdup(ctx, name);
    if (m->prev_normalize)
        return m->prev_normalize(ctx, base, name, m->prev_opaque);
    return js_strdup(ctx, name);
}

/*
 * Read a mod entrypoint. The anti-mod label is the mod package name, so every
 * mod ends up with its own container key: a dump from one mod never decrypts
 * inside another one.
 */
static JSValue luna_read_mod_entry(LunaMods *m, LunaLoadedMod *mod, char *err, size_t err_cap)
{
    char path[1024], msg[512];
    LunaAntiModData am;
    uint8_t *buf;
    size_t len;
    JSValue obj;

    am = m->am;
    am.label = mod->name;
    if (luna_join(path, sizeof(path), mod->dir, mod->entry) != 0) {
        snprintf(err, err_cap, "invalid entrypoint path for %s", mod->name);
        return JS_EXCEPTION;
    }
    buf = (uint8_t *)luna_read_file(path, LUNA_ENTRY_MAX, &len);
    if (!buf) {
        if (err && err_cap) {
            size_t used;

            luna_copy_str(err, err_cap, "cannot read ");
            used = strlen(err);
            luna_copy_str(err + used, err_cap > used ? err_cap - used : 0, path);
        }
        return JS_EXCEPTION;
    }
    obj = JS_ReadObjectLuna(m->ctx, buf, len, JS_READ_OBJ_BYTECODE, &am, msg, sizeof(msg));
    free(buf);
    if (JS_IsException(obj)) {
        if (err && err_cap) {
            size_t used;

            luna_copy_str(err, err_cap, mod->name);
            used = strlen(err);
            luna_copy_str(err + used, err_cap > used ? err_cap - used : 0,
                         msg[0] ? msg : ": cannot decrypt entrypoint");
        }
        return JS_EXCEPTION;
    }
    return obj;
}

static JSModuleDef *luna_module_load(JSContext *ctx, const char *module_name, void *opaque)
{
    LunaMods *m = (LunaMods *)opaque;
    LunaLoadedMod *mod = luna_mods_find(m, luna_strip_prefix(module_name));
    char msg[512];
    JSValue obj;

    if (!mod) {
        if (m->prev_load)
            return m->prev_load(ctx, module_name, m->prev_opaque);
        JS_ThrowReferenceError(ctx, "luna mod '%s' is not registered", luna_strip_prefix(module_name));
        return NULL;
    }
    if (!JS_IsUndefined(mod->module))
        return (JSModuleDef *)JS_VALUE_GET_PTR(mod->module);

    obj = luna_read_mod_entry(m, mod, msg, sizeof(msg));
    if (JS_IsException(obj)) {
        JS_ThrowInternalError(ctx, "%s", msg);
        return NULL;
    }
    mod->module = obj;
    return (JSModuleDef *)JS_VALUE_GET_PTR(obj);
}

/*
 * Evaluate one mod and publish its exports namespace so dependents can import
 * it. A mod that already arrived through an import was evaluated by the module
 * graph itself, so it is only adopted here.
 */
static int luna_eval_mod(LunaMods *m, LunaLoadedMod *mod, char *err, size_t err_cap)
{
    JSValue promise;

    if (mod->evaluated)
        return 0;

    if (JS_IsUndefined(mod->module)) {
        JSValue obj = luna_read_mod_entry(m, mod, err, err_cap);

        if (JS_IsException(obj))
            return -1;
        mod->module = obj;
        /* imports have to be resolved before the module can be evaluated;
         * this is what pulls in dependency mods through our loader hooks */
        if (JS_ResolveModule(m->ctx, obj) < 0) {
            snprintf(err, err_cap, "cannot resolve imports");
            return -1;
        }
        /* JS_EvalFunction consumes the reference it is given, so hand it a
         * second one and keep the module alive in the registry */
        promise = JS_EvalFunction(m->ctx, JS_DupValue(m->ctx, obj));
        if (JS_IsException(promise)) {
            snprintf(err, err_cap, "evaluation failed");
            JS_FreeValue(m->ctx, promise);
            return -1;
        }
        JS_FreeValue(m->ctx, promise);
    }
    mod->evaluated = 1;

    if (JS_IsUndefined(mod->exports))
        mod->exports = JS_GetModuleNamespace(m->ctx, mod->module);
    return 0;
}

/* ------------------------------------------------------------------ */
/* discovery                                                           */
/* ------------------------------------------------------------------ */

typedef struct LunaModDir {
    char *dir;
    char *root;
    int priority;
    LunaManifest manifest;
} LunaModDir;

/* A directory that looks like a mod (it has manifest.json) but cannot be
 * used. Reported to the host instead of being silently skipped. */
typedef struct LunaScanIssue {
    char *dir;
    char *root;
    char *error;
} LunaScanIssue;

static void luna_moddir_free(LunaModDir *md)
{
    if (!md)
        return;
    free(md->dir);
    free(md->root);
    md->dir = NULL;
    md->root = NULL;
    luna_manifest_clear(&md->manifest);
}

static void luna_scan_issue_add(LunaScanIssue **issues, size_t *count,
                                const char *dir, const char *root, const char *error)
{
    LunaScanIssue *grown;

    if (*count >= LUNA_SCAN_ISSUE_MAX)
        return;
    grown = (LunaScanIssue *)realloc(*issues, (*count + 1) * sizeof(**issues));
    if (!grown)
        return;
    *issues = grown;
    memset(&grown[*count], 0, sizeof(**issues));
    grown[*count].dir = strdup(dir);
    grown[*count].root = strdup(root);
    grown[*count].error = strdup(error);
    if (!grown[*count].dir || !grown[*count].root || !grown[*count].error) {
        free(grown[*count].dir);
        free(grown[*count].root);
        free(grown[*count].error);
        return;
    }
    (*count)++;
}

static void luna_scan_issues_free(LunaScanIssue *issues, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(issues[i].dir);
        free(issues[i].root);
        free(issues[i].error);
    }
    free(issues);
}

static int luna_scan_issue_cmp(const void *a, const void *b)
{
    const LunaScanIssue *x = (const LunaScanIssue *)a;
    const LunaScanIssue *y = (const LunaScanIssue *)b;

    return strcmp(x->dir, y->dir);
}

static int luna_scan_root(JSContext *ctx, const char *root, int priority,
                          LunaModDir **out, size_t *out_count,
                          LunaScanIssue **out_issues, size_t *out_issue_count)
{
    DIR *d;
    struct dirent *de;
    LunaModDir *found = NULL;
    LunaScanIssue *issues = NULL;
    size_t count = 0, issue_count = 0;

    *out = NULL;
    *out_count = 0;
    *out_issues = NULL;
    *out_issue_count = 0;
    if (!luna_is_dir(root))
        return 0;
    d = opendir(root);
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        char dir[1024], manifest[1200], msg[512];
        LunaManifest m;
        LunaModDir *grown;

        if (de->d_name[0] == '.')
            continue;
        if (luna_join(dir, sizeof(dir), root, de->d_name) != 0)
            continue;
        if (!luna_is_dir(dir))
            continue;
        if (luna_join(manifest, sizeof(manifest), dir, LUNA_MODS_MANIFEST) != 0)
            continue;
        if (!luna_is_file(manifest))
            continue;
        memset(&m, 0, sizeof(m));
        if (luna_manifest_load(ctx, dir, &m, msg, sizeof(msg)) != 0) {
            luna_scan_issue_add(&issues, &issue_count, dir, root, msg);
            continue;
        }
        if (luna_manifest_validate(&m, msg, sizeof(msg)) != 0) {
            luna_scan_issue_add(&issues, &issue_count, dir, root, msg);
            luna_manifest_clear(&m);
            continue;
        }
        grown = (LunaModDir *)realloc(found, (count + 1) * sizeof(*found));
        if (!grown) {
            luna_manifest_clear(&m);
            continue;
        }
        found = grown;
        memset(&found[count], 0, sizeof(found[count]));
        found[count].manifest = m;
        found[count].priority = priority;
        found[count].dir = strdup(dir);
        found[count].root = strdup(root);
        if (!found[count].dir || !found[count].root) {
            luna_moddir_free(&found[count]);
            continue;
        }
        count++;
    }
    closedir(d);
    *out = found;
    *out_count = count;
    *out_issues = issues;
    *out_issue_count = issue_count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* resolution                                                          */
/* ------------------------------------------------------------------ */

/*
 * One version per package, like Forge style mod loaders, but the choice is
 * requirement aware: every copy of a package found on disk is a candidate,
 * and the loader picks the candidate that lets the most mods load, with more
 * satisfied requirements and newer versions breaking ties. A mod whose needs
 * cannot be met fails alone, and its error names the requirements that were
 * in the way.
 */

typedef struct LunaPackage {
    const char *name;
    size_t *cands;          /* indices into dirs, newest first */
    size_t cand_count;
    size_t chosen;          /* index into dirs */
} LunaPackage;

typedef struct LunaModEntry {
    LunaModDir *dir;
    size_t pkg;
    int loaded;
    int failed;
    char error[512];
} LunaModEntry;

typedef struct LunaDepRef {
    char name[256];
    const char *spec;
} LunaDepRef;

static void luna_dep_ref(const char *dep, LunaDepRef *ref)
{
    luna_split_dep(dep, ref->name, sizeof(ref->name), &ref->spec);
}

/* Deterministic discovery order: by package name, newest version first, then
 * the highest priority root (scanned first), then the directory. */
static int luna_moddir_cmp(const void *a, const void *b)
{
    const LunaModDir *x = (const LunaModDir *)a;
    const LunaModDir *y = (const LunaModDir *)b;
    int c = strcmp(x->manifest.name, y->manifest.name);

    if (c)
        return c;
    c = luna_version_cmp(y->manifest.version, x->manifest.version);
    if (c)
        return c;
    if (x->priority != y->priority)
        return x->priority < y->priority ? -1 : 1;
    return strcmp(x->dir, y->dir);
}

static LunaPackage *luna_find_package(LunaPackage *pkgs, size_t count, const char *name)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (strcmp(pkgs[i].name, name) == 0)
            return &pkgs[i];
    }
    return NULL;
}

/* Group the sorted discovery list into packages with candidate versions. */
static size_t luna_build_packages(LunaModDir *dirs, size_t dir_count, LunaPackage **out)
{
    LunaPackage *pkgs = NULL;
    size_t count = 0, i;

    *out = NULL;
    for (i = 0; i < dir_count; ) {
        size_t j = i + 1, k;
        LunaPackage *grown;

        while (j < dir_count && strcmp(dirs[j].manifest.name, dirs[i].manifest.name) == 0)
            j++;
        grown = (LunaPackage *)realloc(pkgs, (count + 1) * sizeof(*pkgs));
        if (!grown) {
            for (k = 0; k < count; k++)
                free(pkgs[k].cands);
            free(pkgs);
            return 0;
        }
        pkgs = grown;
        memset(&pkgs[count], 0, sizeof(pkgs[count]));
        pkgs[count].name = dirs[i].manifest.name;
        pkgs[count].cand_count = j - i;
        pkgs[count].cands = (size_t *)malloc((j - i) * sizeof(size_t));
        if (!pkgs[count].cands) {
            for (k = 0; k < count; k++)
                free(pkgs[k].cands);
            free(pkgs);
            return 0;
        }
        for (k = 0; k < j - i; k++)
            pkgs[count].cands[k] = i + k;
        pkgs[count].chosen = i;
        count++;
        i = j;
    }
    *out = pkgs;
    return count;
}

/* Do all of the mod's requirements on depname accept version? */
static int luna_requirements_accept(const LunaManifest *man, const char *depname,
                                    const char *version)
{
    size_t i;

    for (i = 0; i < man->dep_count; i++) {
        LunaDepRef ref;

        luna_dep_ref(man->deps[i], &ref);
        if (strcmp(ref.name, depname) == 0 &&
            !luna_version_matches(version, ref.spec))
            return 0;
    }
    return 1;
}

/* Does the mod require depname at all? */
static int luna_requires(const LunaManifest *man, const char *depname)
{
    size_t i;

    for (i = 0; i < man->dep_count; i++) {
        LunaDepRef ref;

        luna_dep_ref(man->deps[i], &ref);
        if (strcmp(ref.name, depname) == 0)
            return 1;
    }
    return 0;
}

/* Does the mod require depname in a way that version violates? */
static int luna_requires_but_rejects(const LunaManifest *man, const char *depname,
                                     const char *version)
{
    size_t i;

    for (i = 0; i < man->dep_count; i++) {
        LunaDepRef ref;

        luna_dep_ref(man->deps[i], &ref);
        if (strcmp(ref.name, depname) != 0)
            continue;
        if (!luna_version_matches(version, ref.spec))
            return 1;
    }
    return 0;
}

/* Metadata check: with the current selection, would this package load? */
static int luna_would_load(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count, size_t i)
{
    const LunaManifest *man = &dirs[pkgs[i].chosen].manifest;
    size_t k;

    for (k = 0; k < man->dep_count; k++) {
        LunaDepRef ref;
        LunaPackage *p;

        luna_dep_ref(man->deps[k], &ref);
        if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0) {
            if (!luna_version_matches(LUNA_MODS_API_VERSION, ref.spec))
                return 0;
            continue;
        }
        p = luna_find_package(pkgs, pkg_count, ref.name);
        if (!p)
            return 0;
        if (!luna_version_matches(dirs[p->chosen].manifest.version, ref.spec))
            return 0;
    }
    for (k = 0; k < man->conflict_count; k++) {
        LunaDepRef ref;
        LunaPackage *p;

        luna_dep_ref(man->conflicts[k], &ref);
        p = luna_find_package(pkgs, pkg_count, ref.name);
        if (p && luna_version_matches(dirs[p->chosen].manifest.version, ref.spec))
            return 0;
    }
    return 1;
}

static size_t luna_count_loadable(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count)
{
    size_t i, total = 0;

    for (i = 0; i < pkg_count; i++) {
        if (luna_would_load(dirs, pkgs, pkg_count, i))
            total++;
    }
    return total;
}

/* Number of requirement entries the current selection satisfies. */
static size_t luna_satisfied_requirements(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count)
{
    size_t i, k, total = 0;

    for (i = 0; i < pkg_count; i++) {
        const LunaManifest *man = &dirs[pkgs[i].chosen].manifest;

        for (k = 0; k < man->dep_count; k++) {
            LunaDepRef ref;
            LunaPackage *p;

            luna_dep_ref(man->deps[k], &ref);
            if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0) {
                if (luna_version_matches(LUNA_MODS_API_VERSION, ref.spec))
                    total++;
                continue;
            }
            p = luna_find_package(pkgs, pkg_count, ref.name);
            if (p && luna_requirements_accept(man, ref.name, dirs[p->chosen].manifest.version))
                total++;
        }
    }
    return total;
}

/* Optional requirements are a preference, not a constraint: among selections
 * that load the same mods and satisfy the same required dependencies, prefer
 * one that also satisfies more optionalDependencies. */
static size_t luna_satisfied_optional(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count)
{
    size_t i, k, total = 0;

    for (i = 0; i < pkg_count; i++) {
        const LunaManifest *man = &dirs[pkgs[i].chosen].manifest;

        for (k = 0; k < man->opt_dep_count; k++) {
            LunaDepRef ref;
            LunaPackage *p;

            luna_dep_ref(man->opt_deps[k], &ref);
            if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0) {
                if (luna_version_matches(LUNA_MODS_API_VERSION, ref.spec))
                    total++;
                continue;
            }
            p = luna_find_package(pkgs, pkg_count, ref.name);
            if (p && luna_version_matches(dirs[p->chosen].manifest.version, ref.spec))
                total++;
        }
    }
    return total;
}

/*
 * Hill climbing from "newest copy of everything": each sweep tries to improve
 * how many mods the selection can load, then how many required requirements
 * it satisfies, then how many optional ones, and keeps only strict
 * improvements, so it always terminates and the result does not depend on
 * directory iteration order.
 */
static void luna_select_versions(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count)
{
    size_t i, k, sweep;
    size_t max_sweeps = pkg_count * 2 + 4;

    for (i = 0; i < pkg_count; i++)
        pkgs[i].chosen = pkgs[i].cands[0];

    for (sweep = 0; sweep < max_sweeps; sweep++) {
        int changed = 0;

        for (i = 0; i < pkg_count; i++) {
            size_t original = pkgs[i].chosen;
            size_t current_primary = luna_count_loadable(dirs, pkgs, pkg_count);
            size_t current_secondary = luna_satisfied_requirements(dirs, pkgs, pkg_count);
            size_t current_optional = luna_satisfied_optional(dirs, pkgs, pkg_count);

            for (k = 0; k < pkgs[i].cand_count; k++) {
                size_t cand = pkgs[i].cands[k];
                size_t primary, secondary, optional;

                if (cand == pkgs[i].chosen)
                    continue;
                pkgs[i].chosen = cand;
                primary = luna_count_loadable(dirs, pkgs, pkg_count);
                secondary = luna_satisfied_requirements(dirs, pkgs, pkg_count);
                optional = luna_satisfied_optional(dirs, pkgs, pkg_count);
                if (primary > current_primary ||
                    (primary == current_primary && secondary > current_secondary) ||
                    (primary == current_primary && secondary == current_secondary &&
                     optional > current_optional)) {
                    changed = 1;
                    break;
                }
                pkgs[i].chosen = original;
            }
        }
        if (!changed)
            break;
    }
}

/* Copies that live in a read only asset root are materialized into the app
 * data directory, so it holds exactly what is about to run. */
static void luna_materialize_chosen(LunaModDir *dirs, LunaPackage *pkgs, size_t pkg_count,
                                    const char *writable_root)
{
    size_t i, wlen;

    if (!writable_root || !*writable_root)
        return;
    wlen = strlen(writable_root);
    for (i = 0; i < pkg_count; i++) {
        LunaModDir *md = &dirs[pkgs[i].chosen];
        char target[1024];

        if (strncmp(md->dir, writable_root, wlen) == 0 && md->dir[wlen] == '/')
            continue;
        if (luna_join(target, sizeof(target), writable_root, md->manifest.name) != 0)
            continue;
        if (luna_copy_tree(md->dir, target) == 0) {
            char *new_dir = strdup(target);
            char *new_root = strdup(writable_root);

            if (new_dir && new_root) {
                free(md->dir);
                free(md->root);
                md->dir = new_dir;
                md->root = new_root;
            } else {
                free(new_dir);
                free(new_root);
            }
        }
    }
}

static void luna_dep_label(const char *dep, const char *spec, char *out, size_t cap)
{
    if (spec && *spec)
        snprintf(out, cap, "%s@%s", dep, spec);
    else
        snprintf(out, cap, "%s", dep);
}

static void luna_warning_add(char **warnings, size_t *count, const char *text)
{
    char *copy = strdup(text);

    if (copy)
        warnings[(*count)++] = copy;
}

/* Soft dependency diagnostics, computed once the final loaded/failed state is
 * known. Warnings never influence selection or loadability. */
static char **luna_optional_warnings(const LunaManifest *man, LunaModDir *dirs,
                                     LunaPackage *pkgs, LunaModEntry *entries,
                                     size_t pkg_count, size_t *out_count)
{
    char **warnings;
    size_t count = 0, k;

    *out_count = 0;
    if (man->opt_dep_count == 0)
        return NULL;
    warnings = (char **)calloc(man->opt_dep_count, sizeof(char *));
    if (!warnings)
        return NULL;
    for (k = 0; k < man->opt_dep_count; k++) {
        LunaDepRef ref;
        LunaPackage *p;
        char label[300], msg[512];

        luna_dep_ref(man->opt_deps[k], &ref);
        luna_dep_label(ref.name, ref.spec, label, sizeof(label));
        if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0) {
            if (!luna_version_matches(LUNA_MODS_API_VERSION, ref.spec)) {
                snprintf(msg, sizeof(msg),
                         "optional loader API '%s' is not satisfied (loader API is %s)",
                         label, LUNA_MODS_API_VERSION);
                luna_warning_add(warnings, &count, msg);
            }
            continue;
        }
        p = luna_find_package(pkgs, pkg_count, ref.name);
        if (!p) {
            snprintf(msg, sizeof(msg), "optional dependency '%s' is not installed", label);
            luna_warning_add(warnings, &count, msg);
            continue;
        }
        if (!luna_version_matches(dirs[p->chosen].manifest.version, ref.spec)) {
            snprintf(msg, sizeof(msg),
                     "optional dependency '%s' is not satisfied (selected version %s)",
                     label, dirs[p->chosen].manifest.version);
            luna_warning_add(warnings, &count, msg);
            continue;
        }
        if (entries[p - pkgs].failed) {
            snprintf(msg, sizeof(msg),
                     "optional dependency '%s' failed to load", label);
            luna_warning_add(warnings, &count, msg);
        }
    }
    if (count == 0) {
        free(warnings);
        return NULL;
    }
    *out_count = count;
    return warnings;
}

static void luna_fail_missing(LunaModEntry *e, const char *dep, const char *spec)
{
    char label[300];

    luna_dep_label(dep, spec, label, sizeof(label));
    snprintf(e->error, sizeof(e->error), "missing dependency '%s'", label);
    e->failed = 1;
}

static void luna_fail_dep_failed(LunaModEntry *e, const char *dep)
{
    snprintf(e->error, sizeof(e->error), "dependency '%s' failed to load", dep);
    e->failed = 1;
}

static void luna_fail_luna(LunaModEntry *e, const char *spec)
{
    snprintf(e->error, sizeof(e->error), "requires luna@%s, but the loader API is %s",
             spec && *spec ? spec : "*", LUNA_MODS_API_VERSION);
    e->failed = 1;
}

static void luna_fail_conflict(LunaModEntry *e, const char *dep, const char *version)
{
    snprintf(e->error, sizeof(e->error), "conflicts with '%s' %s", dep, version);
    e->failed = 1;
}

/*
 * Version mismatch with the reasoning a modder needs: which requirement was
 * not met, what is selected, and, when a different installed copy would have
 * matched this mod, which other mod keeps that copy from being selected.
 */
static void luna_fail_mismatch(LunaModDir *dirs, LunaPackage *pkgs, LunaModEntry *entries,
                               size_t pkg_count, size_t self, const char *dep,
                               const char *spec)
{
    LunaPackage *p = luna_find_package(pkgs, pkg_count, dep);
    const LunaManifest *man = &entries[self].dir->manifest;
    char label[300], alt[64];
    const char *selected = p ? dirs[p->chosen].manifest.version : "?";
    const char *blocker = NULL;
    size_t k;

    luna_dep_label(dep, spec, label, sizeof(label));
    alt[0] = '\0';
    if (p && luna_requires(man, dep)) {
        for (k = 0; k < p->cand_count; k++) {
            size_t cand = p->cands[k];

            if (cand == p->chosen)
                continue;
            if (luna_requirements_accept(man, dep, dirs[cand].manifest.version)) {
                snprintf(alt, sizeof(alt), "%s", dirs[cand].manifest.version);
                break;
            }
        }
    }
    if (alt[0]) {
        for (k = 0; k < pkg_count; k++) {
            if (k == self)
                continue;
            if (luna_requires_but_rejects(&dirs[pkgs[k].chosen].manifest, dep, alt)) {
                blocker = dirs[pkgs[k].chosen].manifest.name;
                break;
            }
        }
    }
    if (alt[0] && blocker)
        snprintf(entries[self].error, sizeof(entries[self].error),
                 "requires '%s', but %s is selected (%s matches this mod, blocked by '%s')",
                 label, selected, alt, blocker);
    else if (alt[0])
        snprintf(entries[self].error, sizeof(entries[self].error),
                 "requires '%s', but %s is selected (%s also matches this mod)",
                 label, selected, alt);
    else
        snprintf(entries[self].error, sizeof(entries[self].error),
                 "requires '%s', but only %s is installed", label, selected);
    entries[self].failed = 1;
}

/* One pass over the graph: evaluate every mod whose dependencies are already
 * loaded. Returns how many completed, so a stuck graph can be detected. */
static size_t luna_load_pass(LunaMods *m, LunaModDir *dirs, LunaPackage *pkgs,
                             LunaModEntry *entries, size_t pkg_count)
{
    size_t progressed = 0, i, k;

    for (i = 0; i < pkg_count; i++) {
        const LunaManifest *man = &dirs[pkgs[i].chosen].manifest;
        LunaLoadedMod *mod;
        int ready = 1;

        if (entries[i].loaded || entries[i].failed)
            continue;

        for (k = 0; k < man->dep_count; k++) {
            LunaDepRef ref;
            LunaPackage *p;
            size_t j;

            luna_dep_ref(man->deps[k], &ref);
            if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0) {
                if (!luna_version_matches(LUNA_MODS_API_VERSION, ref.spec)) {
                    luna_fail_luna(&entries[i], ref.spec);
                    ready = 0;
                }
                continue;
            }
            p = luna_find_package(pkgs, pkg_count, ref.name);
            if (!p) {
                luna_fail_missing(&entries[i], ref.name, ref.spec);
                ready = 0;
                break;
            }
            j = (size_t)(p - pkgs);
            if (entries[j].failed) {
                luna_fail_dep_failed(&entries[i], ref.name);
                ready = 0;
                break;
            }
            if (!entries[j].loaded) {
                ready = 0;      /* wait for the dependency to evaluate first */
                break;
            }
            if (!luna_version_matches(dirs[p->chosen].manifest.version, ref.spec)) {
                luna_fail_mismatch(dirs, pkgs, entries, pkg_count, i, ref.name, ref.spec);
                ready = 0;
                break;
            }
        }
        if (!ready || entries[i].failed)
            continue;

        for (k = 0; k < man->conflict_count; k++) {
            LunaDepRef ref;
            LunaPackage *p;

            luna_dep_ref(man->conflicts[k], &ref);
            p = luna_find_package(pkgs, pkg_count, ref.name);
            if (p && luna_version_matches(dirs[p->chosen].manifest.version, ref.spec)) {
                luna_fail_conflict(&entries[i], ref.name, dirs[p->chosen].manifest.version);
                ready = 0;
                break;
            }
        }
        if (!ready || entries[i].failed)
            continue;

        /* explicit load order wishes are waited on, but a wish that can never
         * be satisfied (missing or failed target) does not block forever */
        for (k = 0; k < man->after_count && ready; k++) {
            LunaPackage *p = luna_find_package(pkgs, pkg_count, man->after[k]);
            size_t j;

            if (!p)
                continue;
            j = (size_t)(p - pkgs);
            if (!entries[j].loaded && !entries[j].failed)
                ready = 0;
        }
        for (k = 0; k < pkg_count && ready; k++) {
            const LunaManifest *other = &dirs[pkgs[k].chosen].manifest;
            size_t b;

            for (b = 0; b < other->before_count; b++) {
                if (strcmp(other->before[b], man->name) == 0 &&
                    !entries[k].loaded && !entries[k].failed) {
                    ready = 0;
                    break;
                }
            }
        }
        if (!ready)
            continue;

        mod = luna_mods_find(m, man->name);
        if (!mod) {
            snprintf(entries[i].error, sizeof(entries[i].error), "registry entry missing");
            entries[i].failed = 1;
            continue;
        }
        if (luna_eval_mod(m, mod, entries[i].error, sizeof(entries[i].error)) != 0) {
            entries[i].failed = 1;
            continue;
        }
        entries[i].loaded = 1;
        progressed++;
    }
    return progressed;
}

/* ------------------------------------------------------------------ */
/* cycle reporting                                                     */
/* ------------------------------------------------------------------ */

enum {
    LUNA_EDGE_DEP = 0,
    LUNA_EDGE_ORDER = 1
};

typedef struct LunaCycle {
    LunaModDir *dirs;
    LunaPackage *pkgs;
    LunaModEntry *entries;
    size_t pkg_count;
    unsigned char *state;
    size_t *stack;
    unsigned char *stack_kind;
    size_t stack_len;
    char message[512];
} LunaCycle;

/*
 * The k-th mod that u is waiting for: a required dependency that has not
 * loaded, a loadAfter target, or any mod that asked to load before u.
 * Returns the target package index, or -1 once there are no more.
 */
static long luna_wait_edge(LunaCycle *c, size_t u, size_t k, int *kind)
{
    const LunaManifest *man = &c->dirs[c->pkgs[u].chosen].manifest;
    size_t n = 0, i;

    for (i = 0; i < man->dep_count; i++) {
        LunaDepRef ref;
        LunaPackage *p;
        size_t j;

        luna_dep_ref(man->deps[i], &ref);
        if (strcmp(ref.name, LUNA_MODS_API_NAME) == 0)
            continue;
        p = luna_find_package(c->pkgs, c->pkg_count, ref.name);
        if (!p)
            continue;
        j = (size_t)(p - c->pkgs);
        if (c->entries[j].loaded || c->entries[j].failed)
            continue;
        if (n++ == k) {
            *kind = LUNA_EDGE_DEP;
            return (long)j;
        }
    }
    for (i = 0; i < man->after_count; i++) {
        LunaPackage *p = luna_find_package(c->pkgs, c->pkg_count, man->after[i]);
        size_t j;

        if (!p)
            continue;
        j = (size_t)(p - c->pkgs);
        if (c->entries[j].loaded || c->entries[j].failed)
            continue;
        if (n++ == k) {
            *kind = LUNA_EDGE_ORDER;
            return (long)j;
        }
    }
    for (i = 0; i < c->pkg_count; i++) {
        const LunaManifest *other = &c->dirs[c->pkgs[i].chosen].manifest;
        size_t b;

        if (c->entries[i].loaded || c->entries[i].failed)
            continue;
        for (b = 0; b < other->before_count; b++) {
            if (strcmp(other->before[b], man->name) == 0) {
                if (n++ == k) {
                    *kind = LUNA_EDGE_ORDER;
                    return (long)i;
                }
                break;
            }
        }
    }
    return -1;
}

static void luna_append_str(char *buf, size_t cap, const char *s)
{
    size_t used = strlen(buf);

    if (used + 1 >= cap)
        return;
    luna_copy_str(buf + used, cap - used, s);
}

static const char *luna_entry_name(LunaCycle *c, size_t i)
{
    return c->dirs[c->pkgs[i].chosen].manifest.name;
}

static int luna_cycle_dfs(LunaCycle *c, size_t u, size_t *found_start)
{
    size_t k = 0;
    int kind;

    c->state[u] = 1;
    c->stack[c->stack_len] = u;
    c->stack_len++;

    for (;;) {
        long v = luna_wait_edge(c, u, k, &kind);
        size_t pos, j;
        int has_dep;

        if (v < 0)
            break;
        k++;
        if (c->state[v] == 2)
            continue;
        if (c->state[v] == 1) {
            pos = c->stack_len;
            for (j = 0; j < c->stack_len; j++) {
                if (c->stack[j] == (size_t)v) {
                    pos = j;
                    break;
                }
            }
            if (pos >= c->stack_len)
                continue;       /* not on the stack: cannot happen */
            has_dep = (kind == LUNA_EDGE_DEP);
            for (j = pos + 1; j < c->stack_len; j++) {
                if (c->stack_kind[j] == LUNA_EDGE_DEP)
                    has_dep = 1;
            }
            snprintf(c->message, sizeof(c->message), "%s cycle:",
                     has_dep ? "dependency" : "load order");
            for (j = pos; j < c->stack_len; j++) {
                luna_append_str(c->message, sizeof(c->message), " ");
                if (j > pos)
                    luna_append_str(c->message, sizeof(c->message), "-> ");
                luna_append_str(c->message, sizeof(c->message), luna_entry_name(c, c->stack[j]));
            }
            luna_append_str(c->message, sizeof(c->message), " -> ");
            luna_append_str(c->message, sizeof(c->message), luna_entry_name(c, (size_t)v));
            *found_start = pos;
            return 1;
        }
        /* state == 0: descend */
        c->stack_kind[c->stack_len] = (unsigned char)kind;
        if (luna_cycle_dfs(c, (size_t)v, found_start))
            return 1;
    }
    c->state[u] = 2;
    c->stack_len--;
    return 0;
}

/* Mark every mod on the first waiting cycle found, and report whether one was
 * found. The caller re-runs the load pass so dependents fail with a note. */
static int luna_fail_cycles(LunaModDir *dirs, LunaPackage *pkgs, LunaModEntry *entries,
                            size_t pkg_count)
{
    LunaCycle c;
    size_t i;
    int found = 0;

    memset(&c, 0, sizeof(c));
    c.dirs = dirs;
    c.pkgs = pkgs;
    c.entries = entries;
    c.pkg_count = pkg_count;
    c.state = (unsigned char *)calloc(pkg_count, 1);
    c.stack = (size_t *)malloc(pkg_count * sizeof(size_t));
    c.stack_kind = (unsigned char *)malloc(pkg_count);
    if (!c.state || !c.stack || !c.stack_kind) {
        free(c.state);
        free(c.stack);
        free(c.stack_kind);
        return 0;
    }
    for (i = 0; i < pkg_count && !found; i++) {
        size_t start = 0;

        if (entries[i].loaded || entries[i].failed || c.state[i] != 0)
            continue;
        c.stack_len = 0;
        c.message[0] = '\0';
        if (luna_cycle_dfs(&c, i, &start)) {
            size_t j;

            for (j = start; j < c.stack_len; j++) {
                LunaModEntry *e = &entries[c.stack[j]];

                if (!e->loaded && !e->failed) {
                    luna_copy_str(e->error, sizeof(e->error), c.message);
                    e->failed = 1;
                }
            }
            found = 1;
        }
    }
    free(c.state);
    free(c.stack);
    free(c.stack_kind);
    return found;
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

/*
 * Default integrity probe: refuse to run while the process looks inspected.
 *
 * - ptrace(PTRACE_TRACEME) fails when a tracer is already attached
 * - /proc/self/status reports the tracer pid directly
 *
 * None of this is a guarantee; it raises the cost of "just attach and look
 * around", which is the realistic threat for a mod loader.
 */
static int luna_integrity_default(void *user_data)
{
#ifdef __linux__
    FILE *f;
    char line[256];

    /*
     * Only the status file is consulted here: PTRACE_TRACEME succeeds once
     * and then poisons every later call on this process, which would make the
     * check refuse to run after the very first successful load.
     */
    f = fopen("/proc/self/status", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);

                fclose(f);
                return pid != 0;
            }
        }
        fclose(f);
    }
#endif
    (void)user_data;
    return 0;
}

static int luna_integrity_check(LunaMods *m)
{
    if (m->integrity_probe)
        return m->integrity_probe(m->integrity_user_data);
    return luna_integrity_default(NULL);
}

void luna_mods_set_integrity_probe(LunaMods *m, LunaIntegrityProbe probe, void *user_data)
{
    if (!m)
        return;
    m->integrity_probe = probe;
    m->integrity_user_data = user_data;
}

int luna_mods_load(LunaMods *m, const char **roots, size_t root_count,
                  const char *writable_root, const LunaAntiModData *am,
                  LunaModInfo **out, size_t *out_count, char *err, size_t err_cap)
{
    LunaModDir *dirs = NULL;
    size_t dir_count = 0, i;
    LunaPackage *pkgs = NULL;
    size_t pkg_count = 0;
    LunaModEntry *entries = NULL;
    LunaModInfo *info = NULL;
    size_t info_count = 0;
    LunaScanIssue *issues = NULL;
    size_t issue_count = 0;
    int rc = -1;

    if (!m || !roots || !out || !out_count)
        return -1;
    *out = NULL;
    *out_count = 0;
    if (m->count > 0) {
        snprintf(err, err_cap,
                 "loader already loaded %zu mod(s); create a fresh loader to rescan",
                 m->count);
        return -1;
    }
    if (luna_integrity_check(m)) {
        snprintf(err, err_cap, "runtime integrity check failed");
        return -1;
    }
    if (am)
        m->am = *am;

    for (i = 0; i < root_count; i++) {
        LunaModDir *partial = NULL;
        size_t partial_count = 0;
        LunaScanIssue *partial_issues = NULL;
        size_t partial_issue_count = 0;

        luna_scan_root(m->ctx, roots[i], (int)i, &partial, &partial_count,
                       &partial_issues, &partial_issue_count);
        if (partial) {
            LunaModDir *grown = (LunaModDir *)realloc(dirs, (dir_count + partial_count) * sizeof(*dirs));

            if (grown) {
                memcpy(grown + dir_count, partial, partial_count * sizeof(*grown));
                dir_count += partial_count;
                dirs = grown;
                free(partial);
            } else {
                size_t k;

                for (k = 0; k < partial_count; k++)
                    luna_moddir_free(&partial[k]);
                free(partial);
            }
        }
        if (partial_issues) {
            LunaScanIssue *grown = (LunaScanIssue *)realloc(issues, (issue_count + partial_issue_count) * sizeof(*issues));

            if (grown) {
                memcpy(grown + issue_count, partial_issues, partial_issue_count * sizeof(*grown));
                issue_count += partial_issue_count;
                issues = grown;
                free(partial_issues);
            } else {
                luna_scan_issues_free(partial_issues, partial_issue_count);
            }
        }
    }
    if (issues)
        qsort(issues, issue_count, sizeof(*issues), luna_scan_issue_cmp);

    if (dir_count == 0) {
        if (issue_count > 0) {
            snprintf(err, err_cap,
                     "no loadable mods in %zu root(s); %zu invalid manifest(s), first: %s: %s",
                     root_count, issue_count, issues[0].dir, issues[0].error);
        } else {
            snprintf(err, err_cap, "no mods found in %zu root(s)", root_count);
        }
        goto done;
    }
    /* deterministic order no matter what readdir() reported */
    qsort(dirs, dir_count, sizeof(*dirs), luna_moddir_cmp);

    pkg_count = luna_build_packages(dirs, dir_count, &pkgs);
    if (!pkgs) {
        snprintf(err, err_cap, "out of memory");
        goto done;
    }
    luna_select_versions(dirs, pkgs, pkg_count);
    luna_materialize_chosen(dirs, pkgs, pkg_count, writable_root);

    info_count = pkg_count + issue_count;
    entries = (LunaModEntry *)calloc(pkg_count, sizeof(*entries));
    info = (LunaModInfo *)calloc(info_count, sizeof(*info));
    if (!entries || !info) {
        snprintf(err, err_cap, "out of memory");
        goto done;
    }
    for (i = 0; i < pkg_count; i++) {
        LunaModDir *md = &dirs[pkgs[i].chosen];
        LunaLoadedMod *mod;

        entries[i].dir = md;
        entries[i].pkg = i;
        info[i].name = strdup(md->manifest.name);
        info[i].version = strdup(md->manifest.version);
        info[i].author = strdup(md->manifest.author);
        info[i].icon = strdup(md->manifest.icon);
        info[i].entry = strdup(md->manifest.entry);
        info[i].dir = strdup(md->dir);
        info[i].root = strdup(md->root);
        if (!info[i].name || !info[i].version || !info[i].author ||
            !info[i].icon || !info[i].entry || !info[i].dir || !info[i].root) {
            snprintf(err, err_cap, "out of memory");
            goto done;
        }
        mod = luna_mods_add(m, md->manifest.name);
        if (!mod) {
            snprintf(err, err_cap, "out of memory");
            goto done;
        }
        free(mod->dir);
        free(mod->entry);
        mod->dir = strdup(md->dir);
        mod->entry = strdup(md->manifest.entry);
        if (!mod->dir || !mod->entry) {
            snprintf(err, err_cap, "out of memory");
            goto done;
        }
    }

    /* Rejected manifests are part of the result: a mod that disappears
     * silently is impossible to debug from a host UI. */
    for (i = 0; i < issue_count; i++) {
        LunaModInfo *row = &info[pkg_count + i];
        const char *base = strrchr(issues[i].dir, '/');
        size_t need = strlen(issues[i].error) + 32;

        base = base ? base + 1 : issues[i].dir;
        row->name = strdup(base);
        row->version = strdup("");
        row->author = strdup("");
        row->icon = strdup("");
        row->entry = strdup("");
        row->dir = strdup(issues[i].dir);
        row->root = strdup(issues[i].root);
        row->error = (char *)malloc(need);
        if (!row->name || !row->version || !row->author || !row->icon ||
            !row->entry || !row->dir || !row->root || !row->error) {
            snprintf(err, err_cap, "out of memory");
            goto done;
        }
        snprintf(row->error, need, "invalid manifest: %s", issues[i].error);
        row->failed = 1;
    }

    /* mods import each other by package name, so the hooks have to be live
     * before the first mod is evaluated */
    if (!m->hooks_installed) {
        JS_SetModuleLoaderFunc(m->rt, luna_module_normalize, luna_module_load, m);
        m->hooks_installed = 1;
    }

    /* iterate until nothing new loads: dependencies come first; cycles and
     * graphs that can never be satisfied are reported instead of hanging */
    {
        size_t rounds;
        size_t max_rounds = pkg_count * 2 + 4;   /* each round loads or fails at least one mod */

        for (rounds = 0; rounds <= max_rounds; rounds++) {
            size_t progressed = luna_load_pass(m, dirs, pkgs, entries, pkg_count);

            if (luna_fail_cycles(dirs, pkgs, entries, pkg_count))
                continue;       /* cycle members failed, dependents are next */
            if (progressed == 0)
                break;
        }
    }
    for (i = 0; i < pkg_count; i++) {
        if (!entries[i].loaded && !entries[i].failed) {
            snprintf(entries[i].error, sizeof(entries[i].error), "unresolved dependency graph");
            entries[i].failed = 1;
        }
        info[i].loaded = entries[i].loaded;
        info[i].failed = entries[i].failed;
        if (entries[i].error[0])
            info[i].error = strdup(entries[i].error);
    }
    /* warnings are diagnostics only; compute them after every status is
     * final so "the optional package failed" is reported correctly */
    for (i = 0; i < pkg_count; i++) {
        info[i].warnings = luna_optional_warnings(&dirs[pkgs[i].chosen].manifest,
                                                  dirs, pkgs, entries, pkg_count,
                                                  &info[i].warning_count);
    }

    *out = info;
    *out_count = info_count;
    info = NULL;
    info_count = 0;
    rc = 0;

 done:
    luna_mods_free_info(info, info_count);
    free(entries);
    if (pkgs) {
        for (i = 0; i < pkg_count; i++)
            free(pkgs[i].cands);
        free(pkgs);
    }
    {
        size_t k;

        for (k = 0; k < dir_count; k++)
            luna_moddir_free(&dirs[k]);
    }
    free(dirs);
    luna_scan_issues_free(issues, issue_count);
    return rc;
}
