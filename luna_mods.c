/*
 * Luna mod loader.
 *
 * Discovers mod packages on disk, picks the newest copy of each one, copies
 * read only (APK asset) copies into the app data directory when needed,
 * resolves the dependency graph declared by manifest.json and evaluates the
 * entrypoint bytecode of every mod in dependency order.
 *
 * Every mod is an ES module, so "exports" are the module exports object and
 * mods consume each other with plain import statements. The registry is also
 * reachable from C through luna_mods_exports() so hosts can expose it to their
 * own scripting surface.
 *
 * manifest.json fields:
 *   name          package name, required, e.g. "com.luna.mods.aim"
 *   version       dotted numeric version, required, e.g. "1.4.2"
 *   author        free form
 *   dependencies  array of "name" or "name@range" strings
 *   icon          file name of the mod icon, relative to the mod directory
 *   entrypoint    bytecode file, defaults to "main.luna"
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
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

/* bounded copy that always NUL terminates */
static void luna_copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static char *luna_read_file(const char *path, size_t *len)
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
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
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
        if (stat(spath, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            if (luna_copy_tree(spath, dpath) != 0) {
                closedir(d);
                return -1;
            }
        } else {
            size_t len;
            char *data = luna_read_file(spath, &len);
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
} LunaManifest;

static void luna_manifest_clear(LunaManifest *m)
{
    size_t i;

    for (i = 0; i < m->dep_count; i++)
        free(m->deps[i]);
    free(m->deps);
    memset(m, 0, sizeof(*m));
}

/* Read a string field out of an already parsed manifest object. */
static int luna_manifest_str(JSContext *ctx, JSValueConst obj, const char *field,
                             char *out, size_t out_cap)
{
    JSValue v = JS_GetPropertyStr(ctx, obj, field);
    const char *s;
    int rc = -1;

    out[0] = '\0';
    if (JS_IsException(v))
        return -1;
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        return 0;
    }
    s = JS_ToCString(ctx, v);
    if (s) {
        snprintf(out, out_cap, "%s", s);
        JS_FreeCString(ctx, s);
        rc = 0;
    }
    JS_FreeValue(ctx, v);
    return rc;
}

static int luna_manifest_deps(JSContext *ctx, JSValueConst obj, char ***out, size_t *out_count)
{
    JSValue arr = JS_GetPropertyStr(ctx, obj, "dependencies");
    JSValue len;
    char **items = NULL;
    size_t count = 0;
    int32_t n, i;

    *out = NULL;
    *out_count = 0;
    if (JS_IsException(arr))
        return -1;
    if (JS_IsUndefined(arr)) {
        JS_FreeValue(ctx, arr);
        return 0;
    }
    len = JS_GetPropertyStr(ctx, arr, "length");
    if (JS_IsException(len)) {
        JS_FreeValue(ctx, arr);
        return -1;
    }
    if (JS_ToInt32(ctx, &n, len) != 0 || n < 0)
        n = 0;
    JS_FreeValue(ctx, len);
    for (i = 0; i < n; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, arr, (uint32_t)i);
        const char *s = JS_ToCString(ctx, item);
        char **grown;

        if (s && *s) {
            grown = (char **)realloc(items, (count + 1) * sizeof(char *));
            if (grown) {
                items = grown;
                items[count++] = strdup(s);
            }
        }
        if (s)
            JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, item);
    }
    JS_FreeValue(ctx, arr);
    *out = items;
    *out_count = count;
    return 0;
}

static int luna_manifest_load(JSContext *ctx, const char *dir, LunaManifest *m)
{
    char path[1024], *json;
    size_t len;
    JSValue obj, parsed, text;
    int rc = -1;

    memset(m, 0, sizeof(*m));
    m->dep_count = 0;
    snprintf(m->entry, sizeof(m->entry), "main.luna");

    if (luna_join(path, sizeof(path), dir, LUNA_MODS_MANIFEST) != 0)
        return -1;
    json = luna_read_file(path, &len);
    if (!json)
        return -1;

    /* the engine already ships a JSON parser, so use it instead of growing a
     * second one: JSON.parse(manifest_source) */
    text = JS_NewStringLen(ctx, json, len);
    free(json);
    if (JS_IsException(text))
        return -1;
    {
        JSValue global = JS_GetGlobalObject(ctx);
        JSValue json_obj = JS_GetPropertyStr(ctx, global, "JSON");

        JS_FreeValue(ctx, global);
        if (JS_IsException(json_obj)) {
            JS_FreeValue(ctx, text);
            return -1;
        }
        obj = JS_GetPropertyStr(ctx, json_obj, "parse");
        JS_FreeValue(ctx, json_obj);
        if (JS_IsException(obj)) {
            JS_FreeValue(ctx, text);
            return -1;
        }
        parsed = JS_Call(ctx, obj, JS_UNDEFINED, 1, &text);
        JS_FreeValue(ctx, obj);
        JS_FreeValue(ctx, text);
        if (JS_IsException(parsed))
            return -1;
    }

    if (luna_manifest_str(ctx, parsed, "name", m->name, sizeof(m->name)) != 0 || !m->name[0])
        goto done;
    if (luna_manifest_str(ctx, parsed, "version", m->version, sizeof(m->version)) != 0 || !m->version[0])
        goto done;
    if (luna_manifest_str(ctx, parsed, "author", m->author, sizeof(m->author)) != 0)
        m->author[0] = '\0';
    if (luna_manifest_str(ctx, parsed, "icon", m->icon, sizeof(m->icon)) != 0)
        m->icon[0] = '\0';
    if (luna_manifest_str(ctx, parsed, "entrypoint", m->entry, sizeof(m->entry)) != 0 || !m->entry[0])
        snprintf(m->entry, sizeof(m->entry), "main.luna");
    if (luna_manifest_deps(ctx, parsed, &m->deps, &m->dep_count) != 0)
        goto done;
    rc = 0;

 done:
    JS_FreeValue(ctx, parsed);
    return rc;
}

/* ------------------------------------------------------------------ */
/* versions                                                            */
/* ------------------------------------------------------------------ */

static int luna_dot_num(const char *s, const char **next)
{
    int v = 0;

    while (*s >= '0' && *s <= '9')
        v = v * 10 + (*s++ - '0');
    *next = (*s == '.') ? s + 1 : s;
    return v;
}

int luna_version_cmp(const char *a, const char *b)
{
    const char *pa = a, *pb = b;

    for (;;) {
        int va = luna_dot_num(pa, &pa);
        int vb = luna_dot_num(pb, &pb);

        if (va != vb)
            return va < vb ? -1 : 1;
        if (!*pa || !*pb)
            return *pa ? 1 : (*pb ? -1 : 0);
    }
}

/* Compare only the first n components. */


int luna_version_matches(const char *version, const char *spec)
{
    char buf[64];
    const char *p = spec;
    char op = 0;
    int c;

    if (!spec || !*spec)
        return 1;
    if (*p == '^' || *p == '~') {
        op = *p++;
    } else if (*p == '>') {
        op = '>';
        p++;
        if (*p == '=') {
            op = 'G';
            p++;
        }
    } else if (*p == '<') {
        op = '<';
        p++;
        if (*p == '=') {
            op = 'L';
            p++;
        }
    } else if (*p == '=') {
        op = '=';
        p++;
    }
    snprintf(buf, sizeof(buf), "%s", p);
    {
        char *sp = strchr(buf, ' ');
        if (sp)
            *sp = '\0';
    }

    switch (op) {
    case '^': {
        /* compatible within the same major, or the same minor for 0.x */
        int vmajor, vminor, smajor, sminor;
        const char *q;

        vmajor = luna_dot_num(version, &q);
        vminor = luna_dot_num(q, &q);
        smajor = luna_dot_num(buf, &q);
        sminor = luna_dot_num(q, &q);
        if (vmajor != smajor)
            return 0;
        if (vmajor == 0)
            return vminor == sminor;
        return 1;
    }
    case '~':
        c = luna_version_cmp(version, buf);
        return c >= 0;
    case '>':
        return luna_version_cmp(version, buf) > 0;
    case '<':
        return luna_version_cmp(version, buf) < 0;
    case 'G':
        return luna_version_cmp(version, buf) >= 0;
    case 'L':
        return luna_version_cmp(version, buf) <= 0;
    default:
        return luna_version_cmp(version, buf) == 0;
    }
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
    buf = (uint8_t *)luna_read_file(path, &len);
    if (!buf) {
        luna_copy_str(err, err_cap, "cannot read ");
        {
            size_t used = strlen(err);
            luna_copy_str(err + used, err_cap > used ? err_cap - used : 0, path);
        }
        return JS_EXCEPTION;
    }
    obj = JS_ReadObjectLuna(m->ctx, buf, len, JS_READ_OBJ_BYTECODE, &am, msg, sizeof(msg));
    free(buf);
    if (JS_IsException(obj)) {
        size_t used = strlen(mod->name);

        luna_copy_str(err, err_cap, mod->name);
        luna_copy_str(err + used, err_cap > used ? err_cap - used : 0,
                     msg[0] ? msg : ": cannot decrypt entrypoint");
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

/* Split "com.luna.mods.core@^1.2.0" into name and spec. */
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

/* ------------------------------------------------------------------ */
/* discovery                                                           */
/* ------------------------------------------------------------------ */

typedef struct LunaModDir {
    char *dir;
    char *root;
    LunaManifest manifest;
} LunaModDir;

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

static int luna_scan_root(JSContext *ctx, const char *root, LunaModDir **out, size_t *out_count)
{
    DIR *d;
    struct dirent *de;
    LunaModDir *found = NULL;
    size_t count = 0;

    *out = NULL;
    *out_count = 0;
    if (!luna_is_dir(root))
        return 0;
    d = opendir(root);
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        char dir[1024], manifest[1200];
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
        if (luna_manifest_load(ctx, dir, &m) != 0) {
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
    return 0;
}

/* Keep exactly one entry per package name: the highest version, and for equal
 * versions the one from the highest priority root (scanned first). */
static void luna_pick_latest(LunaModDir **pmods, size_t *pcount)
{
    size_t i, j, k;

    for (i = 0; i < *pcount; i++) {
        j = i + 1;
        while (j < *pcount) {
            if (strcmp((*pmods)[i].manifest.name, (*pmods)[j].manifest.name) != 0) {
                j++;
                continue;
            }
            if (luna_version_cmp((*pmods)[i].manifest.version,
                                (*pmods)[j].manifest.version) < 0) {
                /* the copy from j is newer: it takes the slot, the old one is
                 * dropped and the new one is re-examined against the rest */
                luna_moddir_free(&(*pmods)[i]);
                (*pmods)[i] = (*pmods)[j];
                j = i + 1;
            }
            luna_moddir_free(&(*pmods)[j]);
            for (k = j; k + 1 < *pcount; k++)
                (*pmods)[k] = (*pmods)[k + 1];
            (*pcount)--;
        }
    }
}

/* One pass over the graph: evaluate every mod whose dependencies are already
 * loaded. Returns how many completed, so a stuck graph can be detected. */
static size_t luna_load_pass(LunaMods *m, LunaModDir *dirs, LunaModInfo *info, size_t count)
{
    size_t progressed = 0, i, k;

    for (i = 0; i < count; i++) {
        LunaManifest *man = &dirs[i].manifest;
        LunaLoadedMod *mod;
        char err[600];
        size_t j;
        int ready = 1;

        if (info[i].loaded || info[i].failed)
            continue;

        for (k = 0; k < man->dep_count; k++) {
            char depname[256];
            const char *spec;
            int found = 0, satisfied = 0;

            luna_split_dep(man->deps[k], depname, sizeof(depname), &spec);
            for (j = 0; j < count; j++) {
                if (strcmp(dirs[j].manifest.name, depname) == 0) {
                    found = 1;
                    if (info[j].loaded && luna_version_matches(dirs[j].manifest.version, spec))
                        satisfied = 1;
                    break;
                }
            }
            if (!found) {
                if (!info[i].error)
                    info[i].error = strdup("missing dependency");
                info[i].failed = 1;
                ready = 0;
                break;
            }
            if (info[j].failed) {
                if (!info[i].error)
                    info[i].error = strdup("dependency failed to load");
                info[i].failed = 1;
                ready = 0;
                break;
            }
            if (!satisfied) {
                if (info[j].loaded && !info[i].error)
                    info[i].error = strdup("dependency version mismatch");
                ready = 0;
                break;
            }
        }
        if (!ready || info[i].failed)
            continue;

        mod = luna_mods_find(m, man->name);
        if (!mod) {
            info[i].error = strdup("registry entry missing");
            info[i].failed = 1;
            continue;
        }
        err[0] = '\0';
        if (luna_eval_mod(m, mod, err, sizeof(err)) != 0) {
            info[i].error = strdup(err);
            info[i].failed = 1;
            continue;
        }
        info[i].loaded = 1;
        progressed++;
    }
    return progressed;
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
    LunaModInfo *info = NULL;
    size_t info_count = 0;
    int rc = -1;

    if (!m || !roots || !out || !out_count)
        return -1;
    *out = NULL;
    *out_count = 0;
    if (luna_integrity_check(m)) {
        snprintf(err, err_cap, "runtime integrity check failed");
        return -1;
    }
    if (am)
        m->am = *am;

    for (i = 0; i < root_count; i++) {
        LunaModDir *partial = NULL;
        size_t partial_count = 0;

        if (luna_scan_root(m->ctx, roots[i], &partial, &partial_count) == 0 && partial) {
            LunaModDir *grown = (LunaModDir *)realloc(dirs, (dir_count + partial_count) * sizeof(*dirs));

            if (grown) {
                memcpy(grown + dir_count, partial, partial_count * sizeof(*grown));
                dir_count += partial_count;
                dirs = grown;
            } else {
                size_t k;

                for (k = 0; k < partial_count; k++)
                    luna_moddir_free(&partial[k]);
            }
            free(partial);
        }
    }
    if (dir_count == 0) {
        snprintf(err, err_cap, "no mods found in %zu root(s)", root_count);
        return -1;
    }
    /* one entry per package name, newest version wins */
    luna_pick_latest(&dirs, &dir_count);

    /* materialize copies that only exist in a read only asset root, so the
     * app data directory ends up holding exactly what is about to run */
    if (writable_root && *writable_root) {
        size_t wlen = strlen(writable_root);

        for (i = 0; i < dir_count; i++) {
            char target[1024];

            if (strncmp(dirs[i].dir, writable_root, wlen) == 0 && dirs[i].dir[wlen] == '/')
                continue;
            if (luna_join(target, sizeof(target), writable_root, dirs[i].manifest.name) != 0)
                continue;
            if (luna_copy_tree(dirs[i].dir, target) == 0) {
                free(dirs[i].dir);
                dirs[i].dir = strdup(target);
                free(dirs[i].root);
                dirs[i].root = strdup(writable_root);
            }
        }
    }

    info = (LunaModInfo *)calloc(dir_count, sizeof(*info));
    if (!info) {
        snprintf(err, err_cap, "out of memory");
        goto done;
    }
    for (i = 0; i < dir_count; i++) {
        LunaLoadedMod *mod;

        info[i].name = strdup(dirs[i].manifest.name);
        info[i].version = strdup(dirs[i].manifest.version);
        info[i].author = strdup(dirs[i].manifest.author);
        info[i].icon = strdup(dirs[i].manifest.icon);
        info[i].entry = strdup(dirs[i].manifest.entry);
        info[i].dir = strdup(dirs[i].dir);
        info[i].root = strdup(dirs[i].root);
        mod = luna_mods_add(m, dirs[i].manifest.name);
        if (!mod) {
            snprintf(err, err_cap, "out of memory");
            goto done;
        }
        free(mod->dir);
        free(mod->entry);
        mod->dir = strdup(dirs[i].dir);
        mod->entry = strdup(dirs[i].manifest.entry);
    }
    info_count = dir_count;

    /* mods import each other by package name, so the hooks have to be live
     * before the first mod is evaluated */
    if (!m->hooks_installed) {
        JS_SetModuleLoaderFunc(m->rt, luna_module_normalize, luna_module_load, m);
        m->hooks_installed = 1;
    }

    /* iterate until nothing new loads: dependencies come first, and graphs
     * that can never be satisfied are reported instead of hanging */
    {
        size_t rounds;

        for (rounds = 0; rounds <= dir_count; rounds++) {
            if (luna_load_pass(m, dirs, info, dir_count) == 0)
                break;
        }
    }
    for (i = 0; i < dir_count; i++) {
        if (!info[i].loaded && !info[i].failed) {
            info[i].failed = 1;
            if (!info[i].error)
                info[i].error = strdup("unresolved dependency graph");
        }
    }

    *out = info;
    *out_count = info_count;
    info = NULL;
    info_count = 0;
    rc = 0;

 done:
    luna_mods_free_info(info, info_count);
    {
        size_t k;

        for (k = 0; k < dir_count; k++)
            luna_moddir_free(&dirs[k]);
    }
    free(dirs);
    return rc;
}
