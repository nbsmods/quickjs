/*
 * Host test for the mod loader: discovery, newest copy selection, asset to
 * app data materialization, dependency ordering and cross mod exports.
 *
 * Layout created under a temporary directory:
 *
 *   <base>/assets/luna/mods/      (read only "APK asset" root)
 *     com.luna.mods.core/         1.0.0  (exports greet)
 *     com.luna.mods.ui/           2.1.0  (imports core@^1.0.0)
 *   <base>/appdata/luna/mods/     (writable root)
 *     com.luna.mods.core/         0.9.0  (must lose to the asset copy)
 *     com.luna.mods.broken/       depends on a package that does not exist
 *     com.luna.mods.cycle-a/      depends on cycle-b
 *     com.luna.mods.cycle-b/      depends on cycle-a
 */
#include "quickjs.h"
#include "quickjs-libc.h"
#include "luna_bc.h"
#include "luna_mods.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int probe_fail(void *user_data)
{
    (void)user_data;
    return 1;
}

static int failures = 0;
static int checks = 0;

static void check(int cond, const char *what)
{
    checks++;
    if (!cond) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", what);
    }
}

#define QJSC "/home/ubuntu/nbs-frida/subprojects/frida-gum/subprojects/quickjs/qjsc"

static const char *mod_core =
    "const VERSION = '1.0.0';\n"
    "export function greet(who) { return 'hello ' + who + ' from core ' + VERSION; }\n";

static const char *mod_core_old =
    "export function greet(who) { return 'stale core ' + who; }\n";

static const char *mod_ui =
    "import { greet } from 'com.luna.mods.core';\n"
    "export function banner() { return '[ui] ' + greet('world'); }\n";

static LunaAntiModData am_data;


static const LunaAntiModData *antimod(const char *label)
{
    memset(&am_data, 0, sizeof(am_data));
    am_data.package = "com.example.game";
    am_data.apk_sig_sha256 = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
    am_data.sig_scheme = "v3";
    am_data.version_name = "45.1.207";
    am_data.version_code = "45207";
    am_data.label = label;
    return &am_data;
}

/* same shape as antimod() but signed by a different certificate */
static const LunaAntiModData *antimod_bad_sig(void)
{
    const LunaAntiModData *base = antimod(NULL);

    memset(&am_data, 0, sizeof(am_data));
    am_data = *base;
    am_data.apk_sig_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    return &am_data;
}

static void write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");

    if (!f) {
        fprintf(stderr, "cannot write %s\n", path);
        exit(1);
    }
    fwrite(data, 1, strlen(data), f);
    fclose(f);
}

static void write_manifest_full(const char *dir, const char *name, const char *version,
                                const char *author, const char *deps, const char *extra)
{
    char path[1024], json[2048];

    { char parent[1024]; char *slash; int rc2;
      snprintf(parent, sizeof(parent), "%s", dir);
      slash = strrchr(parent, '/');
      if (slash) { *slash = '\0';
        for (char *q = parent + 1; *q; q++) if (*q == '/') { *q = '\0'; mkdir(parent, 0755); *q = '/'; }
        rc2 = mkdir(parent, 0755); (void)rc2;
      }
      mkdir(dir, 0755);
    }
    snprintf(json, sizeof(json),
             "{\n"
             "  \"name\": \"%s\",\n"
             "  \"version\": \"%s\",\n"
             "  \"author\": \"%s\",\n"
             "  \"dependencies\": [%s]%s%s,\n"
             "  \"icon\": \"icon.png\",\n"
             "  \"entrypoint\": \"main.luna\"\n"
             "}\n",
             name, version, author, deps ? deps : "",
             extra ? ",\n  " : "",
             extra ? extra : "");
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    write_file(path, json);
    snprintf(path, sizeof(path), "%s/icon.png", dir);
    write_file(path, "\x89PNG fake icon");
}

static void write_manifest(const char *dir, const char *name, const char *version,
                           const char *author, const char *deps)
{
    write_manifest_full(dir, name, version, author, deps, NULL);
}

static void compile_mod(const char *src_path, const char *out_path, const char *label);

/* One mod package: manifest, icon, source, compiled container. */
static void make_mod(const char *root, const char *dirname, const char *name,
                     const char *version, const char *deps, const char *extra,
                     const char *src)
{
    char dir[1024], src_path[1024], obj[1024];

    snprintf(dir, sizeof(dir), "%s/%s", root, dirname);
    write_manifest_full(dir, name, version, "luna", deps, extra);
    snprintf(src_path, sizeof(src_path), "%s/main.js", dir);
    write_file(src_path, src);
    snprintf(obj, sizeof(obj), "%s/main.luna", dir);
    compile_mod(src_path, obj, name);
}

static LunaModInfo *find_info(LunaModInfo *info, size_t count, const char *name)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (strcmp(info[i].name, name) == 0)
            return &info[i];
    }
    return NULL;
}

/* compile a JS source into a Luna container with the given anti-mod label */
static char g_mod_paths[512];

static void compile_mod(const char *src_path, const char *out_path, const char *label)
{
    char amj[1024], cmd[2048];

    snprintf(amj, sizeof(amj), "%s.am.json", out_path);
    {
        FILE *f = fopen(amj, "w");

        if (!f) {
            fprintf(stderr, "cannot write %s\n", amj);
            exit(1);
        }
        fprintf(f, "{\"package\":\"com.example.game\","
                   "\"apk_sig_sha256\":\"11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff\","
                   "\"sig_scheme\":\"v3\","
                   "\"version_name\":\"45.1.207\",\"version_code\":\"45207\","
                   "\"label\":\"%s\"}", label);
        fclose(f);
    }
    snprintf(cmd, sizeof(cmd), "LUNA_DEBUG=${LUNA_DEBUG:-} LUNA_MOD_PATHS=%s %s -n %s -A %s -K 14 %s 2>/tmp/lunac.err",
             g_mod_paths, QJSC, out_path, amj, src_path);
    if (system(cmd) != 0) {
        FILE *e = fopen("/tmp/lunac.err", "r");
        char line[256];

        fprintf(stderr, "lunac failed for %s\n", out_path);
        if (e) {
            while (fgets(line, sizeof(line), e))
                fprintf(stderr, "  %s", line);
            fclose(e);
        }
        exit(1);
    }
}

static const char *mod_tag_src = "export const tag = 'x';\n";

/*
 * Second tree: requirement aware version selection, conflicts, optional
 * dependencies, the loader API gate, explicit load order and cycle reports.
 */
static void run_dependency_scenarios(JSContext *ctx, const char *base)
{
    char root[768], app[768];
    const char *roots[2];
    LunaMods *mods, *again;
    LunaModInfo *info = NULL, *info2 = NULL;
    size_t count = 0, count2 = 0, i;
    char err[512];
    LunaModInfo *m;
    int rc;

    snprintf(root, sizeof(root), "%s/deps/assets", base);
    snprintf(app, sizeof(app), "%s/deps/appdata", base);
    roots[0] = root;
    roots[1] = app;

    make_mod(root, "a", "mod.a", "1.0.0", "\"mod.b@^1.0.0\"", NULL, mod_tag_src);
    make_mod(root, "b-2.0.0", "mod.b", "2.0.0", "", NULL, mod_tag_src);
    make_mod(root, "b-1.0.0", "mod.b", "1.0.0", "", NULL, mod_tag_src);
    make_mod(root, "c", "mod.c", "1.0.0", "\"mod.d@^2.0.0\"", NULL, mod_tag_src);
    make_mod(root, "e", "mod.e", "1.0.0", "\"mod.d@^1.0.0\"", NULL, mod_tag_src);
    make_mod(root, "d-2.0.0", "mod.d", "2.0.0", "", NULL, mod_tag_src);
    make_mod(root, "d-1.0.0", "mod.d", "1.0.0", "", NULL, mod_tag_src);
    make_mod(root, "conflict1", "mod.conflict1", "1.0.0", "",
             "\"conflicts\": [\"mod.conflict2@1.x\"]", mod_tag_src);
    make_mod(root, "conflict2", "mod.conflict2", "1.0.0", "", NULL, mod_tag_src);
    make_mod(root, "opt", "mod.opt", "1.0.0", "",
             "\"optionalDependencies\": [\"mod.ghost@^1.0.0\"]", mod_tag_src);
    make_mod(root, "opt2", "mod.opt2", "1.0.0", "",
             "\"optionalDependencies\": [\"mod.b@2.x\"]", mod_tag_src);
    make_mod(root, "opt3", "mod.opt3", "1.0.0", "",
             "\"optionalDependencies\": [\"mod.f@1.x\"]", mod_tag_src);
    make_mod(root, "f-2.0.0", "mod.f", "2.0.0", "", NULL, mod_tag_src);
    make_mod(root, "f-1.0.0", "mod.f", "1.0.0", "", NULL, mod_tag_src);
    make_mod(root, "gate-ok", "mod.gate-ok", "1.0.0", "\"luna@>=1.0.0\"", NULL, mod_tag_src);
    make_mod(root, "gate-bad", "mod.gate-bad", "1.0.0", "\"luna@>=99.0.0\"", NULL, mod_tag_src);
    make_mod(root, "order-a", "mod.order.a", "1.0.0", "",
             "\"loadAfter\": [\"mod.order.z\"]",
             "globalThis.__luna_order = (globalThis.__luna_order || []).concat(['a']);\n"
             "export const tag = 'a';\n");
    make_mod(root, "order-z", "mod.order.z", "1.0.0", "", NULL,
             "globalThis.__luna_order = (globalThis.__luna_order || []).concat(['z']);\n"
             "export const tag = 'z';\n");
    make_mod(root, "cyc-x", "mod.cyc.x", "1.0.0", "\"mod.cyc.y\"", NULL, mod_tag_src);
    make_mod(root, "cyc-y", "mod.cyc.y", "1.0.0", "\"mod.cyc.x\"", NULL, mod_tag_src);

    mods = luna_mods_create(ctx);
    rc = luna_mods_load(mods, roots, 2, app, antimod(NULL), &info, &count, err, sizeof(err));
    check(rc == 0, "dependency scenario load succeeds");
    check(count == 17, "dependency scenario discovers 17 packages");
    if (rc == 0) {
        for (i = 1; i < count; i++) {
            if (strcmp(info[i - 1].name, info[i].name) >= 0)
                break;
        }
        check(i == count, "packages come back in name order");

        m = find_info(info, count, "mod.a");
        check(m && m->loaded, "a loads");
        m = find_info(info, count, "mod.b");
        check(m && m->version && strcmp(m->version, "1.0.0") == 0,
              "selection downgrades b to the newest copy a can use");
        check(m && m->loaded, "b loads");
        m = find_info(info, count, "mod.c");
        check(m && m->loaded, "c loads");
        m = find_info(info, count, "mod.d");
        check(m && m->loaded && m->version && strcmp(m->version, "2.0.0") == 0,
              "d keeps the newest copy when requirements conflict");
        m = find_info(info, count, "mod.e");
        check(m && m->failed, "e fails when nothing satisfies d@^1.0.0");
        if (m && m->error) {
            check(strstr(m->error, "mod.d@^1.0.0") != NULL, "mismatch names the requirement");
            check(strstr(m->error, "2.0.0") != NULL, "mismatch names the selected version");
            check(strstr(m->error, "mod.c") != NULL, "mismatch names the blocking mod");
        }
        m = find_info(info, count, "mod.conflict1");
        check(m && m->failed && m->error &&
              strstr(m->error, "conflicts with 'mod.conflict2'") != NULL,
              "conflicts refuse to load and name the mod");
        m = find_info(info, count, "mod.conflict2");
        check(m && m->loaded, "the other side of a conflict still loads");
        m = find_info(info, count, "mod.opt");
        check(m && m->loaded, "optional dependency on a missing mod is fine");
        check(m && m->warning_count == 1 && m->warnings[0] &&
              strstr(m->warnings[0], "mod.ghost") != NULL,
              "missing optional dependency is reported as a warning");
        m = find_info(info, count, "mod.opt2");
        check(m && m->loaded, "optional dependency with a mismatching copy is fine");
        check(m && m->warning_count == 1 && m->warnings[0] &&
              strstr(m->warnings[0], "mod.b") != NULL &&
              strstr(m->warnings[0], "1.0.0") != NULL,
              "mismatched optional dependency names the selected version");
        m = find_info(info, count, "mod.f");
        check(m && m->loaded && m->version && strcmp(m->version, "1.0.0") == 0,
              "an optional requirement can hold a package back when it breaks no tie");
        m = find_info(info, count, "mod.opt3");
        check(m && m->loaded && m->warning_count == 0,
              "satisfied optional dependency produces no warning");
        m = find_info(info, count, "mod.gate-ok");
        check(m && m->loaded, "loader API range satisfied");
        m = find_info(info, count, "mod.gate-bad");
        check(m && m->failed && m->error && strstr(m->error, "loader API") != NULL,
              "loader API range checked");
        m = find_info(info, count, "mod.cyc.x");
        check(m && m->failed && m->error && strstr(m->error, "cycle") != NULL,
              "cycle members report the cycle");
        m = find_info(info, count, "mod.cyc.y");
        check(m && m->failed, "both cycle members fail");

        {
            const char *code = "JSON.stringify(globalThis.__luna_order || [])";
            JSValue res = JS_Eval(ctx, code, strlen(code), "<order>", JS_EVAL_TYPE_GLOBAL);

            check(!JS_IsException(res), "order log readable");
            if (!JS_IsException(res)) {
                const char *s = JS_ToCString(ctx, res);

                check(s && strcmp(s, "[\"z\",\"a\"]") == 0, "loadAfter defers evaluation");
                if (s)
                    JS_FreeCString(ctx, s);
            } else {
                js_std_dump_error(ctx);
            }
            JS_FreeValue(ctx, res);
        }
    }

    /* scanning the same tree again picks the same versions and order */
    again = luna_mods_create(ctx);
    rc = luna_mods_load(again, roots, 2, app, antimod(NULL), &info2, &count2, err, sizeof(err));
    check(rc == 0 && count2 == count, "second load discovers the same packages");
    if (rc == 0 && count2 == count) {
        int same = 1;

        for (i = 0; i < count; i++) {
            if (strcmp(info[i].name, info2[i].name) != 0 ||
                strcmp(info[i].version, info2[i].version) != 0 ||
                info[i].loaded != info2[i].loaded ||
                info[i].failed != info2[i].failed) {
                same = 0;
                break;
            }
        }
        check(same, "resolution is deterministic across loads");
    }
    if (info2)
        luna_mods_free_info(info2, count2);
    /* a second load would keep stale modules registered, so it is refused */
    rc = luna_mods_load(again, roots, 2, app, antimod(NULL), &info2, &count2,
                        err, sizeof(err));
    check(rc != 0 && strstr(err, "already") != NULL,
          "a loader refuses a second load");
    luna_mods_destroy(again);
    if (info)
        luna_mods_free_info(info, count);
    luna_mods_destroy(mods);
}

static void mkdir_p(const char *path)
{
    char tmp[1024];
    size_t len;
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void make_raw_mod(const char *root, const char *dirname, const char *json)
{
    char dir[1024], path[1024];

    mkdir_p(root);
    snprintf(dir, sizeof(dir), "%s/%s", root, dirname);
    mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    write_file(path, json);
}

/*
 * Rejected manifests must be visible, and nothing from them may be copied
 * before validation. A name such as "../escape-pwn" used to be able to place
 * the materialized copy outside the writable root.
 */
static void run_manifest_validation(JSContext *ctx, const char *base)
{
    char bad[768], root[768], app[768], path[1024], onlyroot[768], err[512];
    const char *roots[1];
    const char *names[7] = {
        "escape", "badjson", "badver", "baddep", "badentry", "badlist", "reserved"
    };
    const char *needles[7] = {
        "invalid package name", "", "invalid version", "invalid dependency name",
        "invalid entrypoint path", "must be an array", "reserved"
    };
    LunaMods *mods;
    LunaModInfo *info = NULL;
    size_t count = 0, i;
    int rc;

    snprintf(bad, sizeof(bad), "%s/bad", base);
    snprintf(root, sizeof(root), "%s/assets", bad);
    snprintf(app, sizeof(app), "%s/appdata", bad);
    mkdir_p(root);
    mkdir_p(app);

    make_raw_mod(root, "escape",
                 "{\"name\":\"../escape-pwn\",\"version\":\"1.0.0\"}");
    make_raw_mod(root, "badjson",
                 "{\"name\":\"bad.json\",\"version\":\"1.0.0\",");
    make_raw_mod(root, "badver",
                 "{\"name\":\"bad.version\",\"version\":\"1.0.0.0.0\"}");
    make_raw_mod(root, "baddep",
                 "{\"name\":\"bad.dep\",\"version\":\"1.0.0\","
                 "\"dependencies\":[\"../evil@1.0\"]}");
    make_raw_mod(root, "badentry",
                 "{\"name\":\"bad.entry\",\"version\":\"1.0.0\","
                 "\"entrypoint\":\"../main.luna\"}");
    make_raw_mod(root, "badlist",
                 "{\"name\":\"bad.list\",\"version\":\"1.0.0\","
                 "\"dependencies\":\"oops\"}");
    make_raw_mod(root, "reserved",
                 "{\"name\":\"luna\",\"version\":\"1.0.0\"}");
    make_mod(root, "valid", "mod.valid", "1.0.0", "", NULL, mod_tag_src);

    mods = luna_mods_create(ctx);
    roots[0] = root;
    rc = luna_mods_load(mods, roots, 1, app, antimod(NULL), &info, &count,
                        err, sizeof(err));
    check(rc == 0, "a tree with rejected manifests still loads");
    check(count == 8, "valid package plus seven rejected manifests are reported");
    if (rc == 0) {
        LunaModInfo *m = find_info(info, count, "mod.valid");

        check(m && m->loaded, "the valid package in the tree still loads");
        for (i = 0; i < 7; i++) {
            m = find_info(info, count, names[i]);
            check(m && m->failed && m->error != NULL,
                  "rejected manifest has a failed info row");
            check(m && m->error && strstr(m->error, needles[i]) != NULL,
                  "rejected manifest error explains the problem");
        }
        check(luna_mods_count(mods) == 1,
              "rejected manifests are not registered as packages");
        /* the traversal attempt must not materialize outside the writable root */
        snprintf(path, sizeof(path), "%s/escape-pwn", bad);
        check(access(path, F_OK) != 0,
              "a package name cannot escape the writable root");
        snprintf(path, sizeof(path), "%s/evil", bad);
        check(access(path, F_OK) != 0,
              "an invalid dependency name is rejected before any copy");
    }
    luna_mods_free_info(info, count);
    luna_mods_destroy(mods);

    /* a root that only contains rejected manifests reports why */
    snprintf(onlyroot, sizeof(onlyroot), "%s/onlybad", bad);
    make_raw_mod(onlyroot, "broken",
                 "{\"name\":\"only.broken\",\"version\":\"nope\"}");
    {
        LunaMods *only = luna_mods_create(ctx);
        LunaModInfo *oi = NULL;
        size_t oc = 0;

        roots[0] = onlyroot;
        rc = luna_mods_load(only, roots, 1, NULL, antimod(NULL), &oi, &oc,
                            err, sizeof(err));
        check(rc != 0 && strstr(err, "invalid manifest") != NULL &&
              strstr(err, "onlybad") != NULL,
              "an all-invalid root names the rejected manifest");
        if (rc == 0)
            luna_mods_free_info(oi, oc);
        luna_mods_destroy(only);
    }

    /* a valid manifest with no entrypoint fails as a mod, not as a scan error,
     * and the caller may pass a zero sized top level error buffer */
    {
        LunaMods *missing = luna_mods_create(ctx);
        LunaModInfo *mi = NULL;
        size_t mc = 0;

        snprintf(onlyroot, sizeof(onlyroot), "%s/missingroot", bad);
        make_raw_mod(onlyroot, "missing",
                     "{\"name\":\"mod.missing\",\"version\":\"1.0.0-beta\"}");
        roots[0] = onlyroot;
        rc = luna_mods_load(missing, roots, 1, NULL, antimod(NULL), &mi, &mc,
                            NULL, 0);
        check(rc == 0 && mc == 1, "missing entrypoint is a load failure, not a scan failure");
        if (rc == 0) {
            check(mi[0].failed && mi[0].error &&
                  strstr(mi[0].error, "cannot read") != NULL,
                  "missing entrypoint is reported with its path");
            luna_mods_free_info(mi, mc);
        }
        luna_mods_destroy(missing);
    }
}

int main(void)
{
    char base[] = "/tmp/lunamods-XXXXXX";
    char asset_root[768], app_root[768], dir[1024], src[1024], obj[1024];
    char mod_paths[512];
    (void)mod_paths;
    JSRuntime *rt;
    JSContext *ctx;
    LunaMods *mods;
    LunaModInfo *info = NULL;
    size_t info_count = 0;
    char err[512];
    const char *scan_roots[2];
    int rc, i, found_ui = 0, found_core = 0, found_broken = 0, found_a = 0;
    JSValue ui_exports, res;

    if (!mkdtemp(base)) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    snprintf(mod_paths, sizeof(mod_paths), "%s/assets/luna/mods:%s/appdata/luna/mods", base, base);
    snprintf(g_mod_paths, sizeof(g_mod_paths), "%s", mod_paths);
    snprintf(asset_root, sizeof(asset_root), "%s/assets/luna/mods", base);
    snprintf(app_root, sizeof(app_root), "%s/appdata/luna/mods", base);
    mkdir(base, 0755);

    /* asset root: newest core + a dependent ui */
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.core", asset_root);
    write_manifest(dir, "com.luna.mods.core", "1.0.0", "luna", "");
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.ui", asset_root);
    write_manifest(dir, "com.luna.mods.ui", "2.1.0", "luna", "\"com.luna.mods.core@^1.0.0\"");

    /* app data root: stale core, a broken mod, a dependency cycle */
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.core", app_root);
    write_manifest(dir, "com.luna.mods.core", "0.9.0", "luna", "");
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.broken", app_root);
    write_manifest(dir, "com.luna.mods.broken", "1.0.0",  "luna",
                   "\"com.luna.mods.notthere@^1.0.0\"");
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.cycle-a", app_root);
    write_manifest(dir, "com.luna.mods.cycle-a", "1.0.0", "luna", "\"com.luna.mods.cycle-b\"");
    snprintf(dir, sizeof(dir), "%s/com.luna.mods.cycle-b", app_root);
    write_manifest(dir, "com.luna.mods.cycle-b", "1.0.0", "luna", "\"com.luna.mods.cycle-a\"");

    /* sources live inside the mod directory, next to the container */
    snprintf(src, sizeof(src), "%s/com.luna.mods.core/main.js", asset_root);
    write_file(src, mod_core);
    snprintf(obj, sizeof(obj), "%s/com.luna.mods.core/main.luna", asset_root);
    compile_mod(src, obj, "com.luna.mods.core");

    snprintf(src, sizeof(src), "%s/com.luna.mods.core/main.js", app_root);
    write_file(src, mod_core_old);
    snprintf(obj, sizeof(obj), "%s/com.luna.mods.core/main.luna", app_root);
    compile_mod(src, obj, "com.luna.mods.core");

    snprintf(src, sizeof(src), "%s/com.luna.mods.ui/main.js", asset_root);
    write_file(src, mod_ui);
    snprintf(obj, sizeof(obj), "%s/com.luna.mods.ui/main.luna", asset_root);
    compile_mod(src, obj, "com.luna.mods.ui");

    rt = JS_NewRuntime();
    ctx = JS_NewContext(rt);
    mods = luna_mods_create(ctx);

    scan_roots[0] = asset_root;
    scan_roots[1] = app_root;
    /* app data is both a scan root and the writable root, so the asset copy of
     * core gets copied over the stale app data copy */
    rc = luna_mods_load(mods, scan_roots, 2, app_root, antimod(NULL), &info, &info_count,
                       err, sizeof(err));
    if (rc != 0)
        fprintf(stderr, "load error: %s\n", err);
    check(rc == 0, "luna_mods_load succeeds");
    check(info_count == 5, "five mods discovered");
    if (info_count != 5) {
        fprintf(stderr, "  discovered %zu: ", info_count);
        for (i = 0; i < (int)info_count; i++)
            fprintf(stderr, "%s@%s ", info[i].name, info[i].version);
        fprintf(stderr, "\n");
    }

    for (i = 0; i < (int)info_count; i++) {
        if (!info[i].loaded)
            fprintf(stderr, "  mod %s@%s failed: %s\n", info[i].name, info[i].version,
                    info[i].error ? info[i].error : "(no error)");
        if (strcmp(info[i].name, "com.luna.mods.ui") == 0) {
            found_ui = 1;
            check(info[i].loaded == 1, "ui mod loaded");
            check(info[i].version && strcmp(info[i].version, "2.1.0") == 0, "ui version");
            check(info[i].author && strcmp(info[i].author, "luna") == 0, "ui author");
            check(info[i].icon && strcmp(info[i].icon, "icon.png") == 0, "ui icon in manifest");
        }
        if (strcmp(info[i].name, "com.luna.mods.core") == 0) {
            found_core = 1;
            check(info[i].loaded == 1, "core mod loaded");
            check(info[i].version && strcmp(info[i].version, "1.0.0") == 0,
                  "newest core copy wins");
            check(strncmp(info[i].dir, app_root, strlen(app_root)) == 0,
                  "winning copy lives in the writable root");
        }
        if (strcmp(info[i].name, "com.luna.mods.broken") == 0) {
            found_broken = 1;
            check(info[i].failed == 1, "mod with a missing dependency failed");
            check(info[i].error != NULL, "missing dependency reported");
        }
        if (strcmp(info[i].name, "com.luna.mods.cycle-a") == 0) {
            found_a = 1;
            check(info[i].failed == 1, "dependency cycle fails instead of hanging");
        }
    }
    check(found_ui && found_core && found_broken && found_a, "all expected mods present");

    /* the ui mod imported core through the loader hooks */
    ui_exports = luna_mods_exports(mods, "com.luna.mods.ui");
    check(!JS_IsUndefined(ui_exports), "ui exports published");
    if (!JS_IsUndefined(ui_exports)) {
        JSValue global = JS_GetGlobalObject(ctx);

        JS_SetPropertyStr(ctx, global, "__ui", ui_exports);
        JS_FreeValue(ctx, global);
        res = JS_Eval(ctx, "__ui.banner()", strlen("__ui.banner()"), "<test>", JS_EVAL_TYPE_GLOBAL);
        check(!JS_IsException(res), "ui.banner() ran");
        if (!JS_IsException(res)) {
            const char *s = JS_ToCString(ctx, res);

            check(s != NULL, "banner returned a string");
            if (s)
                check(strcmp(s, "[ui] hello world from core 1.0.0") == 0,
                      "mod api exported across mods");
            JS_FreeCString(ctx, s);
        } else {
            js_std_dump_error(ctx);
        }
        JS_FreeValue(ctx, res);
    }

    /*
     * What the loader ran is the sealed container: the entrypoint on disk is
     * still a Luna container whose payload only the engine's decode tables
     * can execute.
     */
    {
        char path[1024];
        FILE *f;
        uint8_t buf[8];
        size_t n;
        const char *root_used = NULL;

        for (i = 0; i < (int)info_count; i++) {
            if (strcmp(info[i].name, "com.luna.mods.core") == 0) {
                root_used = info[i].dir;
                break;
            }
        }
        check(root_used != NULL, "core mod directory known");
        if (root_used) {
            snprintf(path, sizeof(path), "%s/main.luna", root_used);
            f = fopen(path, "rb");
            check(f != NULL, "entrypoint exists");
            if (f) {
                n = fread(buf, 1, sizeof(buf), f);
                fclose(f);
                check(n == sizeof(buf) && memcmp(buf, LUNA_BC_MAGIC, 4) == 0,
                      "loaded mod stays sealed on disk");
            }
        }
    }

    check(luna_mods_count(mods) == 5, "five mods registered");
    check(JS_IsUndefined(luna_mods_exports(mods, "com.luna.mods.broken")),
          "failed mods publish no exports");

    /* the integrity probe is consulted before anything is loaded */
    {
        LunaMods *guarded = luna_mods_create(ctx);
        LunaModInfo *gi = NULL;
        size_t gc = 0;

        luna_mods_set_integrity_probe(guarded, probe_fail, NULL);
        rc = luna_mods_load(guarded, scan_roots, 2, NULL, antimod(NULL), &gi, &gc, err,
                            sizeof err);
        check(rc != 0 && strstr(err, "integrity") != NULL,
              "load refuses while the integrity probe fails");
        if (rc == 0)
            luna_mods_free_info(gi, gc);
        luna_mods_destroy(guarded);
    }

    /* requirement aware resolution, conflicts, load order, cycles */
    run_dependency_scenarios(ctx, base);

    /* rejected manifests are visible and cannot escape their package dir */
    run_manifest_validation(ctx, base);

    /* version helpers */
    check(luna_version_cmp("1.2.3", "1.2.4") < 0, "1.2.3 < 1.2.4");
    check(luna_version_cmp("1.10.0", "1.9.9") > 0, "1.10.0 > 1.9.9");
    check(luna_version_cmp("2.0.0", "10.0.0") < 0, "2.0.0 < 10.0.0");
    check(luna_version_cmp("1.0.0", "1.0.0") == 0, "equal versions");
    check(luna_version_matches("1.4.2", "^1.0.0") == 1, "^1.0.0 accepts 1.4.2");
    check(luna_version_matches("2.0.0", "^1.0.0") == 0, "^1.0.0 rejects 2.0.0");
    check(luna_version_matches("0.3.1", "^0.3.0") == 1, "^0.3.0 accepts 0.3.1");
    check(luna_version_matches("0.4.0", "^0.3.0") == 0, "^0.3.0 rejects 0.4.0");
    check(luna_version_matches("1.2.3", "~1.2.0") == 1, "~1.2.0 accepts 1.2.3");
    check(luna_version_matches("1.2.3", "") == 1, "empty spec matches anything");
    check(luna_version_matches("1.2.3", ">1.2.2") == 1, "> accepts");
    check(luna_version_matches("1.2.3", "<=1.2.3") == 1, "<= accepts equal");
    check(luna_version_cmp("1.2", "1.2.0") == 0, "missing components count as zero");
    check(luna_version_matches("0.2.9", "^0.2.3") == 1, "^0.2.3 accepts 0.2.9");
    check(luna_version_matches("0.2.2", "^0.2.3") == 0, "^0.2.3 rejects older patches");
    check(luna_version_matches("0.3.0", "^0.2.3") == 0, "^0.2.3 rejects 0.3.0");
    check(luna_version_matches("0.0.3", "^0.0.3") == 1, "^0.0.3 accepts itself");
    check(luna_version_matches("0.0.4", "^0.0.3") == 0, "^0.0.4 is out of the caret range");
    check(luna_version_matches("1.2.9", "~1.2.3") == 1, "~1.2.3 accepts patch bumps");
    check(luna_version_matches("1.3.0", "~1.2.3") == 0, "~1.2.3 rejects minor bumps");
    check(luna_version_matches("1.2.2", "~1.2.3") == 0, "~1.2.3 rejects older patches");
    check(luna_version_matches("1.9.9", "1.x") == 1, "1.x accepts");
    check(luna_version_matches("2.0.0", "1.x") == 0, "1.x rejects the next major");
    check(luna_version_matches("1.2.99", "1.2.x") == 1, "1.2.x accepts");
    check(luna_version_matches("1.3.0", "1.2.x") == 0, "1.2.x rejects the next minor");
    check(luna_version_matches("1.5.0", ">=1.0.0 <2.0.0") == 1, "space separated terms are AND");
    check(luna_version_matches("2.0.0", ">=1.0.0 <2.0.0") == 0, "AND upper bound enforced");
    check(luna_version_matches("2.5.0", "1.x || 2.x") == 1, "|| alternatives");
    check(luna_version_matches("3.0.0", "1.x || 2.x") == 0, "|| rejects outside them");
    check(luna_version_matches("4.5.6", "*") == 1, "* matches anything");
    check(luna_version_matches("1.2.5", "1.2") == 1, "partial spec accepts patch siblings");
    check(luna_version_matches("1.3.0", "1.2") == 0, "partial spec rejects the next minor");
    check(luna_version_matches("1.2.3", "1.2.3junk") == 0,
          "trailing text in a requirement is rejected");
    check(luna_version_matches("1.2.3", "1.x.5") == 0,
          "components after a wildcard are rejected");
    check(luna_version_matches("1.2.3", "1.2.3 ||") == 0,
          "an empty alternative is rejected");
    check(luna_version_matches("1.2.3", "   ") == 0,
          "a whitespace only requirement matches nothing");
    check(luna_version_matches("1.2.3", "1.") == 0,
          "a trailing dot is rejected");
    check(luna_version_matches("1.0.0", "=*") == 1,
          "a wildcard with an operator means any");
    check(luna_version_matches("999999999.0.0", "99999999999999999999") == 0,
          "out of range numeric components do not match");
    check(luna_version_cmp("99999999999999999999", "1.0.0") > 0,
          "comparison saturates instead of overflowing");
    check(luna_version_cmp("1.0.0-beta", "1.0.0") < 0,
          "a prerelease sorts below its release");
    check(luna_version_cmp("1.0.0-alpha", "1.0.0-beta") < 0,
          "prerelease identifiers order lexically");
    check(luna_version_cmp("1.0.0-beta.2", "1.0.0-beta.11") < 0,
          "numeric prerelease identifiers compare numerically");
    check(luna_version_cmp("1.0.0-beta", "1.0.0-beta.2") < 0,
          "a shorter prerelease identifier list sorts first");
    check(luna_version_cmp("1.0.0-beta.2", "1.0.0-rc.1") < 0,
          "numeric prerelease identifiers sort before alphanumeric ones");
    check(luna_version_cmp("1.0.0+build.2", "1.0.0") == 0,
          "build metadata does not affect ordering");
    check(luna_version_matches("1.2.3-rc.1", "=1.2.3-rc.1") == 1,
          "an exact prerelease requirement matches");
    check(luna_version_matches("1.2.3", "=1.2.3-rc.1") == 0,
          "a release does not satisfy an exact prerelease");
    check(luna_version_matches("1.2.3-rc.1", "^1.2.3-beta") == 1,
          "caret from a prerelease accepts the same core prerelease");
    check(luna_version_matches("1.2.4-beta", "^1.2.3-beta") == 0,
          "caret from a prerelease rejects other core prereleases");
    check(luna_version_matches("1.2.4", "^1.2.3-beta") == 1,
          "caret from a prerelease accepts later releases");
    check(luna_version_matches("1.5.0-beta", ">=1.0.0") == 0,
          "a release comparator rejects prereleases by default");
    check(luna_version_matches("1.5.0-beta", "*") == 1,
          "* opts into prereleases");
    check(luna_version_matches("1.5.0-beta", NULL) == 1,
          "a bare dependency accepts an installed prerelease");

    /* wrong anti-mod data makes every container fail to load */
    {
        LunaMods *m2 = luna_mods_create(ctx);
        LunaModInfo *i2 = NULL;
        size_t c2 = 0;

        rc = luna_mods_load(m2, scan_roots, 2, NULL, antimod_bad_sig(), &i2, &c2, err, sizeof(err));
        check(rc == 0 && c2 == 5, "scan works with a different key too");
        if (c2 == 5) {
            int loaded = 0;

            for (i = 0; i < (int)c2; i++) {
                if (i2[i].loaded)
                    loaded++;
            }
            check(loaded == 0, "no mod loads with the wrong anti-mod key");
        }
        luna_mods_free_info(i2, c2);
        luna_mods_destroy(m2);
    }

    /*
     * Leak check: with the loader gone every sealed function must have
     * released its bytecode, atom table and keystream, so only the context's
     * own intrinsic objects may still be alive.
     */
    {
        void luna_gc_count(JSRuntime * rt, int * out);
        int remaining = -1, baseline = -1;

        luna_gc_count(rt, &baseline);
        luna_mods_free_info(info, info_count);
        luna_mods_destroy(mods);
        luna_gc_count(rt, &remaining);
        check(remaining == baseline, "no module objects leak after unload");
        if (remaining != baseline)
            fprintf(stderr, "  baseline=%d after=%d\n", baseline, remaining);
        mods = NULL;
    }

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    printf("%s: %d checks, %d failures\n", failures ? "FAILED" : "OK", checks, failures);
    return failures ? 1 : 0;
}
