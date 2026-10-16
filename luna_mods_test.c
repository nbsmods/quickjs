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

static void write_manifest(const char *dir, const char *name, const char *version,
                           const char *author, const char *deps)
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
             "  \"dependencies\": [%s],\n"
             "  \"icon\": \"icon.png\",\n"
             "  \"entrypoint\": \"main.luna\"\n"
             "}\n",
             name, version, author, deps ? deps : "");
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    write_file(path, json);
    snprintf(path, sizeof(path), "%s/icon.png", dir);
    write_file(path, "\x89PNG fake icon");
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
