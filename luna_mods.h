/*
 * Luna mod loader.
 *
 * Discovers mod packages on disk, resolves one version per package with
 * requirement aware selection, copies read-only (APK asset) copies into the
 * app data directory when needed, and evaluates the entrypoint bytecode of
 * every mod in dependency order.
 *
 * Selection: every installed copy of a package is a candidate. The loader
 * picks the copy that lets the most mods load, then satisfies the most
 * requirements, then is newest, so a dependent can hold a package back to an
 * older copy instead of failing. The result is deterministic and independent
 * of directory iteration order.
 *
 * manifest.json understands dependencies (required), optionalDependencies
 * (soft: prefer a compatible copy when one is installed, warn when not,
 * never fail), conflicts/breaks (refuse to load while a match is selected),
 * loadBefore/loadAfter (evaluation order when both are present) and a
 * dependency on the synthetic package "luna" for the loader API version.
 * Range grammar and semantics are documented in luna_mods.c.
 *
 * Manifests are validated before anything is copied or evaluated: package
 * names are restricted to a path safe character set, versions must be dotted
 * numeric with an optional prerelease, entrypoint/icon paths must stay inside
 * the package directory and every dependency must carry a parseable
 * requirement. A directory with an unusable manifest is reported as a failed
 * entry in the load result instead of silently disappearing.
 *
 * Every mod is an ES module, so "exports" are the module exports object and
 * mods consume each other with plain import statements. The registry is also
 * reachable from C through luna_mods_exports() so hosts can expose it to their
 * own scripting surface.
 *
 * This file only depends on quickjs public API and libc.
 */
#ifndef LUNA_MODS_H
#define LUNA_MODS_H

#include "quickjs.h"
#include "luna_bc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNA_MODS_MANIFEST "manifest.json"
#define LUNA_MODS_FORMAT   1

/*
 * Loader API version. Mods can depend on the synthetic package
 * LUNA_MODS_API_NAME: "dependencies": ["luna@>=1.0.0"] fails the mod early
 * when it needs a newer loader than this one.
 */
#define LUNA_MODS_API_NAME    "luna"
#define LUNA_MODS_API_VERSION "1.0.0"

typedef struct LunaMods LunaMods;

/*
 * Runtime integrity probe, run before any mod is loaded. The default probe
 * checks for a debugger (ptrace plus /proc/self/status TracerPid); a host can
 * replace it with its own check. Returning non-zero makes luna_mods_load()
 * refuse to run anything.
 */
typedef int (*LunaIntegrityProbe)(void *user_data);
void luna_mods_set_integrity_probe(LunaMods *m, LunaIntegrityProbe probe, void *user_data);

/* Create a loader bound to a context. */
LunaMods *luna_mods_create(JSContext *ctx);
void luna_mods_destroy(LunaMods *m);

typedef struct LunaModInfo {
    char *name;     /* package name, or directory name for an invalid manifest */
    char *version;
    char *author;
    char *icon;     /* manifest declared icon, may be NULL */
    char *entry;    /* entrypoint file name */
    char *dir;      /* directory the mod was loaded from */
    char *root;     /* root it came from */
    int loaded;     /* evaluated successfully */
    int failed;     /* evaluation failed or a dependency failed */
    char *error;    /* NULL when everything went fine */
    /*
     * Soft dependency diagnostics (missing or incompatible
     * optionalDependencies, optional packages that failed to load). Warnings
     * never change whether a mod loads; warning_count is zero when none.
     */
    char **warnings;
    size_t warning_count;
} LunaModInfo;

/*
 * Load every mod found under roots (highest priority first).
 *
 * roots are directories that directly contain one sub directory per mod
 * package, e.g. <root>/com.luna.mods.hello/manifest.json.
 *
 * Writable root: when non NULL, copies of mods that only exist in a
 * read-only asset root are materialized there first (the loader then works
 * on the copy), which is what makes "assets/luna/mods" behave like a
 * deployment channel for /data/data/<pkg>/files/luna/mods.
 *
 * On success *out receives a malloc()ed array of *out_count entries that the
 * caller frees with luna_mods_free_info(). The first rows are the resolved
 * packages in package name order; when manifests were rejected, one failed
 * row per bad directory follows (name = directory basename, error explains
 * why it was rejected), sorted by directory.
 *
 * A loader performs one load; use a fresh LunaMods to rescan after mods
 * change, so stale modules can never stay registered behind the caller's
 * back.
 */
int luna_mods_load(LunaMods *m, const char **roots, size_t root_count,
                   const char *writable_root, const LunaAntiModData *am,
                   LunaModInfo **out, size_t *out_count, char *err, size_t err_cap);

/* Exports namespace of a loaded mod, JS_UNDEFINED when unknown. */
JSValue luna_mods_exports(LunaMods *m, const char *name);

/*
 * Chain to the module loader that was installed before the mod loader, so a
 * host (e.g. the Frida script backend) keeps working for its own imports.
 * Must be called before luna_mods_load().
 */
void luna_mods_set_fallback(LunaMods *m, JSModuleNormalizeFunc *normalize,
                           JSModuleLoaderFunc *load, void *opaque);

/* Package name of the mod that registered the given exports object, so a host
 * can map a JS value back to its owner. NULL when not a mod namespace. */
const char *luna_mods_owner(LunaMods *m, JSValueConst obj);

/* Number of loaded mods. */
size_t luna_mods_count(LunaMods *m);

void luna_mods_free_info(LunaModInfo *info, size_t count);

/* Version helpers, exposed for tests and tooling. */
int luna_version_cmp(const char *a, const char *b);   /* -1, 0, 1 */
int luna_version_matches(const char *version, const char *spec); /* 0 when ok */


#ifdef __cplusplus
}
#endif

#endif /* LUNA_MODS_H */
