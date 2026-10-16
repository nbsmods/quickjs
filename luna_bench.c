/* benchmark: sealed container vs stock engine, same source */
#include "quickjs.h"
#include "quickjs-libc.h"
#include "luna_bc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static LunaAntiModData am_data;
static const LunaAntiModData *antimod(void)
{
    memset(&am_data, 0, sizeof(am_data));
    am_data.package = "com.bench";
    am_data.apk_sig_sha256 = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
    am_data.version_code = "1";
    am_data.label = "com.luna.bench";
    return &am_data;
}

static const char *src =
    "export function fib(n) { let a = 0, b = 1; while (n-- > 0) { const t = a + b; a = b; b = t; } return a; }\n"
    "export function collatz(n) { let s = 0; while (n > 1) { if (n % 2 === 0) n /= 2; else n = 3 * n + 1; s++; } return s; }\n"
    "export function strbuild() { let s = ''; for (let i = 0; i < 200; i++) s += String.fromCharCode(65 + (i % 26)); return s; }\n"
    "export function objloop() { let t = 0; const o = { a: 1, b: 2, c: 3 };\n"
    "  for (let i = 0; i < 20000; i++) { t += o.a; o.a = (o.a + o.b) % 1000; o.b = (o.b + o.c) % 1000; }\n"
    "  return t; }\n";

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int32_t run(JSContext *ctx, const char *code)
{
    JSValue r = JS_Eval(ctx, code, strlen(code), "<bench>", JS_EVAL_TYPE_GLOBAL);
    int32_t v = -1;

    if (JS_IsException(r)) {
        js_std_dump_error(ctx);
        return -1;
    }
    JS_ToInt32(ctx, &v, r);
    JS_FreeValue(ctx, r);
    return v;
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 200;
    JSRuntime *rt = JS_NewRuntime();
    JSContext *stock = JS_NewContext(rt);
    JSContext *sealed = JS_NewContext(rt);
    JSValue mod;
    uint8_t *container = NULL;
    size_t clen = 0;
    double t0, t1, tstock = 0, tsealed = 0;
    int i;

    /* compile the module once, seal it, then evaluate both sides */
    mod = JS_Eval(stock, src, strlen(src), "bench.js", JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(mod)) {
        js_std_dump_error(stock);
        return 1;
    }
    container = JS_WriteObjectLuna(stock, &clen, mod, JS_WRITE_OBJ_BYTECODE, antimod(),
                                   LUNA_BC_KDF_SHIFT_DEFAULT,
                                   LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
    if (!container) { fprintf(stderr, "container write failed: "); js_std_dump_error(stock); return 1; }
    {
        JSValue promise = JS_EvalFunction(stock, mod);
        JSValue ns, glob, hoist;
        const char *code =
            "(function(){ for (const k in __ns) globalThis[k] = __ns[k]; })()";

        if (JS_IsException(promise)) { js_std_dump_error(stock); return 1; }
        JS_FreeValue(stock, promise);
        ns = JS_GetModuleNamespace(stock, mod);
        glob = JS_GetGlobalObject(stock);
        JS_SetPropertyStr(stock, glob, "__ns", ns); /* takes ownership */
        JS_FreeValue(stock, glob);
        hoist = JS_Eval(stock, code, strlen(code), "<hoist>", JS_EVAL_TYPE_GLOBAL);
        JS_FreeValue(stock, hoist);
    }

    /* load it back into the other context */
    {
        JSValue obj = JS_ReadObjectLuna(sealed, container, clen, JS_READ_OBJ_BYTECODE,
                                        antimod(), NULL, 0);
        JSValue promise, ns, glob, hoist;
        const char *code =
            "(function(){ for (const k in __ns) globalThis[k] = __ns[k]; })()";

        if (JS_IsException(obj)) { js_std_dump_error(sealed); return 1; }
        promise = JS_EvalFunction(sealed, obj);
        if (JS_IsException(promise)) { js_std_dump_error(sealed); return 1; }
        JS_FreeValue(sealed, promise);
        ns = JS_GetModuleNamespace(sealed, obj);
        glob = JS_GetGlobalObject(sealed);
        JS_SetPropertyStr(sealed, glob, "__ns", ns); /* takes ownership */
        JS_FreeValue(sealed, glob);
        hoist = JS_Eval(sealed, code, strlen(code), "<hoist>", JS_EVAL_TYPE_GLOBAL);
        JS_FreeValue(sealed, hoist);
    }

    /* warm up both */
    for (i = 0; i < 3; i++) {
        run(stock, "for (let i = 0; i < 20; i++) fib(300);");
        run(sealed, "for (let i = 0; i < 20; i++) fib(300);");
    }

    t0 = now();
    for (i = 0; i < rounds; i++) run(stock, "for (let i = 0; i < 200; i++) fib(300);");
    t1 = now();
    tstock = t1 - t0;

    t0 = now();
    for (i = 0; i < rounds; i++) run(sealed, "for (let i = 0; i < 200; i++) fib(300);");
    t1 = now();
    tsealed = t1 - t0;

    printf("stock : %8.3f s  (%d rounds)\n", tstock, rounds);
    printf("sealed: %8.3f s  (%d rounds)\n", tsealed, rounds);
    printf("overhead: %+.1f%%\n", (tsealed - tstock) / tstock * 100.0);

    free(container);
    JS_FreeContext(stock);
    JS_FreeContext(sealed);
    JS_FreeRuntime(rt);
    return 0;
}
