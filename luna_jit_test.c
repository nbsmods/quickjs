/*
 * Luna JIT differential test: run the same sealed module in a stock engine
 * and in the sealed engine (native tier enabled) and compare every observable
 * result. Covers the numeric fast paths, float/int slot traffic, fmod calls,
 * deopt paths (strings, bitwise) and the interpreter poll.
 */
#include "quickjs.h"
#include "quickjs-libc.h"
#include "luna_bc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* implemented in quickjs.c when the native tier is built in */
extern int luna_jit_compiled_count(void);
extern int luna_jit_guard_trip_count(void);

static LunaAntiModData am_data;
static const LunaAntiModData *antimod(void)
{
    memset(&am_data, 0, sizeof(am_data));
    am_data.package = "com.jittest";
    am_data.apk_sig_sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    am_data.version_code = "7";
    am_data.label = "com.luna.jittest";
    return &am_data;
}

static const char *src =
    "export function add1(n) { return n + 1; }\n"
    "export function addf(n) { return n + 0.5; }\n"
    "export function gt0(n) { return n > 0; }\n"
    "export function le0(n) { return n <= 0; }\n"
    "export function postdec(n) { return n--; }\n"
    "export function postdecgt(n) { return n-- > 0; }\n"
    "export function loop(n) { let s = 0; let i = 0; while (i < n) { s = s + i; i = i + 1; } return s; }\n"
    "export function count(n) { let s = 0; for (let i = 0; i < n; i++) { s += i; } return s; }\n"
    "export function fib(n) { let a = 0, b = 1; while (n-- > 0) { const t = a + b; a = b; b = t; } return a; }\n"
    "export function neg(n) { return -n; }\n"
    "export function lnot(n) { return !n; }\n"
    "export function dv(a, b) { return a / b; }\n"
    "export function lte(a, b) { return a <= b; }\n"
    "export function lt(a, b) { return a < b; }\n"
    "export function md(a, b) { return a % b; }\n"
    "export function collatz(n) { let s = 0; while (n > 1) { if (n % 2 === 0) n = n / 2; else n = n * 3 + 1; s = s + 1; } return s; }\n"
    "export function bor(a, b) { return a | b; }\n"
    "export function shl(a, b) { return a << b; }\n"
    "export function incdec(n) { let a = n; a++; a--; a += 2; return a; }\n"
    "export function sumto(n) { let s = 0; for (let i = 0; i <= n; i++) { s = s + i * 2; } return s; }\n"
    "export function mixf(a, b) { return a * b + 0.5; }\n"
    "export function stradd(a, b) { return a + b; }\n"
    "export function truthy(x) { return x ? 1 : 0; }\n"
    "export function retbool(n) { return n > 3; }\n"
    "export function retundef() { return; }\n"
    "export function maybebail(x) { let t = x + 1; return t; }\n"
    "export function setloc(n) { let a = n; let b = 0; a = a + 1; b = a; return b; }\n";

static const char *exprs[] = {
    "String(add1(10))",
    "String(addf(10))",
    "String(gt0(10))",
    "String(gt0(0))",
    "String(le0(0))",
    "String(le0(1))",
    "String(postdec(5))",
    "String(postdecgt(5))",
    "String(loop(10))",
    "String(loop(0))",
    "String(count(5000))",
    "String(count(10000))",
    "String(fib(40))",
    "String(fib(300))",
    "String(neg(5))",
    "String(Object.is(neg(0), -0))",
    "String(1/neg(0))",
    "String(lnot(0))",
    "String(lnot(2))",
    "String(lnot(0/0))",
    "String(dv(1, 3))",
    "String(dv(1, 0))",
    "String(dv(-1, 0))",
    "String(dv(0, 0))",
    "String(lte(1, 1))",
    "String(lte(0/0, 1))",
    "String(lt(0/0, 1))",
    "String(lt(1, 0/0))",
    "String(md(7, 3))",
    "String(md(-7, 3))",
    "String(md(7.5, 2))",
    "String(md(-5.5, 2))",
    "String(md(1, 0))",
    "String(Object.is(md(-4, 2), -0))",
    "String(1/md(-4, 2))",
    "String(Object.is(md(-2147483648, -1), -0))",
    "String(md(1e300, 7))",
    "String(md(7, 1e-300))",
    "String(md(1e300*1e300, 2))",
    "String(collatz(1))",
    "String(collatz(27))",
    "String(collatz(1000))",
    "String(bor(6, 3))",
    "String(shl(1, 5))",
    "String(incdec(5))",
    "String(sumto(100))",
    "String(mixf(3, 1e10))",
    "String(stradd(2, 3))",
    "String(stradd('a', 'b'))",
    "String(truthy(5))",
    "String(truthy(0))",
    "String(truthy(0/0))",
    "String(truthy('x'))",
    "String(retbool(5))",
    "String(retbool(1))",
    "String(retundef())",
    "String(maybebail(4))",
    "String(maybebail(4.5))",
    "String(maybebail('a'))",
    "String(setloc(7))",
    "String(typeof retundef())",
};

static void eval_str(JSContext *ctx, const char *expr, char *out, size_t outlen)
{
    JSValue v = JS_Eval(ctx, expr, strlen(expr), "<jit>", JS_EVAL_TYPE_GLOBAL);
    out[0] = 0;
    if (JS_IsException(v)) {
        snprintf(out, outlen, "<EXC>");
    } else {
        const char *p = JS_ToCString(ctx, v);
        if (p) { snprintf(out, outlen, "%s", p); JS_FreeCString(ctx, p); }
        else snprintf(out, outlen, "<noconv>");
    }
    JS_FreeValue(ctx, v);
}

int main(void)
{
    JSRuntime *rt;
    JSContext *stock, *sealed;
    JSValue mod;
    uint8_t *container;
    size_t clen = 0;
    int failures = 0, rounds, i;
    size_t k;
    int nojit = getenv("LUNA_NOJIT") != NULL;

    rt = JS_NewRuntime();
    stock = JS_NewContext(rt);
    sealed = JS_NewContext(rt);
    js_std_add_helpers(stock, 0, NULL);
    js_std_init_handlers(rt);

    mod = JS_Eval(stock, src, strlen(src), "jit.js",
                  JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(mod)) { js_std_dump_error(stock); return 1; }

    container = JS_WriteObjectLuna(stock, &clen, mod, JS_WRITE_OBJ_BYTECODE,
                                   antimod(), LUNA_BC_KDF_SHIFT_DEFAULT,
                                   LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
    if (!container) { fprintf(stderr, "container write failed\n"); return 1; }

    {
        JSValue promise = JS_EvalFunction(stock, mod);
        JSValue ns, glob, hoist;
        const char *code =
            "(function(){ for (const k in __ns) globalThis[k] = __ns[k]; })()";
        if (JS_IsException(promise)) { js_std_dump_error(stock); return 1; }
        JS_FreeValue(stock, promise);
        ns = JS_GetModuleNamespace(stock, mod);
        glob = JS_GetGlobalObject(stock);
        JS_SetPropertyStr(stock, glob, "__ns", ns);
        JS_FreeValue(stock, glob);
        hoist = JS_Eval(stock, code, strlen(code), "<hoist>", JS_EVAL_TYPE_GLOBAL);
        JS_FreeValue(stock, hoist);
    }

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
        JS_SetPropertyStr(sealed, glob, "__ns", ns);
        JS_FreeValue(sealed, glob);
        hoist = JS_Eval(sealed, code, strlen(code), "<hoist>", JS_EVAL_TYPE_GLOBAL);
        JS_FreeValue(sealed, hoist);
    }

    /* two rounds: the second exercises cached native code and deopt replay */
    for (rounds = 0; rounds < 2; rounds++) {
        for (k = 0; k < sizeof(exprs) / sizeof(exprs[0]); k++) {
            char s1[96], e1[96], s2[96], e2[96];
            eval_str(stock, exprs[k], s1, sizeof(s1));
            eval_str(sealed, exprs[k], e1, sizeof(e1));
            eval_str(stock, exprs[k], s2, sizeof(s2));
            eval_str(sealed, exprs[k], e2, sizeof(e2));
            if (strcmp(s1, e1) != 0 || strcmp(s1, e2) != 0 || strcmp(s1, s2) != 0) {
                printf("FAIL: %s\n  stock=%s\n  sealed=%s (round2 %s/%s)\n",
                       exprs[k], s1, e1, s2, e2);
                failures++;
            }
        }
    }

    i = luna_jit_compiled_count();
    if (nojit && i != 0) {
        printf("FAIL: native tier compiled %d functions with LUNA_NOJIT set\n", i);
        failures++;
    }
    if (!nojit && i == 0) {
        printf("FAIL: native tier compiled no functions\n");
        failures++;
    }
    if (nojit) {
        if (luna_jit_guard_trip_count() != 0) {
            printf("FAIL: guard tripped with the native tier disabled\n");
            failures++;
        }
    } else {
#ifdef LUNA_JIT_SELFTEST
        if (luna_jit_guard_trip_count() == 0) {
            printf("FAIL: selftest guard did not trip\n");
            failures++;
        }
#else
        if (luna_jit_guard_trip_count() != 0) {
            printf("FAIL: native image guard tripped unexpectedly\n");
            failures++;
        }
#endif
    }

    if (failures) {
        printf("FAILED: %zu checks, %d failures\n",
               sizeof(exprs) / sizeof(exprs[0]), failures);
    } else {
        printf("OK: %zu checks, 0 failures (native compiles: %d%s)\n",
               sizeof(exprs) / sizeof(exprs[0]), i, nojit ? ", jit off" : "");
    }

    free(container);
    JS_FreeContext(stock);
    JS_FreeContext(sealed);
    js_std_free_handlers(rt);
    JS_FreeRuntime(rt);
    return failures != 0;
}
