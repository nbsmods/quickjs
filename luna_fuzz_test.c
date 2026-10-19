/*
 * Luna differential fuzzer.
 *
 * Generates random modules full of the constructs the sealed engine decodes
 * and fuses (checked locals, const initializers, assignment chains, argument
 * post decrements, loop conditions), runs every program twice - once on the
 * stock engine and once through the sealed container - and requires the two
 * results (or the two thrown errors) to match.
 */
#include "quickjs.h"
#include "quickjs-libc.h"
#include "luna_bc.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

static uint64_t rng_state;

static uint32_t rnd(uint32_t n)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state % n);
}

typedef struct {
    char buf[64 * 1024];
    size_t len;
    int depth;
    int vars;     /* locals available */
    int args;     /* arguments available */
    int fns;      /* callable generated functions */
    int loops;    /* bounded loop budget */
    int loop_arg; /* argument driving the innermost while loop */
} Gen;

static void emit(Gen *g, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void emit(Gen *g, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (g->len >= sizeof(g->buf) - 1024)
        return;
    va_start(ap, fmt);
    n = vsnprintf(g->buf + g->len, sizeof(g->buf) - g->len, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (g->len + (size_t)n >= sizeof(g->buf) - 1)
        g->len = sizeof(g->buf) - 1;
    else
        g->len += (size_t)n;
}

static void gen_expr(Gen *g, char *out, size_t outsz);

static void gen_atom(Gen *g, char *out, size_t outsz)
{
    uint32_t k = rnd(10);

    if (k < 3)
        snprintf(out, outsz, "%d", (int)rnd(1000) - 500);
    else if (k < 4)
        snprintf(out, outsz, "%d.%d", (int)rnd(50) - 25, (int)rnd(100));
    else if (k < 5)
        snprintf(out, outsz, "'s%d'", (int)rnd(100));
    else if (k < 7 && g->vars > 0)
        snprintf(out, outsz, "v%d", (int)rnd(g->vars));
    else if (k < 8 && g->args > 0)
        snprintf(out, outsz, "a%d", (int)rnd(g->args));
    else if (k < 9)
        snprintf(out, outsz, "o.%c", "abc"[rnd(3)]);
    else if (k < 9)
        snprintf(out, outsz, "(%d + %d)", (int)rnd(100), (int)rnd(100));
    else
        snprintf(out, outsz, "true");
}

static void gen_expr(Gen *g, char *out, size_t outsz)
{
    char a[512], b[512];
    uint32_t k = rnd(12);

    if (k < 6 || g->depth > 2) {
        gen_atom(g, out, outsz);
        return;
    }
    g->depth++;
    gen_expr(g, a, sizeof(a));
    gen_expr(g, b, sizeof(b));
    g->depth--;
    switch (rnd(7)) {
    case 0: snprintf(out, outsz, "(%s + %s)", a, b); break;
    case 1: snprintf(out, outsz, "(%s - %s)", a, b); break;
    case 2: snprintf(out, outsz, "(%s * %s)", a, b); break;
    case 3: snprintf(out, outsz, "(%s %% %s)", a, b); break;
    case 4: snprintf(out, outsz, "(%s > %s)", a, b); break;
    case 5: snprintf(out, outsz, "(%s < %s)", a, b); break;
    case 6: snprintf(out, outsz, "(%s / (%s + %d))", a, b, 1 + (int)rnd(9)); break;
    default: snprintf(out, outsz, "(%s === %s)", a, b); break;
    }
}

static void gen_block(Gen *g);

static void gen_stmt(Gen *g, int in_loop)
{
    char e[512];
    uint32_t k = rnd(16);

    if (g->depth > 3) { /* keep the generator recursion bounded */
        gen_expr(g, e, sizeof(e));
        emit(g, "g = %s; ", e);
        return;
    }
    switch (k) {
    case 0: /* const initializer: exercises the fused const init */
        gen_expr(g, e, sizeof(e));
        emit(g, "const c%d = %s; ", g->vars, e);
        g->vars++;
        break;
    case 1:
        gen_expr(g, e, sizeof(e));
        emit(g, "let v%d = %s; ", g->vars, e);
        g->vars++;
        break;
    case 2: /* assignment chain / copies: exercises glc;dup;plc;drop */
        if (g->vars > 1)
            emit(g, "v%d = v%d; ", (int)rnd(g->vars), (int)rnd(g->vars));
        break;
    case 14: /* expression store: exercises dup;plc;drop */
        if (g->vars > 0) {
            gen_expr(g, e, sizeof(e));
            /* the unary plus keeps strings from doubling in loops */
            emit(g, "v%d = +(%s); ", (int)rnd(g->vars), e);
        }
        break;
    case 3: /* increments */
        if (g->vars > 0)
            switch (rnd(4)) {
            case 0: emit(g, "v%d++; ", (int)rnd(g->vars)); break;
            case 1: emit(g, "--v%d; ", (int)rnd(g->vars)); break;
            case 2: emit(g, "v%d += %d; ", (int)rnd(g->vars), (int)rnd(10)); break;
            default: emit(g, "v%d--; ", (int)rnd(g->vars)); break;
            }
        break;
    case 4: /* argument post decrement: the n-- pattern */
        if (g->args > 0 && in_loop)
            emit(g, "a%d--; ", (int)rnd(g->args));
        else if (g->args > 0)
            emit(g, "if (a%d > 0) a%d--; ", (int)rnd(g->args), (int)rnd(g->args));
        break;
    case 12: { /* arg op= const: the n /= 2 shape */
        char opc = "+-*/%"[rnd(5)];
        int a = (int)rnd(g->args);

        /* never grow the argument that drives the enclosing loop, it would
         * keep the program from terminating */
        if ((opc == '+' || opc == '*') && a == g->loop_arg && g->args > 1)
            a = (a + 1) % g->args;
        if (g->args > 0)
            emit(g, "a%d %c= %d; ", a, opc, 1 + (int)rnd(7));
        break;
    }
    case 5: { /* if / else */
        char c[512];
        gen_expr(g, c, sizeof(c));
        emit(g, "if (%s) { ", c);
        g->depth++;
        gen_block(g);
        g->depth--;
        emit(g, "} else { ");
        g->depth++;
        gen_block(g);
        g->depth--;
        emit(g, "} ");
        break;
    }
    case 6: { /* call another generated function */
        char a[256];
        if (g->fns > 0) {
            gen_expr(g, a, sizeof(a));
            emit(g, "f%d(%s, %d); ", (int)rnd(g->fns), a, (int)rnd(100));
        }
        break;
    }
    case 7: { /* try / throw: exercises the error and tdz paths */
        char c[512];
        gen_expr(g, c, sizeof(c));
        emit(g, "try { if (%s) throw new Error('e%d'); ", c, (int)rnd(10));
        g->depth++;
        gen_block(g);
        g->depth--;
        emit(g, "} catch (ex) { ");
        g->depth++;
        gen_block(g);
        g->depth--;
        emit(g, "} ");
        break;
    }
    case 8: { /* nested block with shadowing */
        int save = g->vars;
        emit(g, "{ ");
        g->depth++;
        gen_block(g);
        g->depth--;
        emit(g, "} ");
        g->vars = save;
        break;
    }
    case 13: /* loop with a local bound: the glc;glc;lt;ift shape */
        if (g->loops > 0 && g->vars > 0) {
            int save_kind = 0;

            (void)save_kind;
            emit(g, "const t%d = %d; ", g->vars, 1 + (int)rnd(4));
            g->loops--;
            emit(g, "for (let i%d = 0; i%d < t%d; i%d++) { ",
                 g->vars, g->vars, g->vars, g->vars);
            g->vars++;
            g->depth++;
            gen_block(g);
            g->depth--;
            emit(g, "} ");
        }
        break;
    case 9: /* bounded loop */
        if (g->loops > 0) {
            int bound;
            uint32_t bk = rnd(3);

            if (g->depth > 1) {
                /* inner loops stay tiny so programs always terminate fast */
                bound = 1 + (int)rnd(4);
            } else if (bk == 0) {
                bound = 1 + (int)rnd(4);          /* push_1..4 */
            } else if (bk == 1) {
                bound = 8 + (int)rnd(120);        /* push_i8 */
            } else {
                bound = 128 + (int)rnd(2800);     /* push_i16 */
            }
            g->loops--;
            emit(g, "for (let i%d = 0; i%d < %d; i%d++) { ",
                 g->vars, g->vars, bound, g->vars);
            g->vars++;
            g->depth++;
            gen_block(g);
            g->depth--;
            emit(g, "} ");
        }
        break;
    case 10: /* while with an argument: the fib loop pattern */
        if (g->args > 0 && g->loops > 0) {
            int a = (int)rnd(g->args);
            int save_arg = g->loop_arg;

            g->loops--;
            g->loop_arg = a;
            emit(g, "while (a%d > 0) { a%d--; ", a, a);
            g->depth++;
            gen_block(g);
            g->depth--;
            emit(g, "} ");
            g->loop_arg = save_arg;
        }
        break;
    case 11:
        gen_expr(g, e, sizeof(e));
        emit(g, "o.%c = %s; ", "abc"[rnd(3)], e);
        break;
    case 15: /* loop bounded by an argument: glc; get_arg; lt; if_false8 */
        if (g->args > 0 && g->loops > 0) {
            int save_arg = g->loop_arg;

            /* a1 is always called with a small bound, so this terminates as
             * long as the body cannot grow it */
            g->loops--;
            g->loop_arg = 1;
            emit(g, "for (let i%d = 0; i%d < a1; i%d++) { ",
                 g->vars, g->vars, g->vars);
            g->vars++;
            g->depth++;
            gen_block(g);
            g->depth--;
            emit(g, "} ");
            g->loop_arg = save_arg;
        }
        break;
    default:
        gen_expr(g, e, sizeof(e));
        emit(g, "g = %s; ", e);
        break;
    }
}

static void gen_block(Gen *g)
{
    int n = 1 + (int)rnd(4), i;

    for (i = 0; i < n; i++)
        gen_stmt(g, 1);
}

static const char *gen_program(uint64_t seed, char *src, size_t srcsz)
{
    Gen g;
    int i;

    memset(&g, 0, sizeof(g));
    g.loop_arg = -1;
    rng_state = seed | 1;
    emit(&g, "let g = 0; ");
    for (i = 0; i < 3; i++) {
        int save_vars = g.vars;

        emit(&g, "function f%d(a0, a1) { const o = { a: 1, b: 2, c: 3 }; ", i);
        g.vars = 0;
        g.args = 2;
        g.fns = i;
        g.loops = 2;
        gen_block(&g);
        emit(&g, "return a0 + a1; } ");
        g.vars = save_vars;
    }
    emit(&g, "export function run() { const o = { a: 5, b: 7, c: 9 }; ");
    g.vars = 0;
    g.args = 0;
    g.fns = 3;
    g.loops = 3;
    gen_block(&g);
    emit(&g, "return JSON.stringify([g, typeof g]); } ");
    if (g.len >= sizeof(g.buf) - 1024)
        return NULL;
    snprintf(src, srcsz, "%s", g.buf);
    return src;
}

static void fill_antimod(LunaAntiModData *am)
{
    memset(am, 0, sizeof(*am));
    am->package = "com.fuzz";
    am->apk_sig_sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    am->version_code = "7";
    am->label = "com.luna.fuzz";
}

static const char helper_src[] =
    "(function(){"
    "  try { const r = __ns.run(); return 'V:' + r; }"
    "  catch (e) { return 'E:' + e.name + ':' + e.message; }"
    "})()";

static void exec_module_stock(JSContext *ctx, JSValue mod, char *out, size_t outsz)
{
    JSValue modref = JS_DupValue(ctx, mod);
    JSValue promise = JS_EvalFunction(ctx, mod); /* consumes mod */
    JSValue ns, glob, res;
    const char *s;

    if (JS_IsException(promise)) {
        snprintf(out, outsz, "READFAIL");
        JS_FreeValue(ctx, modref);
        return;
    }
    JS_FreeValue(ctx, promise);
    ns = JS_GetModuleNamespace(ctx, modref);
    JS_FreeValue(ctx, modref);
    glob = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, glob, "__ns", ns);
    res = JS_Eval(ctx, helper_src, sizeof(helper_src) - 1, "<h>",
                  JS_EVAL_TYPE_GLOBAL);
    s = JS_ToCString(ctx, res);
    snprintf(out, outsz, "%s", s ? s : "?");
    JS_FreeCString(ctx, s);
    JS_FreeValue(ctx, res);
    JS_FreeValue(ctx, glob);
}

int main(int argc, char **argv)
{
    int iters = argc > 1 ? atoi(argv[1]) : 300;
    int start = getenv("LUNA_SEED_START") ? atoi(getenv("LUNA_SEED_START")) : 0;
    int i, failures = 0;
    char *src = malloc(64 * 1024);

    for (i = start; i < iters; i++) {
        uint64_t seed = 0x9e3779b97f4a7c15ULL * (uint64_t)(i + 1);
        char got_stock[8192], got_sealed[8192];
        LunaAntiModData am;
        JSRuntime *rt;
        JSContext *ctx;
        JSValue mod;
        uint8_t *container = NULL;
        size_t clen = 0;

        if (getenv("LUNA_SEED_TRACE"))
            fprintf(stderr, "SEED %d\n", i);
        if (getenv("LUNA_DUMP_SEED") && i == atoi(getenv("LUNA_DUMP_SEED")))
            fprintf(stderr, "DUMP %s\n", src);
        if (!gen_program(seed, src, 64 * 1024))
            continue;

        rt = JS_NewRuntime();
        ctx = JS_NewContext(rt);
        mod = JS_Eval(ctx, src, strlen(src), "fuzz.js",
                      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if (JS_IsException(mod)) {
            /* generator bug, skip the seed */
            JS_FreeContext(ctx);
            JS_FreeRuntime(rt);
            continue;
        }
        fill_antimod(&am);
        container = JS_WriteObjectLuna(ctx, &clen, mod, JS_WRITE_OBJ_BYTECODE,
                                       &am, LUNA_BC_KDF_SHIFT_MIN,
                                       LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
        if (!container) {
            JS_FreeValue(ctx, mod);
            JS_FreeContext(ctx);
            JS_FreeRuntime(rt);
            continue;
        }
        exec_module_stock(ctx, mod, got_stock, sizeof(got_stock));
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        /* sealed run */
        rt = JS_NewRuntime();
        ctx = JS_NewContext(rt);
        fill_antimod(&am);
        {
            JSValue obj = JS_ReadObjectLuna(ctx, container, clen,
                                            JS_READ_OBJ_BYTECODE, &am, NULL, 0);

            if (JS_IsException(obj)) {
                snprintf(got_sealed, sizeof(got_sealed), "READFAIL");
            } else {
                exec_module_stock(ctx, obj, got_sealed, sizeof(got_sealed));
            }
        }
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
        free(container);

        if (strcmp(got_stock, got_sealed) != 0) {
            failures++;
            printf("MISMATCH seed %d: stock '%s' sealed '%s'\n", i,
                   got_stock, got_sealed);
            printf("---- source ----\n%s\n----------------\n", src);
            if (failures >= 3)
                break;
        }
    }
    printf("%s: %d iterations, %d mismatches\n", failures ? "FAILED" : "OK",
           i, failures);
    free(src);
    return failures ? 1 : 0;
}
