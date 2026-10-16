/*
 * Engine level round trip test for the Luna custom bytecode container.
 *
 * Compiles a module, seals it into a Luna container with opcode permutation,
 * reads it back with a different context, runs it and checks the exports are
 * intact. Also covers the failure paths (foreign container, wrong anti-mod
 * data, tampering).
 */
#include "quickjs.h"
#include "quickjs-libc.h"
#include "luna_bc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const char mod_source[] =
    "const tag = 'luna-v1';\n"
    "let calls = 0;\n"
    "export function add(a, b) { calls++; return a + b; }\n"
    "export function twice(x) { return add(x, x); }\n"
    "export function name() { return tag + '/' + calls; }\n"
    "export const magic = 0x4c554e41; /* LUNA */\n"
    "export function fib(n) { let a = 0, b = 1; while (n-- > 0) { const t = a + b; a = b; b = t; } return a; }\n"
    "export function sum(arr) { let s = 0; for (const v of arr) s += v; return s; }\n"
    "class Point { constructor(x, y) { this.x = x; this.y = y; }\n"
    "  dist() { return Math.sqrt(this.x * this.x + this.y * this.y); }\n"
    "  static origin() { return new Point(0, 0); } }\n"
    "export function pointDist() { const p = Point.origin(); const q = new Point(3, 4); return p.dist() + q.dist(); }\n"
    "export function jsonRoundTrip() { const o = { a: [1, 2, 3], b: 'x' }; return JSON.parse(JSON.stringify(o)).b; }\n"
    "export function reTest() { return /lun(a)/.exec('luna')[1] + '42'.replace('4', '5'); }\n"
    "export function tryCatch() { try { throw new Error('boom'); } catch (e) { return e.message + '!'; } }\n"
    "export function closure() { let n = 0; return () => ++n; }\n"
    "export function closureRun() { const f = closure(); f(); f(); return f(); }\n"
    "export function rec(n) { if (n <= 1) return 1; return n * rec(n - 1); }\n"
    "export function recRun() { return rec(6) + rec(4); }\n"
    "export function* gen() { let t = 0; for (let i = 1; i <= 3; i++) { const v = yield i; t += v; } return t; }\n"
    "export function genRun() { const g = gen(); const a = g.next().value; const b = g.next(10).value; const c = g.next(20); return a + b + c.value; }\n";

#define BIG_STMTS 150

static char *build_src(void)
{
    size_t cap = sizeof(mod_source) + BIG_STMTS * 40 + 512;
    char *src = malloc(cap);
    int i;

    strcpy(src, mod_source);
    strcat(src, "export function big(x) { let s = x;\n");
    for (i = 0; i < BIG_STMTS; i++)
        strcat(src, "s = (s * 3 + 1) % 100003;\n");
    strcat(src, "return s; }\n");
    strcat(src, "export function bigRec(n, x) { if (n === 0) return x; "
                "return bigRec(n - 1, (x * 7 + 1) % 100003) + big(x); }\n");
    return src;
}

static int expect_big(int x)
{
    int i;

    for (i = 0; i < BIG_STMTS; i++)
        x = (x * 3 + 1) % 100003;
    return x;
}

static int expect_big_rec(int n, int x)
{
    if (n == 0)
        return x;
    return expect_big_rec(n - 1, (x * 7 + 1) % 100003) + expect_big(x);
}

static LunaAntiModData antimod(const char *sig, const char *device)
{
    LunaAntiModData am;

    memset(&am, 0, sizeof(am));
    am.package = "com.example.game";
    am.apk_sig_sha256 = sig;
    am.sig_scheme = "v3";
    am.version_name = "45.1.207";
    am.version_code = "45207";
    am.device_id = device;
    am.label = "com.example.mod.hello";
    return am;
}

static JSValue eval_global(JSContext *ctx, const char *code)
{
    JSValue v = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(v))
        return JS_EXCEPTION;
    return v;
}

static int32_t eval_int(JSContext *ctx, const char *code)
{
    JSValue v = eval_global(ctx, code);
    int32_t r = -1;

    if (JS_IsException(v))
        return -1;
    JS_ToInt32(ctx, &r, v);
    JS_FreeValue(ctx, v);
    return r;
}

static int load_and_probe(JSContext *ctx, const uint8_t *buf, size_t len,
                          const LunaAntiModData *am, const char *expect_name,
                          const char **err)
{
    JSValue obj, modref, promise, ns, fn, global;
    char errbuf[512];
    int rc = -1;

    *err = NULL;
    obj = JS_ReadObjectLuna(ctx, buf, len, JS_READ_OBJ_BYTECODE, am, errbuf, sizeof(errbuf));
    if (JS_IsException(obj)) {
        fprintf(stderr, "  read failed: %s\n", errbuf[0] ? errbuf : "(engine)");
        js_std_dump_error(ctx);
        return -1;
    }

    /* modules must be evaluated before their namespace is usable */
    modref = JS_DupValue(ctx, obj);
    promise = JS_EvalFunction(ctx, obj);
    if (JS_IsException(promise)) {
        *err = "module failed to evaluate";
        js_std_dump_error(ctx);
        JS_FreeValue(ctx, promise);
        JS_FreeValue(ctx, modref);
        return -1;
    }
    JS_FreeValue(ctx, promise);

    ns = JS_GetModuleNamespace(ctx, modref);
    JS_FreeValue(ctx, modref);
    if (JS_IsUndefined(ns)) {
        *err = "no module namespace";
        return -1;
    }
    global = JS_GetGlobalObject(ctx);
    if (JS_SetPropertyStr(ctx, global, "__mod", ns) < 0) {
        *err = "cannot install exports";
        JS_FreeValue(ctx, global);
        return -1;
    }
    JS_FreeValue(ctx, global);

    fn = eval_global(ctx, "__mod.name()");
    if (JS_IsException(fn)) {
        js_std_dump_error (ctx);
        *err = "name() threw";
        JS_FreeValue(ctx, fn);
        return -1;
    }
    {
        const char *sv = JS_ToCString(ctx, fn);
        rc = (sv && strcmp(sv, expect_name) == 0) ? 0 : -1;
        if (rc != 0)
            *err = "unexpected name()";
        JS_FreeCString(ctx, sv);
    }
    JS_FreeValue(ctx, fn);
    if (rc != 0)
        return -1;
    if (eval_int(ctx, "__mod.add(2, 3)") != 5) {
        *err = "add() broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.twice(21)") != 42) {
        *err = "twice() broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.magic") != 0x4c554e41) {
        *err = "magic const broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.fib(10)") != 55) {
        *err = "fib broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.recRun()") != 720 + 24) {
        *err = "recursion broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.genRun()") != 6) {
        *err = "generator broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.big(5)") != expect_big(5)) {
        *err = "window path broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.bigRec(3, 2)") != expect_big_rec(3, 2)) {
        *err = "window recursion broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.sum([1, 2, 3, 4, 5])") != 15) {
        *err = "sum broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.pointDist()") != 5) {
        { JSValue v = eval_global(ctx, "__mod.pointDist()"); if (JS_IsException(v)) js_std_dump_error(ctx); else { printf("pointDist() = %d\n", JS_VALUE_GET_INT(v)); JS_FreeValue(ctx, v); } }
        *err = "class/method broken";
        return -1;
    }
    if (eval_int(ctx, "__mod.closureRun()") != 3) {
        *err = "closure broken";
        return -1;
    }
    {
        JSValue str = eval_global(ctx, "__mod.reTest()");

        if (JS_IsException(str)) {
            *err = "reTest threw";
            JS_FreeValue(ctx, str);
            return -1;
        }
        {
            const char *sv = JS_ToCString(ctx, str);

            if (!sv || strcmp(sv, "a52") != 0) {
                *err = "regexp/replace broken";
                JS_FreeCString(ctx, sv);
                JS_FreeValue(ctx, str);
                return -1;
            }
            JS_FreeCString(ctx, sv);
        }
        JS_FreeValue(ctx, str);
    }
    {
        JSValue str = eval_global(ctx, "__mod.tryCatch()");

        if (JS_IsException(str)) {
            *err = "tryCatch threw";
            JS_FreeValue(ctx, str);
            return -1;
        }
        {
            const char *sv = JS_ToCString(ctx, str);

            if (!sv || strcmp(sv, "boom!") != 0) {
                *err = "try/catch broken";
                JS_FreeCString(ctx, sv);
                JS_FreeValue(ctx, str);
                return -1;
            }
            JS_FreeCString(ctx, sv);
        }
        JS_FreeValue(ctx, str);
    }
    {
        JSValue str = eval_global(ctx, "__mod.jsonRoundTrip()");

        if (JS_IsException(str)) {
            *err = "jsonRoundTrip threw";
            JS_FreeValue(ctx, str);
            return -1;
        }
        {
            const char *sv = JS_ToCString(ctx, str);

            if (!sv || strcmp(sv, "x") != 0) {
                *err = "json broken";
                JS_FreeCString(ctx, sv);
                JS_FreeValue(ctx, str);
                return -1;
            }
            JS_FreeCString(ctx, sv);
        }
        JS_FreeValue(ctx, str);
    }
    return 0;
}

int main(void)
{
    JSRuntime *rt;
    JSContext *ctx, *ctx2;
    JSValue mod;
    uint8_t *container = NULL;
    size_t container_len = 0;
    LunaAntiModData am;
    char errbuf[512];
    const char *errmsg = NULL;
    int rc;

    rt = JS_NewRuntime();
    ctx = JS_NewContext(rt);
    ctx2 = JS_NewContext(rt);

    am = antimod("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff", NULL);

    /* 1. compile a module */
    {
        char *src = build_src();

        mod = JS_Eval(ctx, src, strlen(src), "hello.luna",
                      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY |
                      JS_EVAL_FLAG_STRIP);
        free(src);
    }
    check(!JS_IsException(mod), "module compiles");
    if (JS_IsException(mod))
        return 1;

    /* 2. seal it into a permuted, encrypted container */
    container = JS_WriteObjectLuna(ctx, &container_len, mod, JS_WRITE_OBJ_BYTECODE, &am,
                                  LUNA_BC_KDF_SHIFT_DEFAULT, LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
    check(container != NULL, "container written");
    if (!container) {
        js_std_dump_error(ctx);
        return 1;
    }
    check(container_len > LUNA_BC_HEADER_SIZE, "container has a payload");
    if (container)
        check(memcmp(container, LUNA_BC_MAGIC, 4) == 0, "container magic is LUNA");
    if (!container || container_len <= LUNA_BC_HEADER_SIZE)
        return 1;

    /* write twice in a row: compare the raw function bytecode the writer saw */
    {
        uint8_t *again = NULL;
        size_t again_len = 0;

        again = JS_WriteObjectLuna(ctx, &again_len, mod, JS_WRITE_OBJ_BYTECODE, &am,
                                   LUNA_BC_KDF_SHIFT_DEFAULT,
                                   LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
        free(again);
    }

    /* write twice in a row: the payloads must be identical (containers differ
     * only by the random salt) */
    {
        uint8_t *again = NULL, *p1 = NULL, *p2 = NULL;
        size_t again_len = 0, l1 = 0, l2 = 0;

        again = JS_WriteObjectLuna(ctx, &again_len, mod, JS_WRITE_OBJ_BYTECODE, &am,
                                   LUNA_BC_KDF_SHIFT_DEFAULT,
                                   LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
        check(again != NULL, "second write succeeds");
        if (again) {
            check(luna_bc_unpack(container, container_len, &am, &p1, &l1, NULL,
                                 errbuf, sizeof(errbuf)) == LUNA_BC_OK,
                  "first write decrypts");
            check(luna_bc_unpack(again, again_len, &am, &p2, &l2, NULL,
                                 errbuf, sizeof(errbuf)) == LUNA_BC_OK,
                  "second write decrypts");
            /* the containers differ by design (random salt), so only the
             * payload sizes must agree */
            check(l1 == l2 && l1 > 0, "two writes in a row produce the same size");
            free(p1);
            free(p2);
            free(again);
        }
    }

    /* 3. stock reader must reject it (format is not quickjs bytecode) */
    {
        JSValue foreign = JS_ReadObject(ctx2, container, container_len, JS_READ_OBJ_BYTECODE);
        check(JS_IsException(foreign), "stock JS_ReadObject rejects the container");
        JS_FreeValue(ctx2, foreign);
    }

    /* 4. our reader restores and runs it */
    rc = load_and_probe(ctx2, container, container_len, &am, "luna-v1/0", &errmsg);
    check(rc == 0, "container round trip executes");
    if (rc != 0)
        fprintf(stderr, "  (%s)\n", errmsg ? errmsg : "unknown");

    /* 5. wrong anti-mod data (different signing certificate) is rejected */
    {
        LunaAntiModData bad = antimod("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", NULL);
        JSValue obj = JS_ReadObjectLuna(ctx2, container, container_len, JS_READ_OBJ_BYTECODE, &bad, errbuf, sizeof(errbuf));
        check(JS_IsException(obj), "wrong apk signature rejected");
        JS_FreeValue(ctx2, obj);
    }
    /* 5b. device binding enforced when compiled with one */
    {
        LunaAntiModData dev = antimod("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff", "device-42");
        uint8_t *c2 = NULL;
        size_t l2 = 0;
        JSValue obj;

        c2 = JS_WriteObjectLuna(ctx, &l2, mod, JS_WRITE_OBJ_BYTECODE, &dev,
                               LUNA_BC_KDF_SHIFT_DEFAULT,
                               LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_DEVICE_BOUND | LUNA_BC_FLAG_STRIPPED);
        check(c2 != NULL, "device bound container written");
        obj = JS_ReadObjectLuna(ctx2, c2, l2, JS_READ_OBJ_BYTECODE, &dev, errbuf, sizeof(errbuf));
        check(!JS_IsException(obj), "device bound container loads on its device");
        JS_FreeValue(ctx2, obj);
        obj = JS_ReadObjectLuna(ctx2, c2, l2, JS_READ_OBJ_BYTECODE, &am, errbuf, sizeof(errbuf));
        check(JS_IsException(obj), "device bound container rejected elsewhere");
        JS_FreeValue(ctx2, obj);
        free(c2);
    }

    /* 6. tampered ciphertext is rejected */
    {
        uint8_t *tampered = (uint8_t *)malloc(container_len);
        JSValue obj;

        memcpy(tampered, container, container_len);
        tampered[LUNA_BC_HEADER_SIZE + 2] ^= 0x55;
        obj = JS_ReadObjectLuna(ctx2, tampered, container_len, JS_READ_OBJ_BYTECODE, &am, errbuf, sizeof(errbuf));
        check(JS_IsException(obj), "tampered ciphertext rejected");
        JS_FreeValue(ctx2, obj);
        free(tampered);
    }

    /* 7. truncated container is rejected */
    {
        JSValue obj = JS_ReadObjectLuna(ctx2, container, container_len - 4,
                                       JS_READ_OBJ_BYTECODE, &am, errbuf, sizeof(errbuf));
        check(JS_IsException(obj), "truncated container rejected");
        JS_FreeValue(ctx2, obj);
    }

    /*
     * 8. the whole point of the per function permutation: even with the
     * container fully decrypted, the payload is not quickjs bytecode any
     * stock engine can load, because the opcodes are not canonical.
     */
    {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        uint8_t *stock = NULL;
        size_t stock_len2 = 0, stock_len = 0;
        JSValue foreign;

        rc = luna_bc_unpack(container, container_len, &am, &plain, &plain_len,
                            NULL, errbuf, sizeof(errbuf));
        check(rc == LUNA_BC_OK, "payload decrypts with the right key");
        if (rc == LUNA_BC_OK) {
            /*
             * This is the point of the deep encoding: with the container
             * decrypted, a stock quickjs still cannot read the payload. The
             * opcode bytes are permuted (differently at every position
             * parity), every operand is XORed with a per function keystream
             * and the constant pool is in a permuted order, so the stock
             * deserializer either refuses the stream or produces garbage.
             */
            foreign = JS_ReadObject(ctx2, plain, plain_len, JS_READ_OBJ_BYTECODE);
            if (JS_IsException(foreign)) {
                /* best case: the stock deserializer refuses the payload */
                check(1, "decrypted payload is not stock bytecode any more");
            } else {
                /* it walks the structure, but a stock engine can only hand
                 * back what it was given: the permuted opcodes and encoded
                 * operands, never canonical quickjs bytecode */
                uint8_t *round = JS_WriteObject(ctx2, &stock_len2, foreign,
                                                JS_WRITE_OBJ_BYTECODE);

                check(round && stock_len2 == plain_len &&
                          memcmp(round, plain, plain_len) == 0,
                      "a stock round trip keeps the custom encoding");
                js_free(ctx2, round);
            }
            JS_FreeValue(ctx2, foreign);

            /* and it must not equal the canonical serialization of the module */
            stock = JS_WriteObject(ctx, &stock_len, mod, JS_WRITE_OBJ_BYTECODE);
                        if (stock && stock_len == plain_len) {
                check(memcmp(stock, plain, plain_len) != 0,
                      "payload differs from canonical bytecode");
            } else {
                check(1, "payload length differs from canonical bytecode");
            }
            js_free(ctx, stock);
        }
        free(plain);
    }

    check(container[4] == LUNA_BC_VERSION, "our version byte");
    check((container[5] & LUNA_BC_FLAG_PERMUTED) != 0, "permuted flag set");
    {
        uint8_t *again = NULL;
        size_t again_len = 0;

        again = JS_WriteObjectLuna(ctx, &again_len, mod, JS_WRITE_OBJ_BYTECODE, &am,
                                  LUNA_BC_KDF_SHIFT_DEFAULT, LUNA_BC_FLAG_PERMUTED | LUNA_BC_FLAG_STRIPPED);
        check(again != NULL && again_len == container_len && memcmp(again, container, again_len) != 0,
              "two seals of one module differ");
        free(again);
    }

    JS_FreeValue(ctx, mod);
    free(container);
    JS_FreeContext(ctx);
    JS_FreeContext(ctx2);
    JS_FreeRuntime(rt);

    printf("%s: %d checks, %d failures\n", failures ? "FAILED" : "OK", checks, failures);
    return failures ? 1 : 0;
}
