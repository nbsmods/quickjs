/*
 * Self test for the Luna bytecode container codec.
 *
 * Build: make luna_bc_test    (or see run-luna-tests.sh)
 */
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

static void check_hex(const uint8_t *got, const char *expect, const char *what)
{
    char hex[256];

    luna_bc_hex(got, strlen(expect) / 2, hex);
    if (strcmp(hex, expect) != 0) {
        failures++;
        checks++;
        fprintf(stderr, "FAIL: %s\n  got      %s\n  expected %s\n", what, hex, expect);
        return;
    }
    checks++;
}

static void test_sha256(void)
{
    LunaBCSha256 c;
    uint8_t out[32];

    luna_bc_sha256("abc", 3, out);
    check_hex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "sha256(\"abc\")");

    luna_bc_sha256("", 0, out);
    check_hex(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "sha256(\"\")");

    /* multi update path, exactly block sized and block + 1 */
    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    luna_bc_sha256_final(&c, out);
    check_hex(out, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
              "sha256(56 bytes)");

    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                             "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112);
    luna_bc_sha256_final(&c, out);
    check_hex(out, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
              "sha256(112 bytes)");
}

static void test_hmac(void)
{
    uint8_t out[32];

    luna_bc_hmac_sha256((const uint8_t *)"Jefe", 4,
                       (const uint8_t *)"what do ya want for nothing?", 28, out);
    check_hex(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
              "hmac-sha256 RFC 4231 case 2");
}

static void test_pbkdf2(void)
{
    uint8_t out[32];

    luna_bc_pbkdf2_sha256((const uint8_t *)"password", 8,
                         (const uint8_t *)"salt", 4, 1, out, 32);
    check_hex(out, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
              "pbkdf2-hmac-sha256 c=1");
}

static void test_chacha20(void)
{
    uint8_t key[32], nonce[12], buf[64];
    int i;

    /* RFC 8439 section 2.3.2: all zero key/nonce */
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    memset(buf, 0, sizeof(buf));
    luna_bc_chacha20_xor(key, nonce, 0, buf, sizeof(buf));
    check(memcmp(buf, "\x76\xb8\xe0\xad\xa0\xf1\x3d\x90\x40\x5d\x6a\xe5\x53\x86\xbd\x28", 16) == 0,
          "chacha20 keystream RFC 8439 2.3.2");

    /* RFC 8439 section 2.4.2 */
    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    nonce[4] = 0; nonce[5] = 0; nonce[6] = 0; nonce[7] = 0x4a;
    nonce[8] = 0; nonce[9] = 0; nonce[10] = 0; nonce[11] = 0;
    {
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                         "only one tip for the future, sunscreen would be it.";
        uint8_t ct[114];
        memcpy(ct, pt, 114);
        luna_bc_chacha20_xor(key, nonce, 1, ct, 114);
        check(memcmp(ct, "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81", 16) == 0,
              "chacha20 RFC 8439 2.4.2 block");
        /* and back */
        luna_bc_chacha20_xor(key, nonce, 1, ct, 114);
        check(memcmp(ct, pt, 114) == 0, "chacha20 round trip");
    }
}

/* synthetic opcode table with a couple of size/fmt classes */
static const uint8_t test_op_size[256] = {
    /* 0..15: size 1, fmt 1 */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    /* 16..23: size 5, fmt 3 */
    5,5,5,5,5,5,5,5,
    /* 24..31: size 2, fmt 1 */
    2,2,2,2,2,2,2,2,
};
static const uint8_t test_op_fmt[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    3,3,3,3,3,3,3,3,
    1,1,1,1,1,1,1,1,
};

static void test_permutation(void)
{
    LunaBCPerm p, q;
    uint8_t key[32];
    uint8_t stream[64];
    uint8_t copy[64];
    long n;
    int i, differs = 0;

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)(i * 7 + 3);

    memset(&p, 0, sizeof(p));
    luna_bc_build_permutation(&p, key, sizeof(key), test_op_size, test_op_fmt);

    /* size preservation */
    for (i = 0; i < 256; i++) {
        if (test_op_size[i] && test_op_size[p.perm[i]] != test_op_size[i]) {
            check(0, "permutation preserves instruction size");
            return;
        }
    }
    /* bijection + inverse consistency */
    for (i = 0; i < 256; i++) {
        if (test_op_size[i] && p.unperm[p.perm[i]] != i) {
            check(0, "permutation is invertible");
            return;
        }
    }
    /* it must actually shuffle something */
    for (i = 0; i < 16; i++) {
        if (p.perm[i] != i)
            differs++;
    }
    check(differs > 0, "permutation is not the identity");

    /* stream walk: op0, oplabel(size5), op1, oploc(size2) */
    {
        size_t pos = 0;
        stream[pos++] = 0;
        stream[pos++] = 16; stream[pos++] = 0xaa; stream[pos++] = 0xbb;
        stream[pos++] = 0xcc; stream[pos++] = 0xdd;
        stream[pos++] = 1;
        stream[pos++] = 24; stream[pos++] = 0x11;
        n = (long)pos;
    }
    memcpy(copy, stream, n);
    check(luna_bc_permute_stream(stream, n, &p, 0, test_op_size) == n,
          "permute walks the whole stream");
    check(memcmp(stream, copy, n) != 0, "permuted stream differs from canonical");
    check(luna_bc_permute_stream(stream, n, &p, 1, test_op_size) == n,
          "unpermute walks the whole stream");
    check(memcmp(stream, copy, n) == 0, "unpermute restores the stream");

    /* different key -> different permutation */
    key[0] ^= 0xff;
    luna_bc_build_permutation(&q, key, sizeof(key), test_op_size, test_op_fmt);
    check(memcmp(p.perm, q.perm, 256) != 0, "permutation depends on the key");

    /* malformed stream (trailing garbage) is rejected */
    stream[0] = 16;
    stream[1] = 0;
    check(luna_bc_permute_stream(stream, 2, &p, 0, test_op_size) == -1,
          "truncated instruction is rejected");
}

static LunaAntiModData make_antimod(const char *sig, const char *device)
{
    LunaAntiModData am;

    memset(&am, 0, sizeof(am));
    am.package = "com.example.app";
    am.apk_sig_sha256 = sig;
    am.sig_scheme = "v3";
    am.version_name = "1.2.3";
    am.version_code = "45";
    am.device_id = device;
    am.label = "com.example.mod.hello";
    return am;
}

static void test_container(void)
{
    const uint8_t payload[] = "the quick brown fox jumps over the lazy dog, twice.";
    uint8_t *packed = NULL, *plain = NULL;
    size_t packed_len = 0, plain_len = 0;
    LunaBCHeader hdr;
    char err[LUNA_BC_ERROR_MAX];
    LunaAntiModData am = make_antimod("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", NULL);
    int rc;

    rc = luna_bc_pack(&am, payload, sizeof(payload) - 1, 14, LUNA_BC_FLAG_PERMUTED, &packed,
                     &packed_len, err, sizeof(err));
    check(rc == LUNA_BC_OK, "pack succeeds");
    check(packed_len == LUNA_BC_HEADER_SIZE + sizeof(payload) - 1, "container size");
    check(memcmp(packed, LUNA_BC_MAGIC, 4) == 0, "container magic");
    check(luna_bc_parse_header(packed, packed_len, &hdr, err, sizeof(err)) == LUNA_BC_OK,
          "header parses");
    check((hdr.flags & LUNA_BC_FLAG_PERMUTED) != 0, "permuted flag stored");
    check(hdr.payload_len == sizeof(payload) - 1, "payload length stored");
    check(memcmp(packed + LUNA_BC_HEADER_SIZE, payload, sizeof(payload) - 1) != 0,
          "ciphertext differs from plaintext");

    rc = luna_bc_unpack(packed, packed_len, &am, &plain, &plain_len, &hdr, err, sizeof(err));
    check(rc == LUNA_BC_OK, "unpack succeeds");
    check(plain_len == sizeof(payload) - 1, "unpacked length matches");
    check(plain && memcmp(plain, payload, plain_len) == 0, "unpacked payload matches");

    /* wrong anti-mod data (different app signature) must fail with a key error */
    {
        LunaAntiModData bad = make_antimod("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", NULL);
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        rc = luna_bc_unpack(packed, packed_len, &bad, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_KEY, "wrong apk signature rejected");
        check(p2 == NULL, "no plaintext on key mismatch");
    }
    /* wrong device binding must fail too */
    {
        LunaAntiModData dev = make_antimod("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                                         "device-a");
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        rc = luna_bc_unpack(packed, packed_len, &dev, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_KEY, "device binding enforced");
    }
    /* tampering with the ciphertext is caught by the MAC */
    {
        uint8_t *tampered = (uint8_t *)malloc(packed_len);
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        memcpy(tampered, packed, packed_len);
        tampered[LUNA_BC_HEADER_SIZE + 3] ^= 0x40;
        rc = luna_bc_unpack(tampered, packed_len, &am, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_TAMPERED, "tampered ciphertext rejected");
        free(tampered);
    }
    /* tampering with the header (payload length) is caught too */
    {
        uint8_t *tampered = (uint8_t *)malloc(packed_len);
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        memcpy(tampered, packed, packed_len);
        tampered[8] = (uint8_t)(tampered[8] + 1);
        rc = luna_bc_unpack(tampered, packed_len, &am, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_LENGTH || rc == LUNA_BC_ERR_TAMPERED, "tampered header rejected");
        free(tampered);
    }
    /* truncation */
    {
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        rc = luna_bc_unpack(packed, packed_len - 5, &am, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_LENGTH, "truncated container rejected");
    }
    /* trailing bytes are not covered by the tag, so the format rejects them */
    {
        uint8_t *padded = (uint8_t *)malloc(packed_len + 1);
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        memcpy(padded, packed, packed_len);
        padded[packed_len] = 0xaa;
        rc = luna_bc_unpack(padded, packed_len + 1, &am, &p2, &l2, NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_LENGTH, "trailing bytes rejected");
        free(padded);
    }
    /* the two step API must not underflow when handed a short buffer */
    {
        LunaBCHeader h;
        uint8_t dk[LUNA_BC_DK_LEN];
        uint8_t *p2 = NULL;
        size_t l2 = 0;

        rc = luna_bc_unpack_begin(packed, packed_len, &am, &h, dk, err, sizeof(err));
        check(rc == LUNA_BC_OK, "unpack begin succeeds");
        if (rc == LUNA_BC_OK) {
            rc = luna_bc_unpack_finish(packed, 10, &h, dk, &p2, &l2, err, sizeof(err));
            check(rc == LUNA_BC_ERR_LENGTH, "short buffer rejected without underflow");
        }
    }
    /* reserved header bits must stay zero */
    {
        uint8_t *tampered = (uint8_t *)malloc(packed_len);
        memcpy(tampered, packed, packed_len);
        tampered[7] = 1;
        rc = luna_bc_parse_header(tampered, packed_len, &hdr, err, sizeof(err));
        check(rc == LUNA_BC_ERR_VERSION, "reserved header bits rejected");
        free(tampered);
    }
    /* not a container at all */
    {
        uint8_t *p2 = NULL;
        size_t l2 = 0;
        rc = luna_bc_unpack((const uint8_t *)"deadbeefdeadbeefdeadbeefdeadbeef", 32, &am, &p2, &l2,
                           NULL, err, sizeof(err));
        check(rc == LUNA_BC_ERR_MAGIC, "foreign magic rejected");
    }

    /* two packs of the same payload must differ (random salt/nonce) */
    {
        uint8_t *again = NULL;
        size_t again_len = 0;
        rc = luna_bc_pack(&am, payload, sizeof(payload) - 1, 14, LUNA_BC_FLAG_PERMUTED, &again,
                         &again_len, err, sizeof(err));
        check(rc == LUNA_BC_OK, "second pack succeeds");
        check(again_len == packed_len && memcmp(again, packed, packed_len) != 0,
              "containers are not deterministic");
        free(again);
    }

    free(packed);
    free(plain);
}

static void *luna_bc_contains(const uint8_t *hay, size_t hay_len, const char *needle)
{
    size_t n = strlen(needle), i;
    if (n == 0 || n > hay_len)
        return NULL;
    for (i = 0; i + n <= hay_len; i++) {
        if (memcmp(hay + i, needle, n) == 0)
            return (void *)(hay + i);
    }
    return NULL;
}

static void test_antimod_blob(void)
{
    LunaAntiModData a = make_antimod("aa", "dev1");
    LunaAntiModData b = make_antimod("aa", "dev2");
    LunaAntiModData c = make_antimod("aa", NULL);
    uint8_t ba[512], bb[512], bc[512];
    size_t la, lb, lc;

    la = luna_bc_antimod_blob(&a, ba, sizeof(ba));
    lb = luna_bc_antimod_blob(&b, bb, sizeof(bb));
    lc = luna_bc_antimod_blob(&c, bc, sizeof(bc));
    check(la > 0 && la == lb && lc > 0, "blob sizes match");
    check(memcmp(ba, bb, la) != 0, "device id changes the blob");
    check(memcmp(ba, bc, la) != 0, "empty device id changes the blob");
    check(luna_bc_contains(ba, la, "com.example.app") != NULL, "package is part of the blob");
}

static void test_hmac_incremental(void)
{
    uint8_t key[32], a[52], b[48], tmp[100];
    uint8_t one[32], inc[32];
    LunaBCHmac h;
    int i;

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    for (i = 0; i < 52; i++)
        a[i] = (uint8_t)(i * 3);
    for (i = 0; i < 48; i++)
        b[i] = (uint8_t)(i * 7);

    memcpy(tmp, a, 52);
    memcpy(tmp + 52, b, 48);
    luna_bc_hmac_sha256(key, 32, tmp, 100, one);

    luna_bc_hmac_init(&h, key, 32);
    luna_bc_hmac_update(&h, a, 52);
    luna_bc_hmac_update(&h, b, 48);
    luna_bc_hmac_update(&h, NULL, 0);
    luna_bc_hmac_final(&h, inc);
    check(memcmp(one, inc, 32) == 0, "incremental HMAC matches one-shot");
}

int main(void)
{
    test_sha256();
    test_hmac();
    test_hmac_incremental();
    test_hmac();
    test_pbkdf2();
    test_chacha20();
    test_permutation();
    test_container();
    test_antimod_blob();

    printf("%s: %d checks, %d failures\n", failures ? "FAILED" : "OK", checks, failures);
    return failures ? 1 : 0;
}
