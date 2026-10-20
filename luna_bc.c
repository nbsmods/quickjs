/*
 * Luna custom bytecode container format: implementation.
 *
 * See luna_bc.h for the format description. Everything here is intentionally
 * dependency free C99 so it can be dropped into the engine, the offline
 * compiler and host test harnesses alike.
 */
#include "luna_bc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4)                                                */
/* ------------------------------------------------------------------ */

static const uint32_t luna_bc_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define LUNA_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void luna_bc_sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = LUNA_ROTR32(w[i - 15], 7) ^ LUNA_ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = LUNA_ROTR32(w[i - 2], 17) ^ LUNA_ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = LUNA_ROTR32(e, 6) ^ LUNA_ROTR32(e, 11) ^ LUNA_ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + luna_bc_sha256_k[i] + w[i];
        uint32_t S0 = LUNA_ROTR32(a, 2) ^ LUNA_ROTR32(a, 13) ^ LUNA_ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void luna_bc_sha256_init(LunaBCSha256 *c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0;
    c->buflen = 0;
}

void luna_bc_sha256_update(LunaBCSha256 *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    c->bitlen += (uint64_t)len * 8u;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > len)
            take = len;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            luna_bc_sha256_compress(c->state, c->buf);
            c->buflen = 0;
        }
    }
    while (len >= 64) {
        luna_bc_sha256_compress(c->state, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void luna_bc_sha256_final(LunaBCSha256 *c, uint8_t out[32])
{
    uint64_t bitlen = c->bitlen;
    uint8_t pad[72];
    size_t padlen;
    int i;

    padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    luna_bc_sha256_update(c, pad, padlen);
    /* the length word itself must not be counted */
    c->bitlen = bitlen;
    for (i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bitlen >> (56 - 8 * i));
    luna_bc_sha256_update(c, pad, 8);

    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

void luna_bc_sha256(const void *data, size_t len, uint8_t out[32])
{
    LunaBCSha256 c;
    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, data, len);
    luna_bc_sha256_final(&c, out);
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA256 / PBKDF2                                                */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* HMAC-SHA256 (incremental, so the container MAC can chain the header */
/* and the ciphertext without copying them into one buffer)            */
/* ------------------------------------------------------------------ */

void luna_bc_hmac_init(LunaBCHmac *h, const uint8_t *key, size_t key_len)
{
    uint8_t k[64], pad[64];
    size_t i;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        luna_bc_sha256(key, key_len, k);
    } else if (key_len) {
        memcpy(k, key, key_len);
    }
    for (i = 0; i < 64; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    luna_bc_sha256_init(&h->inner);
    luna_bc_sha256_update(&h->inner, pad, 64);
    for (i = 0; i < 64; i++) {
        h->opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
}

void luna_bc_hmac_update(LunaBCHmac *h, const uint8_t *data, size_t len)
{
    if (len)
        luna_bc_sha256_update(&h->inner, data, len);
}

void luna_bc_hmac_final(LunaBCHmac *h, uint8_t out[32])
{
    uint8_t inner[32];
    LunaBCSha256 c;

    luna_bc_sha256_final(&h->inner, inner);
    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, h->opad, 64);
    luna_bc_sha256_update(&c, inner, 32);
    luna_bc_sha256_final(&c, out);
}

void luna_bc_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t len, uint8_t out[32])
{
    LunaBCHmac c;

    luna_bc_hmac_init(&c, key, key_len);
    if (len)
        luna_bc_hmac_update(&c, data, len);
    luna_bc_hmac_final(&c, out);
}

void luna_bc_pbkdf2_sha256(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iters, uint8_t *out, size_t out_len)
{
    uint32_t block = 1;
    size_t done = 0;

    if (iters == 0)
        iters = 1;
    while (done < out_len) {
        uint8_t asalt[128], count[4], u[32], t[32];
        size_t take, i;
        uint32_t j;
        LunaBCSha256 c;

        if (salt_len > sizeof(asalt) - 4)
            salt_len = sizeof(asalt) - 4;
        memcpy(asalt, salt, salt_len);
        asalt[salt_len] = (uint8_t)(block >> 24);
        asalt[salt_len + 1] = (uint8_t)(block >> 16);
        asalt[salt_len + 2] = (uint8_t)(block >> 8);
        asalt[salt_len + 3] = (uint8_t)(block);
        luna_bc_hmac_sha256(pass, pass_len, asalt, salt_len + 4, u);
        memcpy(t, u, 32);
        for (j = 1; j < iters; j++) {
            luna_bc_hmac_sha256(pass, pass_len, u, 32, u);
            for (i = 0; i < 32; i++)
                t[i] ^= u[i];
        }
        take = out_len - done;
        if (take > 32)
            take = 32;
        memcpy(out + done, t, take);
        done += take;
        block++;
        (void)c;
        (void)count;
    }
}

/* ------------------------------------------------------------------ */
/* ChaCha20 (RFC 8439, 96 bit nonce, 32 bit counter)                   */
/* ------------------------------------------------------------------ */

#define LUNA_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define LUNA_QR(a, b, c, d)                       \
    do {                                         \
        a += b; d ^= a; d = LUNA_ROTL32(d, 16);   \
        c += d; b ^= c; b = LUNA_ROTL32(b, 12);   \
        a += b; d ^= a; d = LUNA_ROTL32(d, 8);    \
        c += d; b ^= c; b = LUNA_ROTL32(b, 7);    \
    } while (0)

static void luna_bc_chacha20_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;

    memcpy(x, in, sizeof(x));
    for (i = 0; i < 10; i++) {
        LUNA_QR(x[0], x[4], x[8], x[12]);
        LUNA_QR(x[1], x[5], x[9], x[13]);
        LUNA_QR(x[2], x[6], x[10], x[14]);
        LUNA_QR(x[3], x[7], x[11], x[15]);
        LUNA_QR(x[0], x[5], x[10], x[15]);
        LUNA_QR(x[1], x[6], x[11], x[12]);
        LUNA_QR(x[2], x[7], x[8], x[13]);
        LUNA_QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[i * 4] = (uint8_t)(v);
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

void luna_bc_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t *data, size_t len)
{
    uint32_t in[16];
    uint8_t ks[64];
    size_t off = 0;
    int i;

    in[0] = 0x61707865u;
    in[1] = 0x3320646eu;
    in[2] = 0x79622d32u;
    in[3] = 0x6b206574u;
    for (i = 0; i < 8; i++) {
        in[4 + i] = ((uint32_t)key[i * 4]) | ((uint32_t)key[i * 4 + 1] << 8) |
                    ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
    }
    in[12] = counter;
    for (i = 0; i < 3; i++) {
        in[13 + i] = ((uint32_t)nonce[i * 4]) | ((uint32_t)nonce[i * 4 + 1] << 8) |
                     ((uint32_t)nonce[i * 4 + 2] << 16) | ((uint32_t)nonce[i * 4 + 3] << 24);
    }

    while (off < len) {
        size_t n = len - off;
        if (n > 64)
            n = 64;
        luna_bc_chacha20_block(in, ks);
        {
            size_t j;
            for (j = 0; j < n; j++)
                data[off + j] ^= ks[j];
        }
        off += n;
        in[12]++;
    }
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

void luna_bc_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    if (!p || !n)
        return;
    /* three passes with volatile writes: a hook on memset(), or a compiler
     * that considers the store dead, cannot skip the erasure */
    for (i = 0; i != n; i++)
        v[i] = 0x00;
    for (i = 0; i != n; i++)
        v[i] = 0xff;
    for (i = 0; i != n; i++)
        v[i] = (uint8_t)(i * 31u + 7u);
    for (i = 0; i != n; i++)
        v[i] = 0x00;
}

int luna_bc_equal(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a, *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++)
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    return diff == 0;
}

static const char luna_bc_hexdigits[] = "0123456789abcdef";

void luna_bc_hex(const uint8_t *in, size_t len, char *out)
{
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = luna_bc_hexdigits[in[i] >> 4];
        out[i * 2 + 1] = luna_bc_hexdigits[in[i] & 15];
    }
    out[len * 2] = '\0';
}

static int luna_bc_hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int luna_bc_unhex(const char *in, uint8_t *out, size_t out_cap)
{
    size_t len = strlen(in), i;

    if (len & 1)
        return LUNA_BC_ERR_ARGUMENT;
    if (len / 2 > out_cap)
        return LUNA_BC_ERR_BUFFER;
    for (i = 0; i < len; i += 2) {
        int hi = luna_bc_hexval(in[i]), lo = luna_bc_hexval(in[i + 1]);
        if (hi < 0 || lo < 0)
            return LUNA_BC_ERR_ARGUMENT;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return LUNA_BC_OK;
}

static uint32_t luna_bc_get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t luna_bc_get_u64le(const uint8_t *p)
{
    return (uint64_t)luna_bc_get_u32le(p) | ((uint64_t)luna_bc_get_u32le(p + 4) << 32);
}

static void luna_bc_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void luna_bc_put_u64le(uint8_t *p, uint64_t v)
{
    luna_bc_put_u32le(p, (uint32_t)(v & 0xffffffffu));
    luna_bc_put_u32le(p + 4, (uint32_t)(v >> 32));
}

static void luna_bc_set_err(char *err, size_t err_cap, const char *msg)
{
    if (err && err_cap)
        snprintf(err, err_cap, "%s", msg);
}

/* ------------------------------------------------------------------ */
/* anti-mod blob canonicalization                                      */
/* ------------------------------------------------------------------ */

static void luna_bc_append_field(uint8_t *buf, size_t *pos, size_t cap,
                                const char *key, const char *val)
{
    size_t klen = strlen(key), vlen = val ? strlen(val) : 0;
    size_t i;

    if (*pos + klen + vlen + 2 > cap)
        return;
    for (i = 0; i < klen; i++)
        buf[(*pos)++] = (uint8_t)key[i];
    if (val) {
        for (i = 0; i < vlen; i++)
            buf[(*pos)++] = (uint8_t)val[i];
    }
    buf[(*pos)++] = 0x1f; /* ASCII unit separator */
}

size_t luna_bc_antimod_blob(const LunaAntiModData *am, uint8_t *out, size_t out_cap)
{
    size_t pos = 0;
    size_t i;
    static const char prefix[] = "luna-antimod-v1";

    for (i = 0; prefix[i] && pos + 1 < out_cap; i++)
        out[pos++] = (uint8_t)prefix[i];
    if (pos + 1 < out_cap)
        out[pos++] = 0x1f;

    luna_bc_append_field(out, &pos, out_cap, "package=", am ? am->package : NULL);
    luna_bc_append_field(out, &pos, out_cap, "apk_sig_sha256=", am ? am->apk_sig_sha256 : NULL);
    luna_bc_append_field(out, &pos, out_cap, "sig_scheme=", am ? am->sig_scheme : NULL);
    luna_bc_append_field(out, &pos, out_cap, "version_code=", am ? am->version_code : NULL);
    luna_bc_append_field(out, &pos, out_cap, "version_name=", am ? am->version_name : NULL);
    luna_bc_append_field(out, &pos, out_cap, "device=", am ? am->device_id : NULL);
    luna_bc_append_field(out, &pos, out_cap, "label=", am ? am->label : NULL);
    return pos;
}

int luna_bc_derive_key(const LunaAntiModData *am, const uint8_t *salt,
                      uint32_t kdf_shift, uint8_t *dk, char *err, size_t err_cap)
{
    uint8_t blob[512];
    size_t blob_len;

    if (kdf_shift < LUNA_BC_KDF_SHIFT_MIN || kdf_shift > LUNA_BC_KDF_SHIFT_MAX) {
        luna_bc_set_err(err, err_cap, "invalid kdf shift");
        return LUNA_BC_ERR_ARGUMENT;
    }
    blob_len = luna_bc_antimod_blob(am, blob, sizeof(blob));
    luna_bc_pbkdf2_sha256(blob, blob_len, salt, LUNA_BC_SALT_LEN, 1u << kdf_shift,
                         dk, LUNA_BC_DK_LEN);
    return LUNA_BC_OK;
}

/* ------------------------------------------------------------------ */
/* container pack / unpack                                             */
/* ------------------------------------------------------------------ */

int luna_bc_pack_begin(const LunaAntiModData *am, uint32_t kdf_shift,
                      LunaBCHeader *hdr, uint8_t *dk, char *err, size_t err_cap)
{
    if (!am || !hdr || !dk) {
        luna_bc_set_err(err, err_cap, "invalid arguments");
        return LUNA_BC_ERR_ARGUMENT;
    }
    if (kdf_shift < LUNA_BC_KDF_SHIFT_MIN || kdf_shift > LUNA_BC_KDF_SHIFT_MAX) {
        luna_bc_set_err(err, err_cap, "invalid kdf shift");
        return LUNA_BC_ERR_ARGUMENT;
    }

    {
        /* salt + nonce from /dev/urandom, with no silent fallback so a broken
         * host cannot produce predictable containers. */
        uint8_t rnd[LUNA_BC_SALT_LEN + LUNA_BC_NONCE_LEN];
        FILE *f = fopen("/dev/urandom", "rb");
        size_t got = 0;

        if (f) {
            got = fread(rnd, 1, sizeof(rnd), f);
            fclose(f);
        }
        if (got != sizeof(rnd)) {
            luna_bc_set_err(err, err_cap, "unable to read /dev/urandom");
            return LUNA_BC_ERR_ARGUMENT;
        }
        memcpy(hdr->salt, rnd, LUNA_BC_SALT_LEN);
        memcpy(hdr->nonce, rnd + LUNA_BC_SALT_LEN, LUNA_BC_NONCE_LEN);
    }

    if (luna_bc_derive_key(am, hdr->salt, kdf_shift, dk, err, err_cap) != LUNA_BC_OK)
        return LUNA_BC_ERR_ARGUMENT;

    hdr->version = LUNA_BC_VERSION;
    hdr->kdf_shift = (uint8_t)kdf_shift;
    hdr->reserved = 0;
    hdr->payload_len = 0;
    hdr->flags = 0;
    return LUNA_BC_OK;
}

int luna_bc_pack_finish(const LunaAntiModData *am, const LunaBCHeader *hdr, const uint8_t *dk,
                       const uint8_t *payload, size_t payload_len, uint8_t **out, size_t *out_len,
                       char *err, size_t err_cap)
{
    uint8_t *buf;
    size_t total;

    (void)am;
    if (!hdr || !dk || !out || !out_len || (!payload && payload_len)) {
        luna_bc_set_err(err, err_cap, "invalid arguments");
        return LUNA_BC_ERR_ARGUMENT;
    }
    if (hdr->version != LUNA_BC_VERSION) {
        luna_bc_set_err(err, err_cap, "unsupported container version");
        return LUNA_BC_ERR_VERSION;
    }
    if (payload_len > 0xffffffffull) {
        luna_bc_set_err(err, err_cap, "payload too large");
        return LUNA_BC_ERR_OVERFLOW;
    }

    total = LUNA_BC_HEADER_SIZE + payload_len;
    if (total < payload_len) {
        luna_bc_set_err(err, err_cap, "payload length overflow");
        return LUNA_BC_ERR_OVERFLOW;
    }
    buf = (uint8_t *)malloc(total ? total : 1);
    if (!buf) {
        luna_bc_set_err(err, err_cap, "out of memory");
        return LUNA_BC_ERR_MEMORY;
    }

    memcpy(buf, LUNA_BC_MAGIC, LUNA_BC_MAGIC_LEN);
    buf[4] = hdr->version;
    buf[5] = hdr->flags;
    buf[6] = hdr->kdf_shift;
    buf[7] = 0;
    luna_bc_put_u64le(buf + 8, (uint64_t)payload_len);
    memcpy(buf + 16, hdr->salt, LUNA_BC_SALT_LEN);
    memcpy(buf + 32, hdr->nonce, LUNA_BC_NONCE_LEN);

    /*
     * key check: HMAC over a fixed label with the dedicated check key. Unlike
     * a keystream prefix this reveals nothing about the stream key.
     */
    {
        uint8_t check_key[LUNA_BC_KEY_LEN], check[32];

        luna_bc_hmac_sha256(dk + LUNA_BC_KEY_LEN, LUNA_BC_HMAC_KEY_LEN,
                            (const uint8_t *)"luna-check-v1", 13, check);
        (void)check_key;
        memcpy(buf + 44, check, LUNA_BC_KEYCHECK_LEN);
        luna_bc_wipe(check, sizeof(check));
    }

    if (payload_len) {
        memcpy(buf + LUNA_BC_HEADER_SIZE, payload, payload_len);
        /* payload uses keystream blocks starting at counter 1 */
        luna_bc_chacha20_xor(dk, hdr->nonce, 1, buf + LUNA_BC_HEADER_SIZE, payload_len);
    }

    {
        uint8_t mac_key[LUNA_BC_KEY_LEN], mac[32];
        LunaBCHmac m;
        LunaBCSha256 c;

        luna_bc_sha256_init(&c);
        luna_bc_sha256_update(&c, "luna-mac-v1", 11);
        luna_bc_sha256_update(&c, dk, LUNA_BC_DK_LEN);
        luna_bc_sha256_final(&c, mac_key);

        luna_bc_hmac_init(&m, mac_key, sizeof(mac_key));
        luna_bc_hmac_update(&m, buf, 52);
        luna_bc_hmac_update(&m, buf + LUNA_BC_HEADER_SIZE, (size_t)payload_len);
        luna_bc_hmac_final(&m, mac);
        memcpy(buf + 52, mac, LUNA_BC_TAG_LEN);
        luna_bc_wipe(mac_key, sizeof(mac_key));
        luna_bc_wipe(mac, sizeof(mac));
    }

    *out = buf;
    *out_len = total;
    return LUNA_BC_OK;
}

int luna_bc_pack(const LunaAntiModData *am, const uint8_t *payload, size_t payload_len,
                uint32_t kdf_shift, int flags, uint8_t **out, size_t *out_len,
                char *err, size_t err_cap)
{
    LunaBCHeader hdr;
    uint8_t dk[LUNA_BC_DK_LEN];
    int rc;

    rc = luna_bc_pack_begin(am, kdf_shift, &hdr, dk, err, err_cap);
    if (rc != LUNA_BC_OK)
        return rc;
    hdr.flags = (uint8_t)(flags & 0xff);
    rc = luna_bc_pack_finish(am, &hdr, dk, payload, payload_len, out, out_len, err, err_cap);
    luna_bc_wipe(dk, sizeof(dk));
    return rc;
}

int luna_bc_unpack_begin(const uint8_t *buf, size_t len, const LunaAntiModData *am,
                        LunaBCHeader *hdr, uint8_t *dk, char *err, size_t err_cap)
{
    LunaBCHeader h;
    int rc;

    rc = luna_bc_parse_header(buf, len, &h, err, err_cap);
    if (rc != LUNA_BC_OK)
        return rc;
    if (luna_bc_derive_key(am, h.salt, h.kdf_shift, dk, err, err_cap) != LUNA_BC_OK) {
        memset(dk, 0, LUNA_BC_DK_LEN);
        return LUNA_BC_ERR_ARGUMENT;
    }
    {
        uint8_t check[32];

        luna_bc_hmac_sha256(dk + LUNA_BC_KEY_LEN, LUNA_BC_HMAC_KEY_LEN,
                            (const uint8_t *)"luna-check-v1", 13, check);
        if (!luna_bc_equal(check, h.key_check, LUNA_BC_KEYCHECK_LEN)) {
            memset(check, 0, sizeof(check));
            luna_bc_set_err(err, err_cap, "wrong key: anti-mod data mismatch");
            luna_bc_wipe(dk, LUNA_BC_DK_LEN);
            return LUNA_BC_ERR_KEY;
        }
        luna_bc_wipe(check, sizeof(check));
    }
    if (hdr)
        *hdr = h;
    return LUNA_BC_OK;
}

int luna_bc_unpack_finish(const uint8_t *buf, size_t len, const LunaBCHeader *hdr,
                         const uint8_t *dk, uint8_t **payload, size_t *payload_len,
                         char *err, size_t err_cap)
{
    uint8_t mac[32];
    uint8_t *plain;

    if (!buf || !hdr || !dk) {
        luna_bc_set_err(err, err_cap, "invalid arguments");
        return LUNA_BC_ERR_ARGUMENT;
    }
    if (len < LUNA_BC_HEADER_SIZE) {
        luna_bc_set_err(err, err_cap, "truncated container");
        return LUNA_BC_ERR_LENGTH;
    }
    /* the tag authenticates exactly payload_len ciphertext bytes, so extra
     * trailing bytes are neither authenticated nor part of the format */
    if (hdr->payload_len != len - LUNA_BC_HEADER_SIZE) {
        luna_bc_set_err(err, err_cap, "container length mismatch");
        return LUNA_BC_ERR_LENGTH;
    }

    /* verify integrity before handing out plaintext */
    {
        uint8_t mac_key[LUNA_BC_KEY_LEN];
        LunaBCSha256 c;
        LunaBCHmac m;

        luna_bc_sha256_init(&c);
        luna_bc_sha256_update(&c, "luna-mac-v1", 11);
        luna_bc_sha256_update(&c, dk, LUNA_BC_DK_LEN);
        luna_bc_sha256_final(&c, mac_key);

        luna_bc_hmac_init(&m, mac_key, sizeof(mac_key));
        luna_bc_hmac_update(&m, buf, 52);
        luna_bc_hmac_update(&m, buf + LUNA_BC_HEADER_SIZE, (size_t)hdr->payload_len);
        luna_bc_hmac_final(&m, mac);
        luna_bc_wipe(mac_key, sizeof(mac_key));
    }
    /* the tag is compared before any of it is erased */
    if (!luna_bc_equal(mac, hdr->tag, LUNA_BC_TAG_LEN)) {
        luna_bc_wipe(mac, sizeof(mac));
        luna_bc_set_err(err, err_cap, "integrity check failed");
        return LUNA_BC_ERR_TAMPERED;
    }

    plain = (uint8_t *)malloc((size_t)hdr->payload_len ? (size_t)hdr->payload_len : 1);
    if (!plain) {
        luna_bc_set_err(err, err_cap, "out of memory");
        return LUNA_BC_ERR_MEMORY;
    }
    if (hdr->payload_len) {
        memcpy(plain, buf + LUNA_BC_HEADER_SIZE, (size_t)hdr->payload_len);
        luna_bc_chacha20_xor(dk, hdr->nonce, 1, plain, (size_t)hdr->payload_len);
    }

    if (payload)
        *payload = plain;
    else
        free(plain);
    if (payload_len)
        *payload_len = (size_t)hdr->payload_len;
    return LUNA_BC_OK;
}

int luna_bc_unpack(const uint8_t *buf, size_t len, const LunaAntiModData *am,
                  uint8_t **payload, size_t *payload_len, LunaBCHeader *hdr,
                  char *err, size_t err_cap)
{
    LunaBCHeader h;
    uint8_t dk[LUNA_BC_DK_LEN];
    int rc;

    rc = luna_bc_unpack_begin(buf, len, am, &h, dk, err, err_cap);
    if (rc != LUNA_BC_OK)
        return rc;
    rc = luna_bc_unpack_finish(buf, len, &h, dk, payload, payload_len, err, err_cap);
    luna_bc_wipe(dk, sizeof(dk));
    if (rc == LUNA_BC_OK && hdr)
        *hdr = h;
    return rc;
}

int luna_bc_parse_header(const uint8_t *buf, size_t len, LunaBCHeader *hdr,
                        char *err, size_t err_cap)
{
    if (!buf || !hdr) {
        luna_bc_set_err(err, err_cap, "invalid arguments");
        return LUNA_BC_ERR_ARGUMENT;
    }
    if (len < LUNA_BC_HEADER_SIZE || memcmp(buf, LUNA_BC_MAGIC, LUNA_BC_MAGIC_LEN) != 0) {
        luna_bc_set_err(err, err_cap, "not a Luna container");
        return LUNA_BC_ERR_MAGIC;
    }
    hdr->version = buf[4];
    hdr->flags = buf[5];
    hdr->kdf_shift = buf[6];
    hdr->reserved = buf[7];
    if (hdr->version != LUNA_BC_VERSION) {
        luna_bc_set_err(err, err_cap, "unsupported container version");
        return LUNA_BC_ERR_VERSION;
    }
    if (hdr->reserved != 0) {
        luna_bc_set_err(err, err_cap, "unsupported reserved header bits");
        return LUNA_BC_ERR_VERSION;
    }
    if (hdr->kdf_shift < LUNA_BC_KDF_SHIFT_MIN || hdr->kdf_shift > LUNA_BC_KDF_SHIFT_MAX) {
        luna_bc_set_err(err, err_cap, "invalid kdf parameters");
        return LUNA_BC_ERR_VERSION;
    }
    hdr->payload_len = luna_bc_get_u64le(buf + 8);
    if (hdr->payload_len > len - LUNA_BC_HEADER_SIZE) {
        luna_bc_set_err(err, err_cap, "truncated container");
        return LUNA_BC_ERR_LENGTH;
    }
    memcpy(hdr->salt, buf + 16, LUNA_BC_SALT_LEN);
    memcpy(hdr->nonce, buf + 32, LUNA_BC_NONCE_LEN);
    memcpy(hdr->key_check, buf + 44, LUNA_BC_KEYCHECK_LEN);
    memcpy(hdr->tag, buf + 52, LUNA_BC_TAG_LEN);
    return LUNA_BC_OK;
}

/* ------------------------------------------------------------------ */
/* opcode permutation                                                  */
/* ------------------------------------------------------------------ */

void luna_bc_perm_key(const uint8_t *dk, uint8_t *out)
{
    luna_bc_sha256("luna-perm-v1", 12, out);
    {
        LunaBCSha256 c;

        luna_bc_sha256_init (&c);
        luna_bc_sha256_update (&c, "luna-perm-v1", 12);
        luna_bc_sha256_update (&c, dk, LUNA_BC_DK_LEN);
        luna_bc_sha256_final (&c, out);
    }
}

typedef struct LunaBCRng {
    uint32_t counter;
    uint8_t key[32];
    uint8_t block[32];
    size_t pos;
} LunaBCRng;

static void luna_bc_rng_init(LunaBCRng *r, const uint8_t *seed, size_t seed_len)
{
    LunaBCSha256 c;

    memset(r, 0, sizeof(*r));
    if (seed_len > 32)
        seed_len = 32;
    memcpy(r->key, seed, seed_len);
    /* mix the rest of the seed into the key */
    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, seed, seed_len);
    luna_bc_sha256_update(&c, "luna-perm-v1", 12);
    luna_bc_sha256_final(&c, r->key);
    r->pos = 32;
}

static uint8_t luna_bc_rng_u8(LunaBCRng *r)
{
    if (r->pos >= 32) {
        uint8_t in[36];

        memcpy(in, r->key, 32);
        in[32] = (uint8_t)(r->counter);
        in[33] = (uint8_t)(r->counter >> 8);
        in[34] = (uint8_t)(r->counter >> 16);
        in[35] = (uint8_t)(r->counter >> 24);
        r->counter++;
        luna_bc_sha256(in, sizeof(in), r->block);
        r->pos = 0;
    }
    return r->block[r->pos++];
}

static uint32_t luna_bc_rng_u32(LunaBCRng *r)
{
    return (uint32_t)luna_bc_rng_u8(r) | ((uint32_t)luna_bc_rng_u8(r) << 8) |
           ((uint32_t)luna_bc_rng_u8(r) << 16) | ((uint32_t)luna_bc_rng_u8(r) << 24);
}

/* uniform value in [0, bound) without modulo bias */
static uint32_t luna_bc_rng_below(LunaBCRng *r, uint32_t bound)
{
    uint32_t limit, v;

    if (bound <= 1)
        return 0;
    limit = (0xffffffffu - (bound - 1)) / bound * bound;
    for (;;) {
        v = luna_bc_rng_u32(r);
        if (v < limit)
            return v % bound;
    }
}

void luna_bc_perm_function_key(uint8_t *out, const uint8_t *perm_master,
                               uint32_t func_index)
{
    LunaBCSha256 c;
    uint8_t idx[4];

    idx[0] = (uint8_t)(func_index);
    idx[1] = (uint8_t)(func_index >> 8);
    idx[2] = (uint8_t)(func_index >> 16);
    idx[3] = (uint8_t)(func_index >> 24);

    luna_bc_sha256_init (&c);
    luna_bc_sha256_update (&c, "luna-perm-func-v1", 17);
    luna_bc_sha256_update (&c, perm_master, LUNA_BC_KEY_LEN);
    luna_bc_sha256_update (&c, idx, sizeof (idx));
    luna_bc_sha256_final (&c, out);
}

void luna_bc_operand_keystream(uint8_t *out, size_t n, const uint8_t *perm_master,
                               uint32_t func_index)
{
    LunaBCSha256 c;
    uint8_t idx[4], block[32];
    size_t done = 0;
    uint32_t counter = 0;

    idx[0] = (uint8_t)(func_index);
    idx[1] = (uint8_t)(func_index >> 8);
    idx[2] = (uint8_t)(func_index >> 16);
    idx[3] = (uint8_t)(func_index >> 24);

    while (done < n) {
        uint8_t ctr[4];
        size_t take;

        ctr[0] = (uint8_t)(counter);
        ctr[1] = (uint8_t)(counter >> 8);
        ctr[2] = (uint8_t)(counter >> 16);
        ctr[3] = (uint8_t)(counter >> 24);
        counter++;

        luna_bc_sha256_init(&c);
        luna_bc_sha256_update(&c, "luna-operand-ks-v1", 18);
        luna_bc_sha256_update(&c, perm_master, LUNA_BC_KEY_LEN);
        luna_bc_sha256_update(&c, idx, sizeof(idx));
        luna_bc_sha256_update(&c, ctr, sizeof(ctr));
        luna_bc_sha256_final(&c, block);

        take = n - done;
        if (take > sizeof(block))
            take = sizeof(block);
        memcpy(out + done, block, take);
        done += take;
    }
    luna_bc_wipe(block, sizeof(block));
}

void luna_bc_cpool_key(uint8_t *out, const uint8_t *perm_master,
                       uint32_t func_index, uint32_t cpool_count)
{
    LunaBCSha256 c;
    uint8_t buf[12];

    buf[0] = (uint8_t)(func_index);
    buf[1] = (uint8_t)(func_index >> 8);
    buf[2] = (uint8_t)(func_index >> 16);
    buf[3] = (uint8_t)(func_index >> 24);
    buf[4] = (uint8_t)(cpool_count);
    buf[5] = (uint8_t)(cpool_count >> 8);
    buf[6] = (uint8_t)(cpool_count >> 16);
    buf[7] = (uint8_t)(cpool_count >> 24);
    buf[8] = (uint8_t)(cpool_count >> 16);
    buf[9] = (uint8_t)(cpool_count >> 24);
    buf[10] = (uint8_t)(cpool_count >> 8);
    buf[11] = (uint8_t)(cpool_count);

    luna_bc_sha256_init(&c);
    luna_bc_sha256_update(&c, "luna-cpool-v1", 12);
    luna_bc_sha256_update(&c, perm_master, LUNA_BC_KEY_LEN);
    luna_bc_sha256_update(&c, buf, sizeof(buf));
    luna_bc_sha256_final(&c, out);
    luna_bc_wipe(buf, sizeof(buf));
}

void luna_bc_perm_range(uint32_t *perm, uint32_t *inv, uint32_t count,
                        const uint8_t *key, size_t key_len)
{
    LunaBCRng rng;
    uint32_t i;

    /* both outputs are filled, so the shuffle runs on a local when only one is
     * wanted */
    {
        uint32_t *work = perm;
        uint32_t stack_buf[64];

        if (!work) {
            work = (count <= sizeof(stack_buf) / sizeof(stack_buf[0]))
                       ? stack_buf
                       : (uint32_t *)malloc(count * sizeof(uint32_t));
            if (!work)
                return;
        }
        for (i = 0; i != count; i++)
            work[i] = i;
        if (count >= 2 && key) {
            luna_bc_rng_init(&rng, key, key_len);
            for (i = count - 1; i > 0; i--) {
                uint32_t j = luna_bc_rng_below(&rng, i + 1);
                uint32_t t = work[i];

                work[i] = work[j];
                work[j] = t;
            }
            luna_bc_wipe(&rng, sizeof(rng));
        }
        if (perm) {
            if (inv)
                for (i = 0; i != count; i++)
                    inv[perm[i]] = i;
        } else {
            if (inv)
                for (i = 0; i != count; i++)
                    inv[work[i]] = i;
            if (work != stack_buf)
                free(work);
            else
                luna_bc_wipe(work, sizeof(stack_buf));
        }
    }
}

void luna_bc_perm_wipe(LunaBCPerm *p)
{
    luna_bc_wipe(p, sizeof(*p));
}

/* A tiny SHA-256 based stream generator: deterministic on all platforms and
 * without any global state. */
void luna_bc_build_permutation(LunaBCPerm *p, const uint8_t *key, size_t key_len,
                              const uint8_t *op_size, const uint8_t *op_fmt)
{
    int v;

    for (v = 0; v < 256; v++) {
        p->perm[v] = (uint8_t)v;
        p->unperm[v] = (uint8_t)v;
    }
    if (!op_size || !op_fmt)
        return;

    /* Shuffle each (size, fmt) opcode class independently. Because the class
     * is closed under the mapping, instruction sizes and operand formats are
     * preserved: a permuted opcode stream is still a well formed stream that
     * only our reader knows how to interpret. */
    {
        int size, fmt;

        for (size = 1; size < 256; size++) {
            for (fmt = 0; fmt < 256; fmt++) {
                uint8_t members[256];
                uint8_t idx[256];
                int count = 0, i, identity;
                LunaBCRng r;
                uint8_t seed[32];
                uint8_t class_id[2];

                for (v = 0; v < 256; v++) {
                    if (op_size[v] == size && op_fmt[v] == fmt)
                        members[count++] = (uint8_t)v;
                }
                if (count < 2)
                    continue;

                class_id[0] = (uint8_t)size;
                class_id[1] = (uint8_t)fmt;
                {
                    LunaBCSha256 c;

                    luna_bc_sha256_init(&c);
                    luna_bc_sha256_update(&c, key, key_len);
                    luna_bc_sha256_update(&c, class_id, 2);
                    luna_bc_sha256_update(&c, "luna-class-v1", 13);
                    luna_bc_sha256_final(&c, seed);
                }
                luna_bc_rng_init(&r, seed, sizeof(seed));

                for (i = 0; i < count; i++)
                    idx[i] = (uint8_t)i;
                for (i = count - 1; i > 0; i--) {
                    uint32_t j = luna_bc_rng_below(&r, (uint32_t)(i + 1));
                    uint8_t t = idx[i];
                    idx[i] = idx[j];
                    idx[j] = t;
                }
                /* never leave a shuffleable class unshuffled */
                identity = 1;
                for (i = 0; i < count; i++) {
                    if (idx[i] != (uint8_t)i) {
                        identity = 0;
                        break;
                    }
                }
                if (identity) {
                    uint8_t t = idx[0];
                    idx[0] = idx[1];
                    idx[1] = t;
                }
                for (i = 0; i < count; i++) {
                    p->perm[members[i]] = members[idx[i]];
                    p->unperm[members[idx[i]]] = members[i];
                }
            }
        }
    }
}

long luna_bc_permute_stream(uint8_t *buf, size_t len, const LunaBCPerm *p,
                           int inverse, const uint8_t *op_size)
{
    const uint8_t *table = inverse ? p->unperm : p->perm;
    size_t pos = 0;

    if (!table || !op_size)
        return -1;
    while (pos < len) {
        uint8_t op = buf[pos];
        uint8_t size = op_size[table[op]];

        if (!size || size > len - pos)
            return -1;
        buf[pos] = table[op];
        pos += size;
    }
    return (long)pos;
}
