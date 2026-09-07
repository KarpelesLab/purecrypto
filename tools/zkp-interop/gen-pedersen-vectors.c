/* Emits vectors/pedersen.json from the secp256k1-zkp black-box oracle.
 *
 * Driven exclusively through the public C API declared in
 * <oracle>/include/secp256k1_generator.h. No implementation file
 * (<oracle>/src/*.c) is read or included -- see ./README.md.
 *
 * Build (after ./build-oracle.sh):
 *
 *   cc gen-pedersen-vectors.c -I <oracle>/include \
 *      <oracle>/.libs/libsecp256k1.a <oracle>/.libs/libsecp256k1_precomputed.a \
 *      -o gen-pedersen-vectors
 *   ./gen-pedersen-vectors > vectors/pedersen.json
 *
 * This program is developer-only: it is never built by CI and the crate's
 * tests never link against the oracle -- they read the committed JSON.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1_generator.h"

static void put_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* A cheap deterministic byte expander so the vector set is reproducible
 * without pulling in an RNG: SHA-256-free xorshift over a 64-bit seed. */
static uint64_t rng_state;
static void fill(unsigned char *out, size_t n, uint64_t seed) {
    rng_state = seed ? seed : 1;
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        out[i] = (unsigned char)(rng_state >> 24);
    }
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char out[33], blind[32], tag[32];
    secp256k1_pedersen_commitment c;
    secp256k1_generator g;

    printf("{\n");

    printf("  \"generator_h\": \"");
    secp256k1_generator_serialize(ctx, out, secp256k1_generator_h);
    put_hex(out, 33);
    printf("\",\n");

    /* Commitments against the fixed generator H. */
    printf("  \"commitments\": [\n");
    {
        static const uint64_t values[] = {
            0, 1, 2, 42, 255, 256, 65535, 1000000,
            0x7fffffffffffffffULL, 0xffffffffffffffffULL, 21000000ULL * 100000000ULL, 3
        };
        size_t nv = sizeof(values) / sizeof(values[0]);
        int first = 1;
        for (size_t i = 0; i < nv; i++) {
            fill(blind, 32, 0x9e3779b97f4a7c15ULL + i);
            if (!secp256k1_pedersen_commit(ctx, &c, blind, values[i], secp256k1_generator_h)) continue;
            secp256k1_pedersen_commitment_serialize(ctx, out, &c);
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"value\": %llu, \"blind\": \"", (unsigned long long)values[i]);
            put_hex(blind, 32);
            printf("\", \"commitment\": \"");
            put_hex(out, 33);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* Asset generators from a 32-byte tag. */
    printf("  \"generators\": [\n");
    {
        int first = 1;
        for (unsigned i = 0; i < 64; i++) {
            if (i == 0) memset(tag, 0x00, 32);
            else if (i == 1) memset(tag, 0xff, 32);
            else fill(tag, 32, 0xdeadbeefcafeULL + i);
            if (!secp256k1_generator_generate(ctx, &g, tag)) continue;
            secp256k1_generator_serialize(ctx, out, &g);
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"tag\": \"");
            put_hex(tag, 32);
            printf("\", \"generator\": \"");
            put_hex(out, 33);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* Blinded asset generators. */
    printf("  \"blinded_generators\": [\n");
    {
        int first = 1;
        for (unsigned i = 0; i < 16; i++) {
            fill(tag, 32, 0x0123456789abcdefULL + i);
            fill(blind, 32, 0xfedcba9876543210ULL + i);
            if (!secp256k1_generator_generate_blinded(ctx, &g, tag, blind)) continue;
            secp256k1_generator_serialize(ctx, out, &g);
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"tag\": \"");
            put_hex(tag, 32);
            printf("\", \"blind\": \"");
            put_hex(blind, 32);
            printf("\", \"generator\": \"");
            put_hex(out, 33);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* Commitments against a per-asset generator. */
    printf("  \"asset_commitments\": [\n");
    {
        int first = 1;
        for (unsigned i = 0; i < 8; i++) {
            fill(tag, 32, 0x5eed0000ULL + i);
            fill(blind, 32, 0xb11d0000ULL + i);
            if (!secp256k1_generator_generate(ctx, &g, tag)) continue;
            uint64_t v = ((uint64_t)i + 1) * 1000003ULL;
            if (!secp256k1_pedersen_commit(ctx, &c, blind, v, &g)) continue;
            secp256k1_pedersen_commitment_serialize(ctx, out, &c);
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"tag\": \"");
            put_hex(tag, 32);
            printf("\", \"value\": %llu, \"blind\": \"", (unsigned long long)v);
            put_hex(blind, 32);
            printf("\", \"commitment\": \"");
            put_hex(out, 33);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* blind_sum: last blind chosen so the tally balances. */
    printf("  \"blind_sums\": [\n");
    {
        int first = 1;
        for (unsigned i = 1; i <= 5; i++) {
            unsigned char b[8][32];
            const unsigned char *ptrs[8];
            unsigned char sum[32];
            for (unsigned j = 0; j < i; j++) {
                fill(b[j], 32, 0xa5a50000ULL + i * 16 + j);
                ptrs[j] = b[j];
            }
            /* first `npositive` are added, the rest subtracted */
            unsigned npos = (i + 1) / 2;
            if (!secp256k1_pedersen_blind_sum(ctx, sum, ptrs, i, npos)) continue;
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"npositive\": %u, \"blinds\": [", npos);
            for (unsigned j = 0; j < i; j++) {
                if (j) printf(", ");
                printf("\"");
                put_hex(b[j], 32);
                printf("\"");
            }
            printf("], \"sum\": \"");
            put_hex(sum, 32);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* blind_generator_blind_sum: the Confidential Assets variant, where the
     * generators themselves are blinded (A' = A + rG). */
    printf("  \"generator_blind_sums\": [\n");
    {
        int first = 1;
        for (unsigned k = 2; k <= 5; k++) {
            uint64_t values[8];
            unsigned char gb[8][32], bf[8][32], before[8][32];
            const unsigned char *gbp[8];
            unsigned char *bfp[8];
            for (unsigned j = 0; j < k; j++) {
                values[j] = ((uint64_t)j + 1) * 7919ULL + k;
                fill(gb[j], 32, 0x6ee20000ULL + k * 16 + j);
                fill(bf[j], 32, 0x77770000ULL + k * 16 + j);
                memcpy(before[j], bf[j], 32);
                gbp[j] = gb[j];
                bfp[j] = bf[j];
            }
            unsigned n_inputs = k / 2;
            if (!secp256k1_pedersen_blind_generator_blind_sum(ctx, values, gbp, bfp, k, n_inputs)) continue;
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"n_inputs\": %u, \"values\": [", n_inputs);
            for (unsigned j = 0; j < k; j++) printf("%s%llu", j ? ", " : "", (unsigned long long)values[j]);
            printf("], \"generator_blinds\": [");
            for (unsigned j = 0; j < k; j++) { printf("%s\"", j ? ", " : ""); put_hex(gb[j], 32); printf("\""); }
            printf("], \"blinding_factors\": [");
            for (unsigned j = 0; j < k; j++) { printf("%s\"", j ? ", " : ""); put_hex(before[j], 32); printf("\""); }
            printf("], \"last_blind\": \"");
            put_hex(bf[k - 1], 32);
            printf("\" }");
        }
    }
    printf("\n  ],\n");

    /* Parse-rejection corpus: every 33-byte input here must be rejected. */
    printf("  \"invalid_commitments\": [\n");
    {
        unsigned char in[33];
        int first = 1;
        secp256k1_pedersen_commitment cc;
        /* every non-0x08/0x09 prefix over a valid x */
        secp256k1_generator_serialize(ctx, in, secp256k1_generator_h);
        for (unsigned pfx = 0; pfx < 256; pfx++) {
            if (pfx == 0x08 || pfx == 0x09) continue;
            in[0] = (unsigned char)pfx;
            if (secp256k1_pedersen_commitment_parse(ctx, &cc, in)) continue; /* accepted: not a rejection vector */
            if (pfx > 0x0f && pfx != 0xff) continue; /* keep the corpus small */
            if (!first) printf(",\n");
            first = 0;
            printf("    \"");
            put_hex(in, 33);
            printf("\"");
        }
        /* x >= p and x = p exactly */
        {
            static const unsigned char pm[32] = {
              0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
              0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0x2f};
            in[0] = 0x08; memcpy(in + 1, pm, 32);
            if (!secp256k1_pedersen_commitment_parse(ctx, &cc, in)) {
                printf(",\n    \""); put_hex(in, 33); printf("\"");
            }
            in[0] = 0x09; memset(in + 1, 0xff, 32);
            if (!secp256k1_pedersen_commitment_parse(ctx, &cc, in)) {
                printf(",\n    \""); put_hex(in, 33); printf("\"");
            }
        }
        /* small x values that are not on the curve */
        for (unsigned k = 0; k < 64; k++) {
            in[0] = 0x08; memset(in + 1, 0, 32); in[32] = (unsigned char)k;
            if (!secp256k1_pedersen_commitment_parse(ctx, &cc, in)) {
                printf(",\n    \""); put_hex(in, 33); printf("\"");
            }
        }
    }
    printf("\n  ],\n");

    printf("  \"invalid_generators\": [\n");
    {
        unsigned char in[33];
        int first = 1;
        secp256k1_generator gg;
        secp256k1_generator_serialize(ctx, in, secp256k1_generator_h);
        for (unsigned pfx = 0; pfx <= 0x0f; pfx++) {
            if (pfx == 0x0a || pfx == 0x0b) continue;
            in[0] = (unsigned char)pfx;
            if (secp256k1_generator_parse(ctx, &gg, in)) continue;
            if (!first) printf(",\n");
            first = 0;
            printf("    \""); put_hex(in, 33); printf("\"");
        }
        {
            static const unsigned char pm[32] = {
              0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
              0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0x2f};
            in[0] = 0x0a; memcpy(in + 1, pm, 32);
            if (!secp256k1_generator_parse(ctx, &gg, in)) { printf(",\n    \""); put_hex(in, 33); printf("\""); }
        }
        for (unsigned k = 0; k < 64; k++) {
            in[0] = 0x0b; memset(in + 1, 0, 32); in[32] = (unsigned char)k;
            if (!secp256k1_generator_parse(ctx, &gg, in)) { printf(",\n    \""); put_hex(in, 33); printf("\""); }
        }
    }
    printf("\n  ]\n");

    printf("}\n");
    return 0;
}
