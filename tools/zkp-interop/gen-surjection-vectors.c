/* Emits vectors/surjection.json from the secp256k1-zkp black-box oracle.
 *
 * Driven exclusively through the public C API declared in
 * <oracle>/include/secp256k1_surjectionproof.h and secp256k1_generator.h. No
 * implementation file under <oracle>/src is read or included -- see ./README.md.
 *
 * Build (after ./build-oracle.sh):
 *
 *   cc gen-surjection-vectors.c -I <oracle>/include \
 *      <oracle>/.libs/libsecp256k1.a <oracle>/.libs/libsecp256k1_precomputed.a \
 *      -o gen-surjection-vectors
 *
 * Two-step use, because one section records proofs made by *this crate* that
 * the oracle accepted:
 *
 *   1. ./gen-surjection-vectors > vectors/surjection.json
 *      (the "purecrypto_proofs" section comes out empty)
 *   2. produce proofs with the crate for the statements in the "proofs"
 *      section, write them one per line as
 *
 *          <input_index> <output_gen_hex> <ib_hex> <ob_hex> <proof_hex> <gen_hex>...
 *
 *      then ./gen-surjection-vectors that-file > vectors/surjection.json
 *      which verifies each line with secp256k1_surjectionproof_verify and
 *      aborts if any is rejected.
 *
 * This program is developer-only: it is never built by CI and the crate's
 * tests never link against the oracle -- they read the committed JSON.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1_generator.h"
#include "secp256k1_surjectionproof.h"

#define MAXN SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS

static secp256k1_context *ctx;

static void put_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* A cheap deterministic byte expander so the vector set is reproducible. */
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

/* Distinct-but-deterministic asset tags. */
static void make_tag(secp256k1_fixed_asset_tag *t, size_t i) {
    memset(t->data, 0, 32);
    t->data[0] = (unsigned char)i;
    t->data[1] = (unsigned char)(i >> 8);
    t->data[2] = 0x5a;
}

/* ------------------------------------------------------------------ */
/* initialize                                                          */
/* ------------------------------------------------------------------ */

static int init_first = 1;

/* `dup_mod`: 0 means all tags distinct, otherwise tag[i] repeats every
 * `dup_mod` entries so several inputs can carry the output's asset. */
static void emit_initialize(size_t n, size_t n_used, size_t match, size_t max_it,
                            uint64_t seedno, size_t dup_mod) {
    static secp256k1_fixed_asset_tag tags[MAXN];
    secp256k1_surjectionproof p;
    unsigned char seed[32];
    size_t idx = 0, i;
    int r;

    for (i = 0; i < n; i++) make_tag(&tags[i], dup_mod ? i % dup_mod : i);
    fill(seed, 32, 0x1234567 + seedno);
    r = secp256k1_surjectionproof_initialize(ctx, &p, &idx, tags, n, n_used,
                                             &tags[match], max_it, seed);

    if (!init_first) printf(",\n");
    init_first = 0;
    printf("    { \"seed\": \"");
    put_hex(seed, 32);
    printf("\", \"n_used\": %zu, \"max_iterations\": %zu, \"output_tag\": \"", n_used, max_it);
    put_hex(tags[match].data, 32);
    printf("\", \"input_tags\": [");
    for (i = 0; i < n; i++) {
        printf("%s\"", i ? ", " : "");
        put_hex(tags[i].data, 32);
        printf("\"");
    }
    printf("], \"ok\": %d, \"input_index\": %zu, \"used\": [", r ? 1 : 0, r ? idx : 0);
    if (r) {
        unsigned char out[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
        size_t olen = sizeof(out), first = 1;
        secp256k1_surjectionproof_serialize(ctx, out, &olen, &p);
        for (i = 0; i < n; i++) {
            if (out[2 + i / 8] & (1 << (i % 8))) {
                printf("%s%zu", first ? "" : ", ", i);
                first = 0;
            }
        }
    }
    printf("] }");
}

/* ------------------------------------------------------------------ */
/* proofs                                                              */
/* ------------------------------------------------------------------ */

static int proof_first = 1;

static void emit_proof(size_t n, size_t n_used, size_t match, uint64_t seedno) {
    static secp256k1_fixed_asset_tag tags[MAXN];
    static secp256k1_generator gens[MAXN];
    static unsigned char blinds[MAXN][32];
    unsigned char obl[32], seed[32], out[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
    secp256k1_generator ogen;
    secp256k1_surjectionproof p;
    size_t idx = 0, olen = sizeof(out), i;

    for (i = 0; i < n; i++) {
        make_tag(&tags[i], i);
        fill(blinds[i], 32, 0xabcdef01 + seedno * 1000 + i);
        blinds[i][0] &= 0x7f;
        if (!secp256k1_generator_generate_blinded(ctx, &gens[i], tags[i].data, blinds[i])) exit(2);
    }
    fill(obl, 32, 0x55aa00ff + seedno);
    obl[0] &= 0x7f;
    if (!secp256k1_generator_generate_blinded(ctx, &ogen, tags[match].data, obl)) exit(3);
    fill(seed, 32, 0x99887766 + seedno);

    if (!secp256k1_surjectionproof_initialize(ctx, &p, &idx, tags, n, n_used,
                                              &tags[match], 100000, seed)) exit(4);
    if (!secp256k1_surjectionproof_generate(ctx, &p, gens, n, &ogen, idx,
                                            blinds[idx], obl)) exit(5);
    if (!secp256k1_surjectionproof_serialize(ctx, out, &olen, &p)) exit(6);
    if (!secp256k1_surjectionproof_verify(ctx, &p, gens, n, &ogen)) exit(7);

    if (!proof_first) printf(",\n");
    proof_first = 0;
    printf("    { \"n_inputs\": %zu, \"n_used\": %zu, \"input_index\": %zu,\n", n, n_used, idx);
    printf("      \"input_generators\": [");
    for (i = 0; i < n; i++) {
        unsigned char g[33];
        secp256k1_generator_serialize(ctx, g, &gens[i]);
        printf("%s\"", i ? ", " : "");
        put_hex(g, 33);
        printf("\"");
    }
    printf("],\n      \"output_generator\": \"");
    {
        unsigned char g[33];
        secp256k1_generator_serialize(ctx, g, &ogen);
        put_hex(g, 33);
    }
    printf("\", \"input_blind\": \"");
    put_hex(blinds[idx], 32);
    printf("\", \"output_blind\": \"");
    put_hex(obl, 32);
    printf("\",\n      \"proof\": \"");
    put_hex(out, olen);
    printf("\" }");
}

/* ------------------------------------------------------------------ */
/* encodings the oracle's parser accepts / rejects                     */
/* ------------------------------------------------------------------ */

static int valid_first = 1, invalid_first = 1;

static void classify(const char *label, const unsigned char *buf, size_t len) {
    secp256k1_surjectionproof p;
    if (secp256k1_surjectionproof_parse(ctx, &p, buf, len)) {
        if (!valid_first) printf(",\n");
        valid_first = 0;
        printf("    { \"note\": \"%s\", \"n_inputs\": %zu, \"n_used\": %zu, \"proof\": \"",
               label, secp256k1_surjectionproof_n_total_inputs(ctx, &p),
               secp256k1_surjectionproof_n_used_inputs(ctx, &p));
        put_hex(buf, len);
        printf("\" }");
    } else {
        if (!invalid_first) printf(",\n");
        invalid_first = 0;
        printf("    { \"note\": \"%s\", \"proof\": \"", label);
        put_hex(buf, len);
        printf("\" }");
    }
}

/* ------------------------------------------------------------------ */
/* purecrypto proofs, verified with the oracle                         */
/* ------------------------------------------------------------------ */

static int read_hex(const char *s, unsigned char *out, size_t max, size_t *len) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > max) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    *len = n / 2;
    return 1;
}

static void emit_purecrypto(const char *path) {
    FILE *f = fopen(path, "r");
    static char line[1 << 20];
    int first = 1;
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(8); }
    while (fgets(line, sizeof(line), f)) {
        static secp256k1_generator gens[MAXN];
        unsigned char buf[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
        unsigned char gb[33], ib[32], ob[32];
        secp256k1_generator ogen;
        secp256k1_surjectionproof p;
        size_t len, n = 0, idx;
        char *tok = strtok(line, " \t\n");
        if (!tok) continue;
        idx = (size_t)atol(tok);
        tok = strtok(NULL, " \t\n");
        if (!read_hex(tok, gb, 33, &len) || len != 33) exit(9);
        if (!secp256k1_generator_parse(ctx, &ogen, gb)) exit(10);
        tok = strtok(NULL, " \t\n");
        if (!read_hex(tok, ib, 32, &len) || len != 32) exit(11);
        tok = strtok(NULL, " \t\n");
        if (!read_hex(tok, ob, 32, &len) || len != 32) exit(12);
        tok = strtok(NULL, " \t\n");
        if (!read_hex(tok, buf, sizeof(buf), &len)) exit(13);
        {
            size_t plen = len;
            char *g;
            unsigned char gbuf[33];
            size_t glen;
            while ((g = strtok(NULL, " \t\n")) != NULL) {
                if (!read_hex(g, gbuf, 33, &glen) || glen != 33) exit(14);
                if (!secp256k1_generator_parse(ctx, &gens[n], gbuf)) exit(15);
                n++;
            }
            if (!secp256k1_surjectionproof_parse(ctx, &p, buf, plen)) {
                fprintf(stderr, "oracle rejected a purecrypto proof (parse)\n");
                exit(16);
            }
            if (!secp256k1_surjectionproof_verify(ctx, &p, gens, n, &ogen)) {
                fprintf(stderr, "oracle rejected a purecrypto proof (verify)\n");
                exit(17);
            }
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"n_inputs\": %zu, \"n_used\": %zu, \"input_index\": %zu,\n",
                   n, secp256k1_surjectionproof_n_used_inputs(ctx, &p), idx);
            printf("      \"input_generators\": [");
            for (size_t i = 0; i < n; i++) {
                unsigned char s[33];
                secp256k1_generator_serialize(ctx, s, &gens[i]);
                printf("%s\"", i ? ", " : "");
                put_hex(s, 33);
                printf("\"");
            }
            printf("],\n      \"output_generator\": \"");
            put_hex(gb, 33);
            printf("\", \"input_blind\": \"");
            put_hex(ib, 32);
            printf("\", \"output_blind\": \"");
            put_hex(ob, 32);
            printf("\",\n      \"proof\": \"");
            put_hex(buf, plen);
            printf("\" }");
        }
    }
    fclose(f);
    if (!first) printf("\n");
}

int main(int argc, char **argv) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    printf("{\n");
    printf("  \"_comment\": \"secp256k1-zkp surjection-proof interop vectors; see tools/zkp-interop/README.md\",\n");

    /* --- initialize: input selection ------------------------------- */
    printf("  \"initialize\": [\n");
    {
        /* distinct tags: exactly one input carries the output's asset */
        emit_initialize(1, 1, 0, 100, 1, 0);
        emit_initialize(2, 1, 1, 1000, 2, 0);
        emit_initialize(2, 2, 0, 100, 3, 0);
        emit_initialize(3, 2, 2, 1000, 4, 0);
        emit_initialize(3, 3, 1, 10, 5, 0);
        emit_initialize(5, 3, 4, 1000, 6, 0);
        emit_initialize(8, 1, 5, 10000, 7, 0);
        emit_initialize(8, 3, 0, 1000, 8, 0);
        emit_initialize(8, 3, 7, 1000, 9, 0);
        emit_initialize(16, 3, 8, 1000, 10, 0);
        emit_initialize(16, 16, 3, 1000, 11, 0);
        emit_initialize(17, 3, 16, 10000, 12, 0);   /* n not a power of two */
        emit_initialize(31, 4, 30, 10000, 13, 0);
        emit_initialize(100, 3, 99, 100000, 14, 0); /* modulo-bias rejection */
        emit_initialize(200, 2, 25, 100000, 15, 0);
        emit_initialize(256, 3, 128, 100000, 17, 0);
        /* max_iterations too small to find the match: expect ok = 0 */
        emit_initialize(8, 1, 5, 1, 18, 0);
        emit_initialize(16, 1, 9, 2, 19, 0);
        emit_initialize(100, 1, 50, 3, 20, 0);
        /* max_iterations = 0 still makes one attempt */
        emit_initialize(4, 2, 0, 0, 21, 0);
        emit_initialize(4, 2, 3, 0, 22, 0);
        /* duplicate tags: several inputs match, last drawn wins */
        emit_initialize(8, 3, 0, 1000, 23, 1);
        emit_initialize(16, 4, 2, 1000, 24, 3);
        emit_initialize(32, 5, 1, 1000, 25, 4);
        emit_initialize(64, 6, 5, 10000, 26, 7);
    }
    printf("\n  ],\n");

    /* --- proofs the oracle produced -------------------------------- */
    printf("  \"proofs\": [\n");
    {
        emit_proof(1, 1, 0, 1);
        emit_proof(2, 1, 0, 2);
        emit_proof(2, 2, 1, 3);
        emit_proof(3, 2, 0, 4);
        emit_proof(3, 3, 1, 5);
        emit_proof(3, 3, 2, 6);
        emit_proof(8, 3, 0, 7);
        emit_proof(8, 3, 4, 8);
        emit_proof(8, 3, 7, 9);
        emit_proof(16, 1, 15, 10);
        emit_proof(16, 16, 8, 11);
        emit_proof(256, 3, 200, 12);
    }
    printf("\n  ],\n");

    /* --- proofs this crate produced, accepted by the oracle --------- */
    printf("  \"purecrypto_proofs\": [\n");
    if (argc > 1) emit_purecrypto(argv[1]);
    printf("  ],\n");

    /* --- encodings the parser accepts or rejects -------------------- */
    {
        unsigned char buf[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX + 64];
        size_t len;
        /* Collect both classes in one pass, printing into two sections; the
         * sections are emitted one after the other, so run the classification
         * twice -- once per section -- with the other one suppressed. */
        for (int pass = 0; pass < 2; pass++) {
            if (pass == 0) printf("  \"valid_encodings\": [\n");
            else printf("  \"invalid_proofs\": [\n");
            /* Emit only the class this pass wants: the same case list runs
             * twice, and each case prints only if its parse result matches
             * the pass. */
            valid_first = 1;
            invalid_first = 1;
#define CLASSIFY(label, b, l)                                                  \
    do {                                                                       \
        secp256k1_surjectionproof _p;                                          \
        int _ok = secp256k1_surjectionproof_parse(ctx, &_p, (b), (l));         \
        if ((pass == 0) == (_ok != 0)) classify((label), (b), (l));            \
    } while (0)

            memset(buf, 0x11, sizeof(buf));
            buf[0] = 4; buf[1] = 0; buf[2] = 0x03;
            len = 3 + 32 * 3;
            CLASSIFY("n=4 used=2", buf, len);
            CLASSIFY("one byte short", buf, len - 1);
            CLASSIFY("one byte long", buf, len + 1);
            CLASSIFY("empty", buf, 0);
            CLASSIFY("one byte", buf, 1);
            CLASSIFY("two bytes", buf, 2);
            CLASSIFY("header only", buf, 3);
            buf[2] = 0x83;
            CLASSIFY("bitmap bit >= n_inputs", buf, 3 + 32 * 4);
            buf[2] = 0x13;
            CLASSIFY("bitmap bit >= n_inputs (bit 4)", buf, 3 + 32 * 4);
            buf[2] = 0x03;
            CLASSIFY("length claims one s too few", buf, 3 + 32 * 2);
            CLASSIFY("length claims one s too many", buf, 3 + 32 * 4);
            buf[0] = 0; buf[1] = 0;
            CLASSIFY("n_inputs=0, e0 only", buf, 34);
            CLASSIFY("n_inputs=0, trailing byte", buf, 35);
            buf[0] = 8; buf[1] = 0; buf[2] = 0x00;
            CLASSIFY("n_inputs=8, empty bitmap", buf, 3 + 32);
            buf[2] = 0x81;
            CLASSIFY("n_inputs=8, bits 0 and 7", buf, 3 + 32 * 3);
            buf[0] = 1; buf[1] = 1;
            CLASSIFY("n_inputs=257", buf, 2 + 33 + 32 * 2);
            buf[0] = 0xff; buf[1] = 0xff;
            CLASSIFY("n_inputs=65535", buf, 200);
            buf[0] = 0; buf[1] = 1;
            memset(buf + 2, 0xff, 32);
            CLASSIFY("n_inputs=256, all used", buf, 2 + 32 + 32 * 257);
            memset(buf + 2, 0x00, 32);
            buf[2] = 0x01;
            CLASSIFY("n_inputs=256, one used", buf, 2 + 32 + 32 * 2);
            buf[0] = 4; buf[1] = 0; buf[2] = 0x03;
            memset(buf + 3, 0xff, 32 * 3);
            CLASSIFY("scalars all 0xff", buf, 3 + 32 * 3);
            memset(buf + 3, 0x00, 32 * 3);
            CLASSIFY("scalars all zero", buf, 3 + 32 * 3);
#undef CLASSIFY
            printf("\n  ]%s\n", pass == 0 ? "," : "");
        }
    }
    printf("}\n");
    return 0;
}
