/* Generates tools/zkp-interop/vectors/rangeproof.json from the secp256k1-zkp
 * black-box oracle.
 *
 * This file is a developer-only harness. It is never compiled into the crate
 * and never linked by `cargo test`; the crate's tests read the committed JSON.
 *
 * Build (see README.md for the oracle build):
 *   cc gen-rangeproof-vectors.c -I <oracle>/include <oracle>/.libs/libsecp256k1.a \
 *      -o gen-rangeproof-vectors
 *   ./gen-rangeproof-vectors > vectors/rangeproof.json
 *
 * Only the public headers secp256k1.h, secp256k1_generator.h and
 * secp256k1_rangeproof.h are used. No implementation source is consulted.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>

static secp256k1_context *ctx;
static void nocb(const char *m, void *d) { (void)m; (void)d; }

static void ph(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

/* A tiny deterministic byte stream so the vectors are reproducible. */
static uint64_t rng_state = 0x243F6A8885A308D3ULL;
static unsigned char rnd_byte(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (unsigned char)(rng_state >> 24);
}
static void rnd(unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) p[i] = rnd_byte();
}

struct testcase {
    uint64_t value;
    uint64_t min_value;
    int exp;
    int min_bits;
    int use_asset;   /* 0: generator H, 1: a per-asset generator */
    int zero_blind;  /* exercise the all-zero blinding factor the header allows */
    size_t msg_len;
    size_t extra_len;
};

static const struct testcase cases[] = {
    /* value, min_value, exp, min_bits, asset, zero_blind, msg, extra */
    { 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 0, 0, 0, 0, 0, 0, 0 },
    { 5, 0, 0, 0, 0, 0, 0, 0 },
    { 255, 0, 0, 0, 0, 0, 0, 0 },
    { 256, 0, 0, 0, 0, 0, 0, 0 },
    { 1000, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 1, 0, 0, 0, 0 },
    { 1, 0, 0, 1, 0, 0, 0, 0 },
    { 3, 0, 0, 2, 0, 0, 0, 0 },
    { 3, 0, 0, 3, 0, 0, 0, 0 },
    { 3, 0, 0, 4, 0, 0, 0, 0 },
    { 3, 0, 0, 5, 0, 0, 0, 0 },
    { 3, 0, 0, 6, 0, 0, 0, 0 },
    { 7, 0, 0, 8, 0, 0, 0, 0 },
    { 42, 0, 0, 16, 0, 0, 0, 0 },
    { 42, 0, 0, 32, 0, 0, 0, 0 },
    { 5, 0, 0, 64, 0, 0, 0, 0 },
    { 0, 0, 0, 64, 0, 0, 0, 0 },
    { 18446744073709551615ULL, 0, 0, 0, 0, 0, 0, 0 },
    { 9223372036854775807ULL, 0, 0, 0, 0, 0, 0, 0 },
    { 1000, 0, 1, 0, 0, 0, 0, 0 },
    { 1000, 0, 2, 0, 0, 0, 0, 0 },
    { 1000, 0, 3, 0, 0, 0, 0, 0 },
    { 1234, 0, 1, 0, 0, 0, 0, 0 },
    { 1234, 0, 2, 0, 0, 0, 0, 0 },
    { 1000000000, 0, 6, 0, 0, 0, 0, 0 },
    { 1000, 0, -1, 0, 0, 0, 0, 0 },
    { 0, 0, -1, 0, 0, 0, 0, 0 },
    { 18446744073709551615ULL, 0, -1, 0, 0, 0, 0, 0 },
    { 1000, 500, 0, 0, 0, 0, 0, 0 },
    { 1000, 1000, 0, 0, 0, 0, 0, 0 },
    { 7, 7, 0, 0, 0, 0, 0, 0 },
    { 1000, 500, 1, 0, 0, 0, 0, 0 },
    { 1234, 500, 2, 0, 0, 0, 0, 0 },
    { 5, 5, 0, 8, 0, 0, 0, 0 },
    { 4294967295ULL, 1, 0, 0, 0, 0, 0, 0 },
    /* extra_commit */
    { 7, 0, 0, 4, 0, 0, 0, 12 },
    { 1000, 500, 1, 0, 0, 0, 0, 32 },
    { 0, 0, 0, 1, 0, 0, 0, 1 },
    { 999, 0, 0, 0, 0, 0, 0, 71 },
    /* embedded messages */
    { 0, 0, 0, 4, 0, 0, 10, 0 },
    { 5, 0, 0, 8, 0, 0, 32, 0 },
    { 5, 0, 0, 8, 0, 0, 100, 0 },
    { 5, 0, 0, 8, 0, 0, 384, 0 },
    { 42, 0, 0, 32, 0, 0, 512, 0 },
    { 42, 0, 0, 64, 0, 0, 3968, 0 },
    { 123, 12, 1, 16, 0, 0, 64, 17 },
    /* per-asset generators */
    { 0, 0, 0, 0, 1, 0, 0, 0 },
    { 5, 0, 0, 0, 1, 0, 0, 0 },
    { 1000, 0, 2, 0, 1, 0, 0, 0 },
    { 1000, 500, 0, 0, 1, 0, 0, 0 },
    { 4242, 0, 0, 32, 1, 0, 128, 24 },
    { 18446744073709551615ULL, 0, 0, 0, 1, 0, 0, 0 },
    /* the all-zero blinding factor the header documents (needs min_bits >= 3) */
    { 1, 0, 0, 3, 0, 1, 0, 0 },
    { 7, 0, 0, 8, 0, 1, 0, 0 },
    { 1000, 0, 1, 16, 0, 1, 32, 8 },
};

int main(void) {
    unsigned char blind[32], nonce[32], msg[4096], extra[128], tag[32];
    unsigned char proof[5200], cser[33], gser[33];
    size_t i;
    int first;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context_set_illegal_callback(ctx, nocb, NULL);

    printf("{\n");
    printf("  \"proofs\": [\n");
    first = 1;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct testcase *tc = &cases[i];
        secp256k1_generator gen;
        secp256k1_pedersen_commitment commit;
        size_t plen = sizeof(proof);
        int oe, om, rv, rw;
        uint64_t on, ox, vmin, vmax, rvalue;
        unsigned char rblind[32], rmsg[4096];
        size_t rlen = sizeof(rmsg);

        rnd(blind, 32);
        rnd(nonce, 32);
        rnd(msg, tc->msg_len);
        rnd(extra, tc->extra_len);
        rnd(tag, 32);
        if (tc->zero_blind) memset(blind, 0, 32);

        if (tc->use_asset) {
            if (!secp256k1_generator_generate(ctx, &gen, tag)) continue;
        } else {
            memcpy(&gen, secp256k1_generator_h, sizeof(gen));
        }
        if (!secp256k1_pedersen_commit(ctx, &commit, blind, tc->value, &gen)) continue;
        if (!secp256k1_rangeproof_sign(ctx, proof, &plen, tc->min_value, &commit,
                                       blind, nonce, tc->exp, tc->min_bits, tc->value,
                                       tc->msg_len ? msg : NULL, tc->msg_len,
                                       tc->extra_len ? extra : NULL, tc->extra_len, &gen)) {
            fprintf(stderr, "case %zu: sign failed\n", i);
            continue;
        }
        if (!secp256k1_rangeproof_info(ctx, &oe, &om, &on, &ox, proof, plen)) continue;
        rv = secp256k1_rangeproof_verify(ctx, &vmin, &vmax, &commit, proof, plen,
                                         tc->extra_len ? extra : NULL, tc->extra_len, &gen);
        if (!rv) { fprintf(stderr, "case %zu: verify failed\n", i); continue; }
        memset(rmsg, 0, sizeof(rmsg));
        rw = secp256k1_rangeproof_rewind(ctx, rblind, &rvalue, rmsg, &rlen, nonce,
                                         &vmin, &vmax, &commit, proof, plen,
                                         tc->extra_len ? extra : NULL, tc->extra_len, &gen);
        if (!rw) { fprintf(stderr, "case %zu: rewind failed\n", i); continue; }
        secp256k1_pedersen_commitment_serialize(ctx, cser, &commit);
        secp256k1_generator_serialize(ctx, gser, &gen);

        if (!first) printf(",\n");
        first = 0;
        printf("    {\n");
        printf("      \"value\": %llu, \"min_value\": %llu, \"exp\": %d, \"min_bits\": %d,\n",
               (unsigned long long)tc->value, (unsigned long long)tc->min_value, tc->exp, tc->min_bits);
        printf("      \"blind\": \""); ph(blind, 32); printf("\",\n");
        printf("      \"nonce\": \""); ph(nonce, 32); printf("\",\n");
        printf("      \"generator\": \""); ph(gser, 33); printf("\",\n");
        printf("      \"commitment\": \""); ph(cser, 33); printf("\",\n");
        printf("      \"message\": \""); ph(msg, tc->msg_len); printf("\",\n");
        printf("      \"extra_commit\": \""); ph(extra, tc->extra_len); printf("\",\n");
        printf("      \"info_exp\": %d, \"info_mantissa\": %d,\n", oe, om);
        printf("      \"min\": %llu, \"max\": %llu,\n",
               (unsigned long long)on, (unsigned long long)ox);
        printf("      \"rewind_value\": %llu,\n", (unsigned long long)rvalue);
        printf("      \"rewind_blind\": \""); ph(rblind, 32); printf("\",\n");
        printf("      \"rewind_outlen\": %zu,\n", rlen);
        printf("      \"rewind_message\": \""); ph(rmsg, rlen); printf("\",\n");
        printf("      \"proof\": \""); ph(proof, plen); printf("\"\n");
        printf("    }");
    }
    printf("\n  ],\n");

    /* Proofs the oracle rejects: truncations and single-byte mutations of a
     * valid proof, plus a valid proof checked against the wrong commitment. */
    printf("  \"rejects\": [\n");
    first = 1;
    {
        secp256k1_generator gen;
        secp256k1_pedersen_commitment commit, other;
        size_t plen = sizeof(proof);
        unsigned char oser[33];
        size_t cut, k;
        memcpy(&gen, secp256k1_generator_h, sizeof(gen));
        rnd(blind, 32);
        rnd(nonce, 32);
        if (!secp256k1_pedersen_commit(ctx, &commit, blind, 4242, &gen)) return 1;
        if (!secp256k1_rangeproof_sign(ctx, proof, &plen, 0, &commit, blind, nonce,
                                       0, 16, 4242, NULL, 0, NULL, 0, &gen)) return 1;
        secp256k1_pedersen_commitment_serialize(ctx, cser, &commit);
        secp256k1_generator_serialize(ctx, gser, &gen);
        rnd(blind, 32);
        if (!secp256k1_pedersen_commit(ctx, &other, blind, 4242, &gen)) return 1;
        secp256k1_pedersen_commitment_serialize(ctx, oser, &other);

        for (cut = 0; cut < plen; cut++) {
            uint64_t a, b;
            if (secp256k1_rangeproof_verify(ctx, &a, &b, &commit, proof, cut, NULL, 0, &gen)) {
                fprintf(stderr, "truncation %zu verified?!\n", cut);
                continue;
            }
            if (cut % 149 && cut < plen - 3) continue;  /* keep the file small */
            if (!first) printf(",\n");
            first = 0;
            printf("    { \"why\": \"truncated\", \"commitment\": \"");
            ph(cser, 33);
            printf("\", \"generator\": \"");
            ph(gser, 33);
            printf("\", \"proof\": \"");
            ph(proof, cut);
            printf("\" }");
        }
        for (k = 0; k < plen; k += 211) {
            uint64_t a, b;
            unsigned char save = proof[k];
            proof[k] ^= 0x40;
            if (!secp256k1_rangeproof_verify(ctx, &a, &b, &commit, proof, plen, NULL, 0, &gen)) {
                if (!first) printf(",\n");
                first = 0;
                printf("    { \"why\": \"mutated\", \"commitment\": \"");
                ph(cser, 33);
                printf("\", \"generator\": \"");
                ph(gser, 33);
                printf("\", \"proof\": \"");
                ph(proof, plen);
                printf("\" }");
            }
            proof[k] = save;
        }
        {
            uint64_t a, b;
            if (!secp256k1_rangeproof_verify(ctx, &a, &b, &other, proof, plen, NULL, 0, &gen)) {
                if (!first) printf(",\n");
                first = 0;
                printf("    { \"why\": \"wrong commitment\", \"commitment\": \"");
                ph(oser, 33);
                printf("\", \"generator\": \"");
                ph(gser, 33);
                printf("\", \"proof\": \"");
                ph(proof, plen);
                printf("\" }");
            }
        }
    }
    printf("\n  ]\n}\n");
    return 0;
}
