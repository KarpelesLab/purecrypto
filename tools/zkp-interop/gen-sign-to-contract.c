/*
 * Generates vectors/sign_to_contract.json by driving the secp256k1-zkp oracle
 * through its PUBLIC C API only. No oracle implementation source is read; the
 * only oracle files this needs are include/*.h.
 *
 *   ./build-oracle.sh
 *   cc gen-sign-to-contract.c -I oracle/include oracle/.libs/libsecp256k1.a \
 *       -o gen-sign-to-contract
 *   ./gen-sign-to-contract "$(git -C oracle rev-parse HEAD)" \
 *       > vectors/sign_to_contract.json
 *
 * The SHA-256 below is written from FIPS 180-4 and is used only to derive the
 * pseudo-random test inputs; it is not part of the crate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Compact SHA-256, written from FIPS 180-4 for this throwaway probe driver. */
#include <stdint.h>
#include <string.h>

typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha256_t;

static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(sha256_t *s, const unsigned char *p) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2; int i;
    for (i=0;i<16;i++) w[i]=((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
    for (i=16;i<64;i++){uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1;}
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for (i=0;i<64;i++){
        t1=h+(ROR(e,6)^ROR(e,11)^ROR(e,25))+((e&f)^(~e&g))+K256[i]+w[i];
        t2=(ROR(a,2)^ROR(a,13)^ROR(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha256_init(sha256_t *s){
    s->h[0]=0x6a09e667;s->h[1]=0xbb67ae85;s->h[2]=0x3c6ef372;s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f;s->h[5]=0x9b05688c;s->h[6]=0x1f83d9ab;s->h[7]=0x5be0cd19;
    s->len=0;s->n=0;}
static void sha256_update(sha256_t *s, const void *data, size_t len){
    const unsigned char *p=(const unsigned char*)data; s->len+=len;
    while(len){ size_t take=64-s->n; if(take>len)take=len;
        memcpy(s->buf+s->n,p,take); s->n+=take; p+=take; len-=take;
        if(s->n==64){sha256_block(s,s->buf); s->n=0;} } }
static void sha256_final(sha256_t *s, unsigned char out[32]){
    uint64_t bits=s->len*8; unsigned char pad[72]; size_t padlen; int i;
    pad[0]=0x80; padlen=1;
    while(((s->n+padlen)%64)!=56) pad[padlen++]=0;
    for(i=7;i>=0;i--) pad[padlen++]=(unsigned char)(bits>>(8*i));
    sha256_update(s,pad,padlen);
    for(i=0;i<8;i++){out[4*i]=(unsigned char)(s->h[i]>>24);out[4*i+1]=(unsigned char)(s->h[i]>>16);
        out[4*i+2]=(unsigned char)(s->h[i]>>8);out[4*i+3]=(unsigned char)s->h[i];} }
static void sha256_oneshot(const void *d, size_t n, unsigned char out[32]){ sha256_t s; sha256_init(&s); sha256_update(&s,d,n); sha256_final(&s,out); }

#include "secp256k1.h"
#include "secp256k1_ecdsa_s2c.h"

static secp256k1_context *ctx;

static void phex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void prand(const char *dom, unsigned int i, unsigned char out[32]) {
    unsigned char buf[64];
    size_t n = strlen(dom);
    memcpy(buf, dom, n);
    buf[n] = (unsigned char)i;
    buf[n + 1] = (unsigned char)(i >> 8);
    sha256_oneshot(buf, n + 2, out);
}

static int emit(const unsigned char *seckey, const unsigned char *msg32,
                const unsigned char *data32, const char *note, int first) {
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_s2c_opening opening;
    secp256k1_pubkey pk;
    unsigned char op33[33], sig64[64], pk33[33], hc[32];
    size_t pl = 33;

    if (!secp256k1_ec_seckey_verify(ctx, seckey)) return first;
    if (!secp256k1_ecdsa_s2c_sign(ctx, &sig, &opening, msg32, seckey, data32)) return first;
    if (!secp256k1_ecdsa_s2c_opening_serialize(ctx, op33, &opening)) return first;
    secp256k1_ecdsa_signature_serialize_compact(ctx, sig64, &sig);
    if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey)) return first;
    secp256k1_ec_pubkey_serialize(ctx, pk33, &pl, &pk, SECP256K1_EC_COMPRESSED);
    if (!secp256k1_ecdsa_verify(ctx, &sig, msg32, &pk)) { fprintf(stderr, "sig invalid\n"); exit(1); }
    if (!secp256k1_ecdsa_s2c_verify_commit(ctx, &sig, data32, &opening)) { fprintf(stderr, "commit invalid\n"); exit(1); }
    if (!secp256k1_ecdsa_anti_exfil_host_commit(ctx, hc, data32)) exit(1);

    if (!first) printf(",\n");
    printf("    {\n");
    printf("      \"note\": \"%s\",\n", note);
    printf("      \"seckey\": \""); phex(seckey, 32); printf("\",\n");
    printf("      \"pubkey33\": \""); phex(pk33, 33); printf("\",\n");
    printf("      \"msg32\": \""); phex(msg32, 32); printf("\",\n");
    printf("      \"data32\": \""); phex(data32, 32); printf("\",\n");
    printf("      \"host_commit32\": \""); phex(hc, 32); printf("\",\n");
    printf("      \"opening33\": \""); phex(op33, 33); printf("\",\n");
    printf("      \"sig64\": \""); phex(sig64, 64); printf("\"\n");
    printf("    }");
    return 0;
}

int main(int argc, char **argv) {
    /* argv[1], if given, is the oracle git revision, recorded for provenance. */
    const char *rev = argc > 1 ? argv[1] : "unknown";
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sk[32], msg[32], data[32];
    int first = 1;
    char note[64];

    printf("{\n");
    printf("  \"scheme\": \"ecdsa-sign-to-contract/secp256k1\",\n");
    printf("  \"source\": \"generated by driving Blockstream secp256k1-zkp through its public C API (secp256k1_ecdsa_s2c_sign / _opening_serialize / _verify_commit / secp256k1_ecdsa_anti_exfil_host_commit)\",\n");
    printf("  \"oracle_rev\": \"%s\",\n", rev);
    printf("  \"generator\": \"tools/zkp-interop/gen-sign-to-contract.c\",\n");
    printf("  \"encoding\": \"lowercase hex; sig64 is compact r||s (low-S); opening33 is the compressed original nonce point R1\",\n");
    printf("  \"vectors\": [\n");

    /* deterministic pseudo-random cases */
    for (unsigned int i = 0; i < 8; i++) {
        prand("s2c-sk", i, sk);
        prand("s2c-msg", i, msg);
        prand("s2c-data", i, data);
        snprintf(note, sizeof note, "pseudo-random #%u", i);
        first = emit(sk, msg, data, note, first);
    }

    /* seckey = 1 */
    memset(sk, 0, 32); sk[31] = 1;
    prand("s2c-msg", 100, msg);
    prand("s2c-data", 100, data);
    first = emit(sk, msg, data, "seckey = 1", first);

    /* all-zero data */
    prand("s2c-sk", 200, sk);
    prand("s2c-msg", 200, msg);
    memset(data, 0, 32);
    first = emit(sk, msg, data, "data32 = all zeros", first);

    /* all-zero message */
    prand("s2c-sk", 201, sk);
    memset(msg, 0, 32);
    prand("s2c-data", 201, data);
    first = emit(sk, msg, data, "msg32 = all zeros", first);

    /* message >= group order n (0xff..ff): exercises raw-msg DRBG seeding
     * together with reduction of the message scalar mod n */
    prand("s2c-sk", 202, sk);
    memset(msg, 0xff, 32);
    prand("s2c-data", 202, data);
    first = emit(sk, msg, data, "msg32 = 0xff..ff (>= n, must reduce)", first);

    /* data = all 0xff */
    prand("s2c-sk", 203, sk);
    prand("s2c-msg", 203, msg);
    memset(data, 0xff, 32);
    first = emit(sk, msg, data, "data32 = all 0xff", first);

    /* seckey = n - 1 */
    {
        static const unsigned char n_minus_1[32] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40};
        memcpy(sk, n_minus_1, 32);
        prand("s2c-msg", 204, msg);
        prand("s2c-data", 204, data);
        first = emit(sk, msg, data, "seckey = n - 1", first);
    }

    printf("\n  ]\n}\n");
    secp256k1_context_destroy(ctx);
    return 0;
}
