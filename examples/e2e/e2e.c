#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "battery.h"
#include "battery_helpers.h"

typedef struct {
    size_t rss_kb; // current resident set size (kB)
    size_t hwm_kb; // high-water mark (kB)
} memsnap_t;

static int g_mem_available = -1;

static void mem_init(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (f) { fclose(f); g_mem_available = 1; }
    else { g_mem_available = 0; }
}

static void read_memsnap(memsnap_t* s) {
    s->rss_kb = 0;
    s->hwm_kb = 0;
    if (g_mem_available != 1) return;
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) { g_mem_available = 0; return; }
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (!s->rss_kb && strncmp(line, "VmRSS:", 6) == 0) {
            unsigned long v = 0; // kB
            if (sscanf(line + 6, "%*[^0-9]%lu", &v) == 1) s->rss_kb = (size_t)v;
        } else if (!s->hwm_kb && strncmp(line, "VmHWM:", 6) == 0) {
            unsigned long v = 0; // kB
            if (sscanf(line + 6, "%*[^0-9]%lu", &v) == 1) s->hwm_kb = (size_t)v;
        }
    }
    fclose(f);
}

static void print_end_stats(const char* op, const memsnap_t* before) {
    if (g_mem_available != 1) {
        printf("[mem] not available on this device\n");
        return;
    }
    memsnap_t after; read_memsnap(&after);
    long used_kb = (long)after.hwm_kb - (long)before->rss_kb;
    if (used_kb < 0) used_kb = 0;
    printf("[mem] op=%s used=%ld kB, rss_after=%zu kB, peak_total=%zu kB\n",
           op, used_kb, after.rss_kb, after.hwm_kb);
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "both"; // modes: "zkp", "tfhe", "both"
    // ZKP: device knows both leaves; server supplies parent→root path.
    // rows = levels(parent→root) + 2 must be a power of two.
    // For a depth-32 demo: parent→root levels = 30 -> rows = 32.
    enum { LEVELS = 30 }; // parent→root
    uint32_t secret16_u32[16]; // [leaf(8) | sibling(8)]
    uint32_t neighbors8_by_level_u32[LEVELS * 8];
    uint8_t sides[LEVELS];
    for (int i = 0; i < 8; i++) secret16_u32[i] = 4;      // device leaf
    for (int i = 0; i < 8; i++) secret16_u32[8 + i] = 3;  // sibling
    for (size_t l = 0; l < LEVELS; l++) {
        for (int j = 0; j < 8; j++) neighbors8_by_level_u32[l*8 + j] = 3; // demo neighbors
        sides[l] = 0; // 0 = right, non-zero = left; require sides[0] == 0
    }
    uint8_t zkp_nonce[BATTERY_NONCE_LEN];
    memset(zkp_nonce, 0x11, sizeof zkp_nonce);
    mem_init();
    memsnap_t m0; read_memsnap(&m0);
    printf("[info] Packing ZKP args...\n");
    unsigned char args_buf[1<<16];
    size_t args_len = 0;
    int rc = zkp_pack_args(neighbors8_by_level_u32,
                           sides,
                           LEVELS,
                           args_buf,
                           sizeof args_buf,
                           &args_len);
    if (rc != BATTERY_OK) {
        fprintf(stderr, "zkp_pack_args failed: %s (%d)\n", battery_strerror(rc), rc);
        return 1;
    }
    if (strcmp(mode, "zkp") == 0 || strcmp(mode, "both") == 0) {
        printf("[info] Generating ZKP proof...\n");
        // Baseline before the heavy operation
        memsnap_t base; read_memsnap(&base);
        unsigned char proof_buf[1<<19]; // 0.5 MiB demo buffer
        size_t proof_written = 0;
        // zkp_generate_proof returns a postcard-serialized bundle: (proof, public_values)
        rc = zkp_generate_proof(secret16_u32,
                                args_buf,
                                args_len,
                                zkp_nonce,
                                proof_buf,
                                sizeof proof_buf,
                                &proof_written);
        if (rc != BATTERY_OK) {
            fprintf(stderr, "zkp_generate_proof failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }
        printf("[info] ZKP proof length: %zu bytes\n", proof_written);
        print_end_stats("zkp_generate_proof", &base);
        if (strcmp(mode, "zkp") == 0) return 0;
    }

    // TFHE: encrypt demo bytes under a TFHE public key
    printf("[info] TFHE params: TRLWE_N=%u\n", (unsigned)TFHE_TRLWE_N);
    enum { DEMO_LEN = 16 };
    uint8_t demo_bytes[DEMO_LEN];
    for (int i = 0; i < DEMO_LEN; i++) demo_bytes[i] = (uint8_t)i;
    printf("[info] Demo bytes[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x", demo_bytes[i]);
    printf("\n");

    // Demo public key arrays. Replace with a real PK.
    uint64_t pk_a[TFHE_TRLWE_N];
    uint64_t pk_b[TFHE_TRLWE_N];
    for (uint32_t i = 0; i < TFHE_TRLWE_N; i++) { pk_a[i] = 1ULL; pk_b[i] = 1ULL; }
    printf("[info] PK a[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)pk_a[i]);
    printf("\n[info] PK b[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)pk_b[i]);
    printf("\n");

    if (strcmp(mode, "tfhe") == 0 || strcmp(mode, "both") == 0) {
        // Pack the public key into an opaque buffer
        printf("[info] Packing TFHE PK...\n");
        unsigned char pk_buf[1<<18];
        size_t pk_len = 0;
        rc = tfhe_pack_public_key(pk_a, pk_b, pk_buf, sizeof pk_buf, &pk_len);
        if (rc != BATTERY_OK) {
            fprintf(stderr, "tfhe_pack_public_key failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }

        // Output ciphertext and fixed RNG seed
        unsigned char ct_buf[1<<19];
        size_t ct_written = 0;
        uint8_t seed[BATTERY_SEED_LEN];
        memset(seed, 42, sizeof(seed));
        printf("[info] Seed (first 8 bytes): ");
        for (int i = 0; i < 8; i++) printf("%02x", seed[i]);
        printf("..\n");

        // Baseline before TFHE encrypt
        memsnap_t base; read_memsnap(&base);
        printf("[info] Encrypting demo bytes (tfhe_pk_encrypt)...\n");
        rc = tfhe_pk_encrypt(pk_buf, pk_len, demo_bytes, DEMO_LEN, seed, BATTERY_SEED_LEN,
                                     ct_buf, sizeof ct_buf, &ct_written);
        if (rc != BATTERY_OK) {
            fprintf(stderr, "tfhe_pk_encrypt failed: %s (%d)\n", battery_strerror(rc), rc);
            return 1;
        }
        printf("[info] CT (postcard) length: %zu bytes\n", ct_written);
        print_end_stats("tfhe_pk_encrypt", &base);
        if (strcmp(mode, "tfhe") == 0) return 0;
    }

    return 0;
}
