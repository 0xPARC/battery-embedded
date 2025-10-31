#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "battery.h"
#include "battery_helpers.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--iters N]\n", prog);
}

static uint64_t now_ns(void) {
#if defined(CLOCK_MONOTONIC)
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#else
    return 0;
#endif
}

static uint32_t lcg32(uint32_t *s) {
    *s = (*s) * 1664525u + 1013904223u; return *s;
}

int main(int argc, char **argv) {
    // Parse arguments
    int iters = 100; // default
    int warmup = 0;  // default: no warmup to match process timing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iters") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --iters requires a value\n");
                print_usage(argv[0]);
                return 2;
            }
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v <= 0 || v > INT32_MAX) {
                fprintf(stderr, "error: invalid --iters value: %s\n", argv[i]);
                return 2;
            }
            iters = (int)v;
        } else if (strncmp(argv[i], "--iters=", 8) == 0) {
            const char *val = argv[i] + 8;
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (end == val || *end != '\0' || v <= 0 || v > INT32_MAX) {
                fprintf(stderr, "error: invalid --iters value: %s\n", val);
                return 2;
            }
            iters = (int)v;
        } else if (strcmp(argv[i], "--warmup") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --warmup requires a value\n");
                print_usage(argv[0]);
                return 2;
            }
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v < 0 || v > INT32_MAX) {
                fprintf(stderr, "error: invalid --warmup value: %s\n", argv[i]);
                return 2;
            }
            warmup = (int)v;
        } else if (strncmp(argv[i], "--warmup=", 9) == 0) {
            const char *val = argv[i] + 9;
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (end == val || *end != '\0' || v < 0 || v > INT32_MAX) {
                fprintf(stderr, "error: invalid --warmup value: %s\n", val);
                return 2;
            }
            warmup = (int)v;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    printf("[bench] starting bench_u8: iters=%d\n", iters);

    // Demo PK: fill with 1s
    uint64_t pk_a[TFHE_TRLWE_N], pk_b[TFHE_TRLWE_N];
    for (uint32_t i = 0; i < TFHE_TRLWE_N; i++) { pk_a[i] = 1ull; pk_b[i] = 1ull; }
    unsigned char pk_buf[1<<18]; size_t pk_len = 0;
    int rc = tfhe_pack_public_key(pk_a, pk_b, pk_buf, sizeof pk_buf, &pk_len);
    if (rc != BATTERY_OK) { fprintf(stderr, "pk pack failed: %s\n", battery_strerror(rc)); return 1; }

    uint64_t ct_a[TFHE_TRLWE_N];
    uint64_t ct_b[TFHE_TRLWE_N];
    uint8_t seed[BATTERY_SEED_LEN];
    uint8_t msg[1];
    uint32_t s = 123456789u;

    // Warmup (optional)
    if (warmup > 0) {
        memset(seed, 7, sizeof seed);
        msg[0] = (uint8_t)lcg32(&s);
        for (int i = 0; i < warmup; i++) {
            rc = tfhe_pk_encrypt_raw(pk_buf, pk_len, msg, 1, seed, BATTERY_SEED_LEN, ct_a, ct_b);
            if (rc != BATTERY_OK) { fprintf(stderr, "encrypt failed (warmup): %s\n", battery_strerror(rc)); return 1; }
        }
    }

    uint64_t t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        msg[0] = (uint8_t)lcg32(&s);
        // per-iter seed for reproducibility
        memset(seed, (uint8_t)(i & 0xFF), sizeof seed);
        rc = tfhe_pk_encrypt_raw(pk_buf, pk_len, msg, 1, seed, BATTERY_SEED_LEN, ct_a, ct_b);
        if (rc != BATTERY_OK) { fprintf(stderr, "encrypt failed: %s\n", battery_strerror(rc)); return 1; }
    }
    uint64_t t1 = now_ns();
    double avg_us = (double)(t1 - t0) / (double)iters / 1000.0;
    printf("[bench] avg tfhe_pk_encrypt_raw(1 byte): %.2f us over %d iters\n", avg_us, iters);
    return 0;
}
