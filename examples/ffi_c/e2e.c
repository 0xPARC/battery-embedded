#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "battery.h"
#include "battery_helpers.h"

int main(void) {
    // ZKP: generate public values (e.g., Merkle root)  and zk proof for a provided leaf & path
    // Use a compile-time constant to avoid VLA warnings
    enum { LEVELS = 32 }; // demo depth
    uint32_t leaf8_u32[8];
    uint32_t neighbors8_by_level_u32[LEVELS * 8];
    uint8_t sides[LEVELS];
    for (int i = 0; i < 8; i++) leaf8_u32[i] = 4; // demo leaf values
    for (size_t l = 0; l < LEVELS; l++) {
        for (int j = 0; j < 8; j++) neighbors8_by_level_u32[l*8 + j] = 3; // demo neighbors
        sides[l] = 0; // 0 = right, non-zero = left; require sides[0] == 0
    }
    uint8_t zkp_nonce[TFHE_SEED_LEN];
    memset(zkp_nonce, 0x11, sizeof zkp_nonce);
    uint32_t root_out[HASH_SIZE];
    printf("[info] Generating ZKP proof + public values...\n");
    unsigned char proof_buf[1<<19]; // 0.5 MiB demo buffer
    size_t proof_written = 0;
    int rc = zkp_generate_proof(leaf8_u32,
                            neighbors8_by_level_u32,
                            sides,
                            LEVELS,
                            zkp_nonce,
                            root_out,
                            proof_buf,
                            sizeof proof_buf,
                            &proof_written);
    if (rc != TFHE_OK) {
        fprintf(stderr, "zkp_generate_proof failed: %s (%d)\n", battery_strerror(rc), rc);
        return 1;
    }
    printf("[info] ZKP public root[0..7]: ");
    for (int i = 0; i < HASH_SIZE; i++) printf("%08x ", root_out[i]);
    printf("\n[info] ZKP proof length: %zu bytes\n", proof_written);

    // TFHE: encrypt an AES-128 key under a TFHE public key
    printf("[info] TFHE params: TRLWE_N=%u\n", (unsigned)TFHE_TRLWE_N);
    const uint8_t aes_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    printf("[info] AES-128 key: ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_key[i]);
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

    // Output ciphertext and fixed RNG seed
    uint64_t a_out[TFHE_TRLWE_N];
    uint64_t b_out[TFHE_TRLWE_N];
    uint8_t seed[32];
    memset(seed, 42, sizeof(seed));
    printf("[info] Seed (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02x", seed[i]);
    printf("..\n");

    // Encrypt the AES-128 key directly using TFHE public key
    printf("[info] Encrypting AES key with TFHE PK...\n");
    rc = tfhe_pk_encrypt_aes_key(a_out, b_out, pk_a, pk_b, aes_key, seed, TFHE_SEED_LEN);
    if (rc != TFHE_OK) {
        fprintf(stderr, "tfhe_pk_encrypt_aes_key failed: %s (%d)\n", battery_strerror(rc), rc);
        return 1;
    }
    printf("[info] ct.a[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)a_out[i]);
    printf("\n[info] ct.b[0..7]: ");
    for (int i = 0; i < 8 && i < (int)TFHE_TRLWE_N; i++) printf("%llu ", (unsigned long long)b_out[i]);
    printf("\n");

    // E2E: encrypt some demo data under AES-128-CTR using the plaintext AES key
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)i; // demo data 0..63
    uint8_t iv[16];
    memset(iv, 0x23, sizeof iv); // demo IV (non-random) — replace in production
    printf("[info] AES-CTR IV: ");
    for (int i = 0; i < 16; i++) printf("%02x", iv[i]);
    printf("\n[info] AES-CTR plaintext[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x", data[i]);
    printf("\n[info] Encrypting with AES-CTR...\n");
    if (aes_ctr_encrypt(data, sizeof(data), aes_key, TFHE_AES_KEY_LEN, iv, TFHE_AES_IV_LEN) != TFHE_OK) {
        fprintf(stderr, "aes_ctr_encrypt failed\n");
        return 1;
    }
    printf("[info] AES-CTR ciphertext[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x", data[i]);
    printf("\n");

    return 0;
}
