# FFI C Example: E2E — TFHE public-key encryption, AES-CTR, and ZKP proof

This example demonstrates how to use the generated C bindings to call the TFHE public-key encryption from C and how to generate a ZK proof.

## Build & Run example

- Build and run the C example locally

   $ cd examples/ffi_c
   $ make
   $ ./e2e

- Build the example for running it on the device (requires `zig`!)

   $ cd examples/ffi_c
   $ make PLATFORM=dev-musl
   $ ./e2e

## What it does

- Creates dummy public key arrays `(pk_a, pk_b)`; replace with a real key in practice.
- Calls `tfhe_pk_encrypt_aes_key` to encode a dummy 16‑byte AES‑128 key into the plaintext polynomial and encrypt it with the TFHE public key.
- Calls `aes_ctr_encrypt` to encrypt 64 bytes with that AES key and prints the first 16 bytes of ciphertext.
- Calls `zkp_generate_proof` to produce a STARK proof from a caller-provided leaf, Merkle neighbors, side flags, and nonce. Demo inputs are small, fixed arrays.

## Notes

- The RNG seeds in the demo are fixed for reproducibility; use real randomness in production.
- API returns status codes: `BATTERY_OK`, `BATTERY_ERR_NULL`, `BATTERY_ERR_BADLEN`, `BATTERY_ERR_SEEDLEN`, `BATTERY_ERR_INPUT`, `BATTERY_ERR_BUFSZ`.
- All inputs/outputs use opaque byte buffers; no special alignment requirements.
- For `zkp_generate_proof`:
  - Hash width is `HASH_SIZE = 8` field elements. The Merkle depth is the `levels` argument (32 in the example `LEVELS = 32`).
  - `leaf8_u32` has 8 field elements as `uint32_t` (must be canonical for the KoalaBear field).
  - `neighbors8_by_level_u32` has `levels * 8` field elements in row-major order; level `l` occupies indices `[l*8 .. l*8+8)`.
  - `sides_bitflags[lvl]` indicates neighbor position: `0` = neighbor on the right (concat `[current || neighbor]`), `1` = neighbor on the left (concat `[neighbor || current]`). Only `0` or `1` are accepted; additionally, `sides[0]` MUST be `0` to enforce proof uniqueness.
  - `nonce32` is a 32‑byte seed used in Fiat–Shamir; different nonces produce different proofs for the same inputs.
  - Caller must provide output buffers (`proof_out`, `ct_out`) large enough for postcard‑serialized outputs; if too small, the functions return `BATTERY_ERR_BUFSZ`.
