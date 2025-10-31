# FFI C Example: E2E — TFHE public-key encryption, AES-CTR, and ZKP proof

This example demonstrates how to use the generated C bindings to call the TFHE public‑key encryption from C and how to generate a ZK proof.

## Build & Run example

- Build and run the C example locally

   $ cd examples/e2e
   $ make
   $ ./e2e

- Build the example for running it on a different platform (requires `zig`!)

   $ cd examples/e2e
   $ make PLATFORM=dev-musl
   $ ./e2e

## What it does

- Creates dummy public key arrays `(pk_a, pk_b)`; replace with a real key in practice.
- Calls `tfhe_pk_encrypt` to encode arbitrary bytes (here: a 16‑byte AES‑128 key) into the plaintext polynomial and encrypt it with the TFHE public key.
- Calls `aes_ctr_encrypt` to encrypt 64 bytes with that AES key and prints the first 16 bytes of ciphertext.
- Calls `zkp_generate_proof` to produce a STARK proof from a caller‑provided leaf, Merkle neighbors, side flags, and nonce. Demo inputs are small, fixed arrays.
  The function returns an opaque postcard bundle containing `(proof, public_values)` where `public_values`
  is exactly 24 field elements in this layout: `[root(8) | nonce_field_rep(8) | hash(leaf||nonce)(8)]`.

## Notes

- The RNG seeds in the demo are fixed for reproducibility; use real randomness in production.
- API returns status codes: `BATTERY_OK`, `BATTERY_ERR_NULL`, `BATTERY_ERR_BADLEN`, `BATTERY_ERR_SEEDLEN`, `BATTERY_ERR_INPUT`, `BATTERY_ERR_BUFSZ`.
- All inputs/outputs use opaque byte buffers; no special alignment requirements.
- For `zkp_generate_proof`:
  - Hash width is `HASH_SIZE = 8` field elements. After commit 8bca163, the STARK trace starts with an extra first row hashing `(leaf || nonce)`, so the number of rows is `levels + 1`.
    The prover stack requires the trace height to be a power of two, so callers must choose `levels = 2^k - 1` (e.g., 31 -> rows 32).
  - `leaf8_u32` has 8 field elements as `uint32_t` (must be canonical for the KoalaBear field).
  - `neighbors8_by_level_u32` has `levels * 8` field elements in row-major order; level `l` occupies indices `[l*8 .. l*8+8)`.
  - `sides_bitflags[lvl]` indicates neighbor position: `0` = neighbor on the right (concat `[current || neighbor]`), `1` = neighbor on the left (concat `[neighbor || current]`). Only `0` or `1` are accepted; additionally, `sides[0]` MUST be `0` to enforce proof uniqueness.
  - `nonce32` is a 32‑byte seed used in Fiat–Shamir; different nonces produce different proofs for the same inputs. The Merkle root in `public_values[0..8]` is independent of the nonce; however, `public_values[16..24] = hash(leaf||nonce)` changes per nonce and can be used as a per‑session device identity.
  - Caller must provide output buffers (`proof_out`, `ct_out`) large enough for postcard‑serialized outputs; if too small, the functions return `BATTERY_ERR_BUFSZ`.
