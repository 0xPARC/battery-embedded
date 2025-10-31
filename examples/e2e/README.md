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
- Calls `zkp_generate_proof(secret32, args, nonce32, ...)` to produce a STARK proof from a device secret and an opaque Merkle path (`neighbors + sides`).
  The function returns an opaque postcard bundle containing `(proof, public_values)` where `public_values`
  is exactly 24 field elements in this layout: `[root(8) | nonce_field(8) | hash(leaf||nonce)(8)]`.

## Notes

- The RNG seeds in the demo are fixed for reproducibility; use real randomness in production.
- API returns status codes: `BATTERY_OK`, `BATTERY_ERR_NULL`, `BATTERY_ERR_BADLEN`, `BATTERY_ERR_SEEDLEN`, `BATTERY_ERR_INPUT`, `BATTERY_ERR_BUFSZ`.
- All inputs/outputs use opaque byte buffers; no special alignment requirements.
- For `zkp_generate_proof`:
  - Inputs: `secret32` (32‑byte device secret), `args` = postcard of `{ neighbors8_by_level_u32, sides_bitflags }`, and `nonce32`.
  - The trace includes two extra rows (leaf hash + binding), so `rows = levels + 2` must be a power of two. Choose `levels = 2^k - 2` (e.g., 30 -> rows 32).
  - `neighbors8_by_level_u32` has `levels * 8` field elements in row‑major order; level `l` occupies indices `[l*8 .. l*8+8)`.
  - `sides_bitflags[lvl]` indicates neighbor position: `0` = neighbor on the right (concat `[current || neighbor]`), `1` = neighbor on the left (concat `[neighbor || current]`). Only `0` or `1` are accepted; additionally, `sides[0]` MUST be `0` to enforce proof uniqueness.
  - The leaf is derived in‑circuit as `leaf = Poseidon2(secret)`. For convenience there is also `zkp_compute_leaf_from_secret(secret32, out_u32[8])` which returns the 8 canonical field limbs.
  - `nonce32` is a 32‑byte seed; `public_values[16..24] = hash(leaf||nonce)` changes per nonce while the Merkle root in `public_values[0..8]` is nonce‑independent.
  - Caller must provide output buffers large enough for postcard‑serialized outputs; if too small, functions return `BATTERY_ERR_BUFSZ`.
