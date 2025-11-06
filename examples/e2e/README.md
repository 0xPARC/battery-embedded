# FFI C Example: E2E — TFHE public-key encryption and ZKP proof

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
- Calls `tfhe_pk_encrypt` to encode and encrypt 16 demo bytes into the plaintext polynomial with the TFHE public key.
- Calls `zkp_generate_proof` to produce a STARK proof. The device passes both secret leaves (`secret16_u32 = [leaf(8) | sibling(8)]`),
  and the server supplies an opaque postcard for the parent→root path (`zkp_pack_args`). The function returns an opaque postcard bundle
  containing `(proof, public_values)` where `public_values` is exactly 24 field elements in this layout:
  `[root(8) | nonce_field_rep(8) | hash(leaf||nonce)(8)]`.

## Notes

- The RNG seeds in the demo are fixed for reproducibility; use real randomness in production.
- API returns status codes: `BATTERY_OK`, `BATTERY_ERR_NULL`, `BATTERY_ERR_BADLEN`, `BATTERY_ERR_SEEDLEN`, `BATTERY_ERR_INPUT`, `BATTERY_ERR_BUFSZ`.
- All inputs/outputs use opaque byte buffers; no special alignment requirements.
- For `zkp_generate_proof`:
  - Hash width is `HASH_SIZE = 8` field elements. The STARK trace starts with an extra first row hashing `(leaf || nonce)`; we then prepend the sibling with a fixed right-neighbor flag. Therefore, `rows = levels(parent→root) + 2` must be a power of two (e.g., for 32 rows use `levels = 30`).
  - `secret16_u32` packs both leaves as canonical field reps.
  - `neighbors8_by_level_u32` has `levels * 8` field elements in row-major order; level `l` occupies indices `[l*8 .. l*8+8)`.
  - `sides_bitflags[lvl]` indicates neighbor position: `0` = right, `1` = left. Only `0` or `1` are accepted.
  - `nonce32` is a 32‑byte seed used in Fiat–Shamir; different nonces produce different proofs for the same inputs. The Merkle root in `public_values[0..8]` is independent of the nonce; however, `public_values[16..24] = hash(leaf||nonce)` changes per nonce and can be used as a per‑session device identity.
  - Caller must provide output buffers (`proof_out`, `ct_out`) large enough for postcard‑serialized outputs; if too small, the functions return `BATTERY_ERR_BUFSZ`.

Optional helper:
- `zkp_parent_from_secret(secret16_u32, parent8_u32_out)` computes `parent = Poseidon2(leaf || sibling)` so the device can verify the server-provided path begins at the expected node without revealing the leaves.
