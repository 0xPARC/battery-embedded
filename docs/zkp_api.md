# ZKP FFI API — Client/Server Contract

This document describes how a server and a device (client) interact to generate a Merkle‑path proof using the FFI.

## Overview

- Hash width: `HASH_SIZE = 8` field elements.
- The prover’s trace includes two extra rows (leaf hash + binding), so `rows = levels + 2` must be a power of two.
  Choose `levels = 2^k − 2` (e.g., 30 → rows 32).
- The leaf is computed inside the circuit as `leaf = Poseidon2(secret)`; callers never pass the leaf directly.

## Server → Client: Opaque Path Args

The server prepares Merkle path arguments and sends them as a postcard‑serialized buffer.

```
struct OpaqueMerklePathArgs {
    neighbors8_by_level_u32: Vec<[u32; 8]>,
    sides_bitflags: Vec<u8>,
}
```

Rules:
- `levels = neighbors8_by_level_u32.len()` and `sides_bitflags.len() == levels`.
- Each neighbor is 8 canonical field limbs (`u32`).
- `sides_bitflags[lvl] ∈ {0, 1}` with semantics:
  - `0` → neighbor on the right, concatenate `[current || neighbor]`.
  - `1` → neighbor on the left, concatenate `[neighbor || current]`.
- Uniqueness: enforce `sides_bitflags[0] == 0`.
- Power‑of‑two height: `(levels + 2).is_power_of_two()` must hold.

The helper `zkp_pack_args` is provided to build this buffer.

## Client API

Generate a proof:

```
int32_t zkp_generate_proof(const uint8_t *secret32,
                           const uint8_t *args,
                           size_t args_len,
                           const uint8_t *nonce32,
                           uint8_t *proof_out,
                           size_t proof_out_len,
                           size_t *out_proof_written);
```

Inputs:
- `secret32` — 32‑byte device secret mapped to 8 canonical limbs; non‑canonical limbs return `BATTERY_ERR_INPUT`.
- `args` — postcard of `OpaqueMerklePathArgs` from the server (neighbors + sides only).
- `nonce32` — 32‑byte nonce used for binding `hash(leaf || nonce)`.

Output:
- `proof_out` — postcard bundle `(proof, public_values)` with
  `public_values = [root(8) | nonce_field(8) | hash(leaf||nonce)(8)]`.
- If the buffer is too small, returns `BATTERY_ERR_BUFSZ` and sets `*out_proof_written` to the required size.

Compute a leaf locally (optional):

```
int32_t zkp_compute_leaf_from_secret(const uint8_t *secret32,
                                     uint32_t *leaf_out_u32,
                                     size_t leaf_out_len);
```

This returns the 8 canonical limbs of `Poseidon2(secret)`; useful for logging or server‑side comparisons.

## Validation Checklist

- Levels: `(levels + 2)` is a power of two; `levels > 0`.
- Sides: `sides_bitflags` only contains `0` or `1`, and `sides_bitflags[0] == 0`.
- Canonical limbs: neighbors and the secret map to canonical field elements.
- Buffer sizing: handle `BATTERY_ERR_BUFSZ` by resizing and retrying.
