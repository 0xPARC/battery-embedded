use super::Vec;
use crate::poly::Poly;
use crate::tfhe::encode_bits_as_trlwe_plaintext;
use crate::tfhe::{TFHEPublicKey, TRLWECiphertext};
use crate::zkp::HASH_SIZE;
use crate::zkp::{self, MerkleInclusionProof, Val};

use p3_field::PrimeField32;
use p3_field::integers::QuotientMap;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Public constants for FFI
pub const TFHE_TRLWE_N: usize = 1 << 10;
const Q: u64 = 1 << 50;
const ERR_B: u64 = 250;

// Unified FFI status and size constants (project‑wide)
pub const BATTERY_OK: i32 = 0;
pub const BATTERY_ERR_NULL: i32 = -1; // null pointer
pub const BATTERY_ERR_BADLEN: i32 = -2; // incorrect buffer length
pub const BATTERY_ERR_SEEDLEN: i32 = -6; // incorrect seed length
pub const BATTERY_ERR_INPUT: i32 = -8; // invalid inputs
pub const BATTERY_ERR_BUFSZ: i32 = -10; // output buffer too small

pub const BATTERY_SEED_LEN: usize = 32; // TFHE RNG seed length
pub const BATTERY_NONCE_LEN: usize = 32; // ZKP Fiat–Shamir nonce length

pub const BATTERY_API_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn battery_api_version() -> u32 {
    BATTERY_API_VERSION
}

/// Encrypt an arbitrary byte string by encoding its bits LSB-first into a TRLWE plaintext
/// and encrypting it with the TFHE public key. The number of encoded bits is `bytes_len * 8`.
/// Fails if `bytes_len * 8 > TFHE_TRLWE_N`.
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pk_encrypt(
    pk: *const u8,
    pk_len: usize,
    bytes: *const u8,
    bytes_len: usize,
    seed32: *const u8,
    seed_len: usize,
    ct_out: *mut u8,
    ct_out_len: usize,
    out_written: *mut usize,
) -> i32 {
    if pk.is_null()
        || bytes.is_null()
        || seed32.is_null()
        || ct_out.is_null()
        || out_written.is_null()
    {
        return BATTERY_ERR_NULL;
    }
    if seed_len != BATTERY_SEED_LEN {
        return BATTERY_ERR_SEEDLEN;
    }
    // Check capacity
    let bit_len = bytes_len.saturating_mul(8);
    if bit_len > TFHE_TRLWE_N {
        return BATTERY_ERR_BADLEN;
    }
    // Deserialize PK
    let pk_bytes = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let pk: TFHEPublicKey<TFHE_TRLWE_N, Q> = match postcard::from_bytes(pk_bytes) {
        Ok(v) => v,
        Err(_) => return BATTERY_ERR_INPUT,
    };
    // Build plaintext from bytes
    let data = unsafe { core::slice::from_raw_parts(bytes, bytes_len) };
    let pt_poly = encode_bits_as_trlwe_plaintext::<TFHE_TRLWE_N, Q>(data, bit_len);
    // RNG
    let seed = unsafe { core::slice::from_raw_parts(seed32, BATTERY_SEED_LEN) };
    let mut seed_arr = [0u8; BATTERY_SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);
    // Encrypt
    let ct_obj = TRLWECiphertext::<TFHE_TRLWE_N, Q>::encrypt_with_public_key::<_, ERR_B>(
        &pt_poly, &pk, &mut rng,
    );
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(ct_out, ct_out_len) };
    match postcard::to_slice(&ct_obj, out_bytes) {
        Ok(rem) => {
            let written = ct_out_len - rem.len();
            unsafe {
                *out_written = written;
            }
            BATTERY_OK
        }
        Err(_) => match postcard::to_allocvec(&ct_obj) {
            Ok(bytes) => {
                unsafe {
                    *out_written = bytes.len();
                }
                BATTERY_ERR_BUFSZ
            }
            Err(_) => BATTERY_ERR_INPUT,
        },
    }
}

/// Compute the parent hash from the two secret leaves using the same Poseidon2 parameters
/// and orientation used in the Merkle tree: parent = H(leaf || sibling) with selector=0.
/// Inputs:
/// - `secret16_u32`: two concatenated leaves as 16 u32 words.
/// Outputs:
/// - `parent8_u32_out`: 8 u32 words with the parent field elements.
#[unsafe(no_mangle)]
pub extern "C" fn zkp_parent_from_secret(
    secret16_u32: *const u32,
    parent8_u32_out: *mut u32,
) -> i32 {
    if secret16_u32.is_null() || parent8_u32_out.is_null() {
        return BATTERY_ERR_NULL;
    }
    let words = unsafe { core::slice::from_raw_parts(secret16_u32, 16) };
    let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
    let mut sib = [Val::from_canonical_checked(0).unwrap(); 8];
    for i in 0..8 {
        match Val::from_canonical_checked(words[i]) {
            Some(v) => leaf[i] = v,
            None => return BATTERY_ERR_INPUT,
        }
        match Val::from_canonical_checked(words[8 + i]) {
            Some(v) => sib[i] = v,
            None => return BATTERY_ERR_INPUT,
        }
    }

    // Compute parent via reusable hashing logic
    let parent = zkp::hash::parent_from_pair(&leaf, &sib);
    let out = unsafe { core::slice::from_raw_parts_mut(parent8_u32_out, 8) };
    for i in 0..8 {
        out[i] = parent[i].as_canonical_u32();
    }
    BATTERY_OK
}

/// Encrypt bytes and return raw TRLWE ciphertext coefficients (no serialization).
/// a_out and b_out must each point to arrays of length TFHE_TRLWE_N.
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pk_encrypt_raw(
    pk: *const u8,
    pk_len: usize,
    bytes: *const u8,
    bytes_len: usize,
    seed32: *const u8,
    seed_len: usize,
    a_out: *mut u64,
    b_out: *mut u64,
) -> i32 {
    if pk.is_null() || bytes.is_null() || seed32.is_null() || a_out.is_null() || b_out.is_null() {
        return BATTERY_ERR_NULL;
    }

    if seed_len != BATTERY_SEED_LEN {
        return BATTERY_ERR_SEEDLEN;
    }

    let bit_len = bytes_len.saturating_mul(8);
    if bit_len > TFHE_TRLWE_N {
        return BATTERY_ERR_BADLEN;
    }

    // Deserialize PK
    let pk_bytes = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let pk: TFHEPublicKey<TFHE_TRLWE_N, Q> = match postcard::from_bytes(pk_bytes) {
        Ok(v) => v,
        Err(_) => return BATTERY_ERR_INPUT,
    };

    // Build plaintext from bytes
    let data = unsafe { core::slice::from_raw_parts(bytes, bytes_len) };
    let pt_poly = encode_bits_as_trlwe_plaintext::<TFHE_TRLWE_N, Q>(data, bit_len);

    // RNG
    let seed = unsafe { core::slice::from_raw_parts(seed32, BATTERY_SEED_LEN) };
    let mut seed_arr = [0u8; BATTERY_SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);

    // Encrypt
    let ct_obj = TRLWECiphertext::<TFHE_TRLWE_N, Q>::encrypt_with_public_key::<_, ERR_B>(
        &pt_poly, &pk, &mut rng,
    );

    // Write raw coefficients
    let a_dst = unsafe { core::slice::from_raw_parts_mut(a_out, TFHE_TRLWE_N) };
    let b_dst = unsafe { core::slice::from_raw_parts_mut(b_out, TFHE_TRLWE_N) };
    a_dst.copy_from_slice(&ct_obj.a.coeffs);
    b_dst.copy_from_slice(&ct_obj.b.coeffs);
    BATTERY_OK
}

// ------------- ZKP -------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ZkpProofBundle(
    MerkleInclusionProof,
    Vec<Val>, // public values layout: [root(8) | nonce_field(8) | hash(leaf||nonce)(8)]
);

#[derive(serde::Serialize, serde::Deserialize)]
struct OpaqueMerklePathArgs {
    // Parent-to-root siblings; the device supplies both leaves in `secret`.
    neighbors8_by_level_u32: Vec<[u32; 8]>,
    sides_bitflags: Vec<u8>,
}

/// Generate a Merkle-path ZK proof. The device provides both secret leaves,
/// and the opaque args contain the parent→root path supplied by the server.
/// Inputs:
/// - `secret16_u32`: two concatenated leaves as 16 `u32` words: [leaf(8) | sibling(8)]
/// - `args`/`args_len`: postcard-serialized OpaqueMerklePathArgs (parent→root)
/// - `nonce32` (len=`BATTERY_NONCE_LEN`)
/// Outputs:
/// - `proof_out`/`proof_out_len`: caller-provided buffer for postcard-serialized bundle:
///   (proof, public_values) where public_values = [root(8) | nonce_field(8) | hash(leaf||nonce)(8)].
/// - `out_proof_written`: number of bytes written. If too small, returns `BATTERY_ERR_BUFSZ`.
///
/// Serialization: postcard 1.x (stable).
#[unsafe(no_mangle)]
pub extern "C" fn zkp_generate_proof(
    secret16_u32: *const u32,
    args: *const u8,
    args_len: usize,
    nonce32: *const u8,
    proof_out: *mut u8,
    proof_out_len: usize,
    out_proof_written: *mut usize,
) -> i32 {
    if secret16_u32.is_null()
        || args.is_null()
        || nonce32.is_null()
        || proof_out.is_null()
        || out_proof_written.is_null()
    {
        return BATTERY_ERR_NULL;
    }
    let args_bytes = unsafe { core::slice::from_raw_parts(args, args_len) };
    let args: OpaqueMerklePathArgs = match postcard::from_bytes(args_bytes) {
        Ok(v) => v,
        Err(_) => return BATTERY_ERR_INPUT,
    };
    let levels_parent = args.neighbors8_by_level_u32.len();
    if args.sides_bitflags.len() != levels_parent {
        return BATTERY_ERR_INPUT;
    }
    // rows = parent-levels + 2 (row0: hash(leaf||nonce), row1: hash(leaf||sibling)) must be power of two
    let rows = levels_parent + 2;
    if !rows.is_power_of_two() {
        return BATTERY_ERR_INPUT;
    }
    let nonce = unsafe { core::slice::from_raw_parts(nonce32, BATTERY_NONCE_LEN) };
    let mut nonce_arr = [0u8; BATTERY_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    // Parse secret: [leaf | sibling]
    let secret_words = unsafe { core::slice::from_raw_parts(secret16_u32, 16) };
    let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
    let mut sibling = [Val::from_canonical_checked(0).unwrap(); 8];
    for i in 0..8 {
        match Val::from_canonical_checked(secret_words[i]) {
            Some(v) => leaf[i] = v,
            None => return BATTERY_ERR_INPUT,
        }
        match Val::from_canonical_checked(secret_words[8 + i]) {
            Some(v) => sibling[i] = v,
            None => return BATTERY_ERR_INPUT,
        }
    }
    let mut neighbors: Vec<([Val; 8], bool)> = Vec::with_capacity(levels_parent + 1);
    // Prepend sibling at side=0 (right neighbor)
    neighbors.push((sibling, false));
    for (lvl, neigh) in args.neighbors8_by_level_u32.iter().enumerate() {
        let mut arr = [Val::from_canonical_checked(0).unwrap(); 8];
        for j in 0..8 {
            match Val::from_canonical_checked(neigh[j]) {
                Some(v) => arr[j] = v,
                None => return BATTERY_ERR_INPUT,
            }
        }
        let side = args.sides_bitflags[lvl];
        if side != 0 && side != 1 {
            return BATTERY_ERR_INPUT;
        }
        let is_left = side == 1;
        neighbors.push((arr, is_left));
    }
    if neighbors[0].1 {
        return BATTERY_ERR_INPUT;
    }
    let (proof, public_values) = zkp::generate_proof(&leaf, &neighbors, &nonce_arr);
    // Public values layout is fixed at 24 = 3 * HASH_SIZE elements:
    //   [root(8) | nonce_field(8) | hash(leaf||nonce)(8)].
    if public_values.len() != 3 * HASH_SIZE {
        return BATTERY_ERR_INPUT;
    }
    let bundle = ZkpProofBundle(proof, public_values);
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(proof_out, proof_out_len) };
    match postcard::to_slice(&bundle, out_bytes) {
        Ok(rem) => {
            let written = proof_out_len - rem.len();
            unsafe {
                *out_proof_written = written;
            }
            BATTERY_OK
        }
        Err(_) => match postcard::to_allocvec(&bundle) {
            Ok(bytes) => {
                unsafe {
                    *out_proof_written = bytes.len();
                }
                BATTERY_ERR_BUFSZ
            }
            Err(_) => BATTERY_ERR_INPUT,
        },
    }
}

// Pack a TFHE public key from `u64[N]` arrays into a postcard-serialized opaque buffer.
/// Serialization: postcard 1.x (stable).
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pack_public_key(
    pk_a: *const u64,
    pk_b: *const u64,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    if pk_a.is_null() || pk_b.is_null() || out.is_null() || out_written.is_null() {
        return BATTERY_ERR_NULL;
    }
    let a_slice = unsafe { core::slice::from_raw_parts(pk_a, TFHE_TRLWE_N) };
    let b_slice = unsafe { core::slice::from_raw_parts(pk_b, TFHE_TRLWE_N) };
    let a = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(a_slice);
    let b = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(b_slice);
    let pk = TFHEPublicKey::<TFHE_TRLWE_N, Q> { a, b };
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
    match postcard::to_slice(&pk, out_bytes) {
        Ok(rem) => {
            let written = out_len - rem.len();
            unsafe {
                *out_written = written;
            }
            BATTERY_OK
        }
        Err(_) => match postcard::to_allocvec(&pk) {
            Ok(bytes) => {
                unsafe {
                    *out_written = bytes.len();
                }
                BATTERY_ERR_BUFSZ
            }
            Err(_) => BATTERY_ERR_INPUT,
        },
    }
}

/// Pack Merkle path arguments into a postcard-serialized opaque buffer.
/// Serialization: postcard 1.x (stable).
#[unsafe(no_mangle)]
pub extern "C" fn zkp_pack_args(
    neighbors8_by_level_u32: *const u32,
    sides_bitflags: *const u8,
    levels: usize,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    if neighbors8_by_level_u32.is_null()
        || sides_bitflags.is_null()
        || out.is_null()
        || out_written.is_null()
    {
        return BATTERY_ERR_NULL;
    }
    // levels may be 0 when the parent is the root
    let neigh_u32 = unsafe { core::slice::from_raw_parts(neighbors8_by_level_u32, levels * 8) };
    let sides = unsafe { core::slice::from_raw_parts(sides_bitflags, levels) };
    let mut neighbors: Vec<[u32; 8]> = Vec::with_capacity(levels);
    for lvl in 0..levels {
        let base = lvl * 8;
        let mut arr = [0u32; 8];
        arr.copy_from_slice(&neigh_u32[base..base + 8]);
        neighbors.push(arr);
    }
    let sides_vec = sides.to_vec();
    let args = OpaqueMerklePathArgs {
        neighbors8_by_level_u32: neighbors,
        sides_bitflags: sides_vec,
    };
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
    match postcard::to_slice(&args, out_bytes) {
        Ok(rem) => {
            let written = out_len - rem.len();
            unsafe {
                *out_written = written;
            }
            BATTERY_OK
        }
        Err(_) => match postcard::to_allocvec(&args) {
            Ok(bytes) => {
                unsafe {
                    *out_written = bytes.len();
                }
                BATTERY_ERR_BUFSZ
            }
            Err(_) => BATTERY_ERR_INPUT,
        },
    }
}

#[cfg(all(test, feature = "ffi"))]
mod tests {
    use super::*;

    #[test]
    fn pack_public_key_roundtrip() {
        let a = [1u64; TFHE_TRLWE_N];
        let b = [2u64; TFHE_TRLWE_N];
        let mut buf = vec![0u8; 1 << 20];
        let mut written: usize = 0;
        let rc = tfhe_pack_public_key(
            a.as_ptr(),
            b.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut written as *mut usize,
        );
        assert_eq!(rc, BATTERY_OK);
        let pk: TFHEPublicKey<TFHE_TRLWE_N, Q> = postcard::from_bytes(&buf[..written]).unwrap();
        for i in 0..TFHE_TRLWE_N {
            assert_eq!(pk.a.coeffs[i], 1u64 % Q);
            assert_eq!(pk.b.coeffs[i], 2u64 % Q);
        }
    }

    #[test]
    fn tfhe_encrypt_buf_too_small() {
        // Build a minimal pk
        let a = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(&[0u64; TFHE_TRLWE_N]);
        let b = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(&[0u64; TFHE_TRLWE_N]);
        let pk = TFHEPublicKey::<TFHE_TRLWE_N, Q> { a, b };
        let pk_bytes = postcard::to_allocvec(&pk).unwrap();
        let data = [0u8; 16];
        let seed = [7u8; BATTERY_SEED_LEN];
        let mut out_written = 0usize;
        let mut dummy: u8 = 0;
        let rc = tfhe_pk_encrypt(
            pk_bytes.as_ptr(),
            pk_bytes.len(),
            data.as_ptr(),
            16,
            seed.as_ptr(),
            BATTERY_SEED_LEN,
            &mut dummy as *mut u8,
            0,
            &mut out_written as *mut usize,
        );
        assert_eq!(rc, BATTERY_ERR_BUFSZ);
        assert!(out_written > 0);
    }

    #[test]
    fn zkp_proof_buf_too_small() {
        // Pack args and then request proof with zero-sized buffer.
        // rows = levels(parent->root) + 2 must be a power of two.
        let levels = 30usize; // rows = 32 after prepend
        let neighbors = vec![3u32; levels * 8];
        let sides = vec![0u8; levels];
        let mut args_buf = vec![0u8; 1 << 16];
        let mut args_len: usize = 0;
        let rc = zkp_pack_args(
            neighbors.as_ptr(),
            sides.as_ptr(),
            levels,
            args_buf.as_mut_ptr(),
            args_buf.len(),
            &mut args_len as *mut usize,
        );
        assert_eq!(rc, BATTERY_OK);
        // Secret = [leaf | sibling]
        let secret: [u32; 16] = {
            let mut s = [0u32; 16];
            for i in 0..8 {
                s[i] = 4;
            }
            for i in 0..8 {
                s[8 + i] = 3;
            }
            s
        };
        let nonce = [1u8; BATTERY_NONCE_LEN];
        let mut proof_written = 0usize;
        let mut dummy: u8 = 0;
        let rc2 = zkp_generate_proof(
            secret.as_ptr(),
            args_buf.as_ptr(),
            args_len,
            nonce.as_ptr(),
            &mut dummy as *mut u8,
            0,
            &mut proof_written as *mut usize,
        );
        assert_eq!(rc2, BATTERY_ERR_BUFSZ);
        assert!(proof_written > 0);
    }

    #[test]
    fn zkp_proof_bundle_roundtrip() {
        // Build opaque args for a valid path (parent->root). rows = levels + 2 = 32
        let levels = 30usize;
        let neighbors = vec![3u32; levels * 8];
        let sides = vec![0u8; levels];
        let mut args_buf = vec![0u8; 1 << 16];
        let mut args_len: usize = 0;
        let rc = zkp_pack_args(
            neighbors.as_ptr(),
            sides.as_ptr(),
            levels,
            args_buf.as_mut_ptr(),
            args_buf.len(),
            &mut args_len as *mut usize,
        );
        assert_eq!(rc, BATTERY_OK);

        // Generate the bundle and deserialize it
        let secret: [u32; 16] = {
            let mut s = [0u32; 16];
            for i in 0..8 {
                s[i] = 4;
            }
            for i in 0..8 {
                s[8 + i] = 3;
            }
            s
        };
        let nonce = [0x11u8; BATTERY_NONCE_LEN];
        let mut out = vec![0u8; 1 << 20];
        let mut written = 0usize;
        let rc2 = zkp_generate_proof(
            secret.as_ptr(),
            args_buf.as_ptr(),
            args_len,
            nonce.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut written as *mut usize,
        );
        assert_eq!(rc2, BATTERY_OK);
        assert!(written > 0);

        let bundle: ZkpProofBundle = postcard::from_bytes(&out[..written]).unwrap();
        // Expect exactly 3 * HASH_SIZE public values: root(8) | nonce_field(8) | hash(leaf||nonce)(8)
        assert_eq!(bundle.1.len(), 3 * HASH_SIZE);
        // Re-serialize and deserialize again to check roundtrip stability of the bundle
        let bytes2 = postcard::to_allocvec(&bundle).unwrap();
        let bundle2: ZkpProofBundle = postcard::from_bytes(&bytes2).unwrap();
        assert_eq!(bundle2.1, bundle.1);
    }

    #[test]
    fn parent_from_secret() {
        use crate::zkp::hash::parent_from_pair;
        // Build two leaves as 16 u32 words: [leaf(8) | sibling(8)]
        let secret: [u32; 16] = {
            let mut s = [0u32; 16];
            for i in 0..8 {
                s[i] = 4;
            }
            for i in 0..8 {
                s[8 + i] = 3;
            }
            s
        };

        // Compute expected parent via hash util
        let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
        let mut sib = [Val::from_canonical_checked(0).unwrap(); 8];
        for i in 0..8 {
            leaf[i] = Val::from_canonical_checked(secret[i]).unwrap();
            sib[i] = Val::from_canonical_checked(secret[8 + i]).unwrap();
        }
        let expected = parent_from_pair(&leaf, &sib);

        let mut out = [0u32; 8];
        let rc = zkp_parent_from_secret(secret.as_ptr(), out.as_mut_ptr());
        assert_eq!(rc, BATTERY_OK);
        for i in 0..8 {
            assert_eq!(out[i], expected[i].as_canonical_u32());
        }
    }
}
