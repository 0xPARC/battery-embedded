use super::Vec;
use crate::aes_ctr::aes_ctr_encrypt_in_place;
use crate::tfhe::{TFHEPublicKey, TRLWECiphertext};
use crate::zkp::{self, MerkleInclusionProof, Val};

use p3_field::integers::QuotientMap;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Public constants for FFI
pub const TFHE_TRLWE_N: usize = 1024;
const Q: u64 = 1 << 50;
const ERR_B: i32 = 1 << 12;

// Unified FFI status and size constants (project‑wide)
pub const BATTERY_OK: i32 = 0;
pub const BATTERY_ERR_NULL: i32 = -1; // null pointer
pub const BATTERY_ERR_BADLEN: i32 = -2; // incorrect buffer length
pub const BATTERY_ERR_SEEDLEN: i32 = -6; // incorrect seed length
pub const BATTERY_ERR_INPUT: i32 = -8; // invalid inputs
pub const BATTERY_ERR_BUFSZ: i32 = -10; // output buffer too small

pub const BATTERY_SEED_LEN: usize = 32; // TFHE RNG seed length
pub const BATTERY_NONCE_LEN: usize = 32; // ZKP Fiat–Shamir nonce length
pub const AES_KEY_LEN: usize = 16;
pub const AES_IV_LEN: usize = 16;

pub const BATTERY_API_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn battery_api_version() -> u32 {
    BATTERY_API_VERSION
}

// ------------- TFHE -------------

/// DEPRECATED: use `tfhe_pk_encrypt` for arbitrary-length byte payloads.
/// This wrapper now forwards to `tfhe_pk_encrypt` with `bytes_len = AES_KEY_LEN`.
/// Inputs/outputs are unchanged and remain opaque postcard buffers.
#[deprecated(note = "Use tfhe_pk_encrypt for arbitrary payloads")]
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pk_encrypt_aes_key(
    pk: *const u8,
    pk_len: usize,
    aes_key16: *const u8,
    seed32: *const u8,
    seed_len: usize,
    ct_out: *mut u8,
    ct_out_len: usize,
    out_written: *mut usize,
) -> i32 {
    tfhe_pk_encrypt(
        pk,
        pk_len,
        aes_key16,
        AES_KEY_LEN,
        seed32,
        seed_len,
        ct_out,
        ct_out_len,
        out_written,
    )
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
    // Get data to encrypt
    let data = unsafe { core::slice::from_raw_parts(bytes, bytes_len) };
    // RNG
    let seed = unsafe { core::slice::from_raw_parts(seed32, BATTERY_SEED_LEN) };
    let mut seed_arr = [0u8; BATTERY_SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);
    // Encrypt
    let ct_obj = TRLWECiphertext::<TFHE_TRLWE_N, Q>::encrypt_bits::<_, ERR_B>(
        &data,
        bytes_len * 8,
        &pk,
        &mut rng,
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

// ------------- ZKP -------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ZkpProofBundle(
    MerkleInclusionProof,
    Vec<Val>, // public values layout: [root(8) | nonce_field(8) | hash(nonce||leaf)(8)]
);

#[derive(serde::Serialize, serde::Deserialize)]
struct OpaqueMerklePathArgs {
    leaf8_u32: [u32; 8],
    neighbors8_by_level_u32: Vec<[u32; 8]>,
    sides_bitflags: Vec<u8>,
}

/// Generate a Merkle-path ZK proof using a single opaque serialized argument, with a separate nonce.
/// Inputs:
/// - `args`/`args_len`: postcard-serialized OpaqueMerklePathArgs
/// - `nonce32` (len=`BATTERY_NONCE_LEN`)
/// Outputs:
/// - `proof_out`/`proof_out_len`: caller-provided buffer for postcard-serialized bundle:
///   (proof, public_values) where public_values = [root(8) | nonce_field(8) | hash(nonce||leaf)(8)].
/// - `out_proof_written`: number of bytes written. If too small, returns `BATTERY_ERR_BUFSZ`.
///
/// Serialization: postcard 1.x (stable).
#[unsafe(no_mangle)]
pub extern "C" fn zkp_generate_proof(
    args: *const u8,
    args_len: usize,
    nonce32: *const u8,
    proof_out: *mut u8,
    proof_out_len: usize,
    out_proof_written: *mut usize,
) -> i32 {
    if args.is_null() || nonce32.is_null() || proof_out.is_null() || out_proof_written.is_null() {
        return BATTERY_ERR_NULL;
    }
    let args_bytes = unsafe { core::slice::from_raw_parts(args, args_len) };
    let args: OpaqueMerklePathArgs = match postcard::from_bytes(args_bytes) {
        Ok(v) => v,
        Err(_) => return BATTERY_ERR_INPUT,
    };
    let levels = args.neighbors8_by_level_u32.len();
    if levels == 0 || args.sides_bitflags.len() != levels {
        return BATTERY_ERR_INPUT;
    }
    // The ZKP trace includes an extra first row for hash(nonce||leaf),
    // so the prover requires (levels + 1) to be a power of two.
    let rows = levels + 1;
    if !rows.is_power_of_two() {
        return BATTERY_ERR_INPUT;
    }
    let nonce = unsafe { core::slice::from_raw_parts(nonce32, BATTERY_NONCE_LEN) };
    let mut nonce_arr = [0u8; BATTERY_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
    for i in 0..8 {
        match Val::from_canonical_checked(args.leaf8_u32[i]) {
            Some(v) => leaf[i] = v,
            None => return BATTERY_ERR_INPUT,
        }
    }
    let mut neighbors: Vec<([Val; 8], bool)> = Vec::with_capacity(levels);
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
    //   [root(8) | nonce_field(8) | hash(nonce||leaf)(8)].
    if public_values.len() != 3 * zkp::HASH_SIZE {
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

// ------------- AES-CTR -------------

#[unsafe(no_mangle)]
pub extern "C" fn aes_ctr_encrypt(
    buf: *mut u8,
    len: usize,
    key16: *const u8,
    key_len: usize,
    iv16: *const u8,
    iv_len: usize,
) -> i32 {
    if buf.is_null() || key16.is_null() || iv16.is_null() {
        return BATTERY_ERR_NULL;
    }
    if key_len != AES_KEY_LEN || iv_len != AES_IV_LEN {
        return BATTERY_ERR_BADLEN;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let key_slice = unsafe { core::slice::from_raw_parts(key16, AES_KEY_LEN) };
    let iv_slice = unsafe { core::slice::from_raw_parts(iv16, AES_IV_LEN) };
    let mut key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; AES_IV_LEN];
    key.copy_from_slice(key_slice);
    iv.copy_from_slice(iv_slice);
    aes_ctr_encrypt_in_place(&key, &iv, slice);
    BATTERY_OK
}

/// Pack a TFHE public key from `u64[N]` arrays into a postcard-serialized opaque buffer.
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
    let a = crate::tfhe::coeffs_mod_q_from_slice::<TFHE_TRLWE_N, Q>(a_slice);
    let b = crate::tfhe::coeffs_mod_q_from_slice::<TFHE_TRLWE_N, Q>(b_slice);
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
    leaf8_u32: *const u32,
    neighbors8_by_level_u32: *const u32,
    sides_bitflags: *const u8,
    levels: usize,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    if leaf8_u32.is_null()
        || neighbors8_by_level_u32.is_null()
        || sides_bitflags.is_null()
        || out.is_null()
        || out_written.is_null()
    {
        return BATTERY_ERR_NULL;
    }
    if levels == 0 {
        return BATTERY_ERR_INPUT;
    }
    let leaf_slice = unsafe { core::slice::from_raw_parts(leaf8_u32, 8) };
    let mut leaf = [0u32; 8];
    leaf.copy_from_slice(leaf_slice);
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
        leaf8_u32: leaf,
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
            assert_eq!(pk.a[i], 1u64 % Q);
            assert_eq!(pk.b[i], 2u64 % Q);
        }
    }

    #[test]
    fn tfhe_encrypt_buf_too_small() {
        // Build a minimal pk
        let a = crate::tfhe::coeffs_mod_q_from_slice::<TFHE_TRLWE_N, Q>(&[0u64; TFHE_TRLWE_N]);
        let b = crate::tfhe::coeffs_mod_q_from_slice::<TFHE_TRLWE_N, Q>(&[0u64; TFHE_TRLWE_N]);
        let pk = TFHEPublicKey::<TFHE_TRLWE_N, Q> { a, b };
        let pk_bytes = postcard::to_allocvec(&pk).unwrap();
        let aes_key = [0u8; AES_KEY_LEN];
        let seed = [7u8; BATTERY_SEED_LEN];
        let mut out_written = 0usize;
        let mut dummy: u8 = 0;
        let rc = tfhe_pk_encrypt(
            pk_bytes.as_ptr(),
            pk_bytes.len(),
            aes_key.as_ptr(),
            AES_KEY_LEN,
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
        // Trace rows = levels + 1 must be a power of two.
        let levels = 31usize; // rows = 32
        let leaf = [4u32; 8];
        let neighbors = vec![3u32; levels * 8];
        let sides = vec![0u8; levels];
        let mut args_buf = vec![0u8; 1 << 16];
        let mut args_len: usize = 0;
        let rc = zkp_pack_args(
            leaf.as_ptr(),
            neighbors.as_ptr(),
            sides.as_ptr(),
            levels,
            args_buf.as_mut_ptr(),
            args_buf.len(),
            &mut args_len as *mut usize,
        );
        assert_eq!(rc, BATTERY_OK);
        let nonce = [1u8; BATTERY_NONCE_LEN];
        let mut proof_written = 0usize;
        let mut dummy: u8 = 0;
        let rc2 = zkp_generate_proof(
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
        // Build opaque args for a valid path (rows = levels + 1 = 32)
        let levels = 31usize;
        let leaf = [4u32; 8];
        let neighbors = vec![3u32; levels * 8];
        let sides = vec![0u8; levels];
        let mut args_buf = vec![0u8; 1 << 16];
        let mut args_len: usize = 0;
        let rc = zkp_pack_args(
            leaf.as_ptr(),
            neighbors.as_ptr(),
            sides.as_ptr(),
            levels,
            args_buf.as_mut_ptr(),
            args_buf.len(),
            &mut args_len as *mut usize,
        );
        assert_eq!(rc, BATTERY_OK);

        // Generate the bundle and deserialize it
        let nonce = [0x11u8; BATTERY_NONCE_LEN];
        let mut out = vec![0u8; 1 << 20];
        let mut written = 0usize;
        let rc2 = zkp_generate_proof(
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
        // Expect exactly 3 * HASH_SIZE public values: root(8) | nonce_field(8) | hash(nonce||leaf)(8)
        assert_eq!(bundle.1.len(), 3 * zkp::HASH_SIZE);
        // Re-serialize and deserialize again to check roundtrip stability of the bundle
        let bytes2 = postcard::to_allocvec(&bundle).unwrap();
        let bundle2: ZkpProofBundle = postcard::from_bytes(&bytes2).unwrap();
        assert_eq!(bundle2.1, bundle.1);
    }
}
