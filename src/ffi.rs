use super::Vec;
use crate::aes_ctr::aes_ctr_encrypt_in_place;
use crate::tfhe::{TFHEPublicKey, TRLWECiphertext, TRLWEPlaintext};
use crate::zkp::{self, Val};

use p3_field::integers::QuotientMap;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Public constants for FFI
pub const TFHE_TRLWE_N: usize = 1024;
const Q: u64 = 1 << 50;
const ERR_B: i64 = 1 << 30;

// FFI status and size constants
pub const TFHE_OK: i32 = 0;
pub const TFHE_ERR_NULL: i32 = -1; // null pointer
pub const TFHE_ERR_BADLEN: i32 = -2; // incorrect buffer length
pub const TFHE_ERR_SEEDLEN: i32 = -6; // incorrect seed length
pub const TFHE_ERR_ZKP_INPUT: i32 = -8; // invalid zkp inputs
pub const TFHE_ERR_ZKP_BUFSZ: i32 = -10; // output buffer too small

pub const TFHE_SEED_LEN: usize = 32;
pub const TFHE_AES_KEY_LEN: usize = 16;
pub const TFHE_AES_IV_LEN: usize = 16;

#[inline]
fn encode_aes_key_as_poly<const N: usize, const Q: u64>(key16: &[u8; 16]) -> TRLWEPlaintext<N, Q> {
    let one: u64 = Q / 4;
    let mut out = TRLWEPlaintext::<N, Q>::zero();
    let limit = core::cmp::min(N, key16.len() * 8);
    for i in 0..limit {
        let b = (key16[i >> 3] >> (i & 7)) & 1;
        out.coeffs[i] = if b != 0 { one } else { 0 };
    }
    out
}

// ------------- TFHE -------------

/// Encrypt an AES-128 key using an opaque serialized public key.
/// Inputs:
/// - `pk`/`pk_len`: postcard-serialized `TFHEPublicKey` for N=1024, Q=2^50.
/// - `aes_key16` (len=16)
/// - `seed32` (len=32)
/// Outputs:
/// - `ct_out`/`ct_out_len`: caller-provided buffer for postcard-serialized `TRLWECiphertext`.
/// - `out_written`: number of bytes written. If too small, returns `TFHE_ERR_ZKP_BUFSZ`.
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
    if pk.is_null() || aes_key16.is_null() || seed32.is_null() || ct_out.is_null() || out_written.is_null() {
        return TFHE_ERR_NULL;
    }
    if seed_len != TFHE_SEED_LEN {
        return TFHE_ERR_SEEDLEN;
    }
    let pk_bytes = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let pk: TFHEPublicKey<TFHE_TRLWE_N, Q> = match postcard::from_bytes(pk_bytes) {
        Ok(v) => v,
        Err(_) => return TFHE_ERR_ZKP_INPUT,
    };
    let seed = unsafe { core::slice::from_raw_parts(seed32, TFHE_SEED_LEN) };
    let mut seed_arr = [0u8; TFHE_SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);
    let key = unsafe { &*(aes_key16 as *const [u8; TFHE_AES_KEY_LEN]) };
    let pt_poly = encode_aes_key_as_poly::<TFHE_TRLWE_N, Q>(key);
    let ct_obj = TRLWECiphertext::<TFHE_TRLWE_N, Q>::encrypt_with_public_key::<_, ERR_B>(
        &pt_poly, &pk, &mut rng,
    );
    match postcard::to_allocvec(&ct_obj) {
        Ok(bytes) => {
            unsafe { *out_written = bytes.len(); }
            if bytes.len() > ct_out_len {
                return TFHE_ERR_ZKP_BUFSZ;
            }
            let out_bytes = unsafe { core::slice::from_raw_parts_mut(ct_out, ct_out_len) };
            out_bytes[..bytes.len()].copy_from_slice(&bytes);
            TFHE_OK
        }
        Err(_) => TFHE_ERR_ZKP_INPUT,
    }
}

// ------------- ZKP -------------

#[derive(serde::Serialize, serde::Deserialize)]
struct OpaqueMerklePathArgs {
    leaf8_u32: [u32; 8],
    neighbors8_by_level_u32: Vec<[u32; 8]>,
    sides_bitflags: Vec<u8>,
}

/// Generate a Merkle-path ZK proof using a single opaque serialized argument, with a separate nonce.
/// Inputs:
/// - `args`/`args_len`: postcard-serialized OpaqueMerklePathArgs
/// - `nonce32` (len=32)
/// Outputs:
/// - `proof_out`/`proof_out_len`: caller-provided buffer for postcard-serialized proof.
/// - `out_proof_written`: number of bytes written. If too small, returns `TFHE_ERR_ZKP_BUFSZ`.
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
        return TFHE_ERR_NULL;
    }
    let args_bytes = unsafe { core::slice::from_raw_parts(args, args_len) };
    let args: OpaqueMerklePathArgs = match postcard::from_bytes(args_bytes) {
        Ok(v) => v,
        Err(_) => return TFHE_ERR_ZKP_INPUT,
    };
    let levels = args.neighbors8_by_level_u32.len();
    if levels == 0 || args.sides_bitflags.len() != levels {
        return TFHE_ERR_ZKP_INPUT;
    }
    let nonce = unsafe { core::slice::from_raw_parts(nonce32, TFHE_SEED_LEN) };
    let mut nonce_arr = [0u8; TFHE_SEED_LEN];
    nonce_arr.copy_from_slice(nonce);
    let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
    for i in 0..8 {
        match Val::from_canonical_checked(args.leaf8_u32[i]) {
            Some(v) => leaf[i] = v,
            None => return TFHE_ERR_ZKP_INPUT,
        }
    }
    let mut neighbors: Vec<([Val; 8], bool)> = Vec::with_capacity(levels);
    for (lvl, neigh) in args.neighbors8_by_level_u32.iter().enumerate() {
        let mut arr = [Val::from_canonical_checked(0).unwrap(); 8];
        for j in 0..8 {
            match Val::from_canonical_checked(neigh[j]) {
                Some(v) => arr[j] = v,
                None => return TFHE_ERR_ZKP_INPUT,
            }
        }
        let side = args.sides_bitflags[lvl];
        if side != 0 && side != 1 {
            return TFHE_ERR_ZKP_INPUT;
        }
        let is_left = side == 1;
        neighbors.push((arr, is_left));
    }
    if neighbors[0].1 {
        return TFHE_ERR_ZKP_INPUT;
    }
    let (proof, public_values) = zkp::generate_proof(&leaf, &neighbors, &nonce_arr);
    if public_values.len() != zkp::HASH_SIZE {
        return TFHE_ERR_ZKP_INPUT;
    }
    match postcard::to_allocvec(&proof) {
        Ok(bytes) => {
            unsafe { *out_proof_written = bytes.len(); }
            if bytes.len() > proof_out_len {
                return TFHE_ERR_ZKP_BUFSZ;
            }
            let out_bytes = unsafe { core::slice::from_raw_parts_mut(proof_out, proof_out_len) };
            out_bytes[..bytes.len()].copy_from_slice(&bytes);
            TFHE_OK
        }
        Err(_) => TFHE_ERR_ZKP_INPUT,
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
        return TFHE_ERR_NULL;
    }
    if key_len != TFHE_AES_KEY_LEN || iv_len != TFHE_AES_IV_LEN {
        return TFHE_ERR_BADLEN;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let key_slice = unsafe { core::slice::from_raw_parts(key16, TFHE_AES_KEY_LEN) };
    let iv_slice = unsafe { core::slice::from_raw_parts(iv16, TFHE_AES_IV_LEN) };
    let mut key = [0u8; TFHE_AES_KEY_LEN];
    let mut iv = [0u8; TFHE_AES_IV_LEN];
    key.copy_from_slice(key_slice);
    iv.copy_from_slice(iv_slice);
    aes_ctr_encrypt_in_place(&key, &iv, slice);
    TFHE_OK
}
/// Pack a TFHE public key from `u64[N]` arrays into a postcard-serialized opaque buffer.
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pack_public_key(
    pk_a: *const u64,
    pk_b: *const u64,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    if pk_a.is_null() || pk_b.is_null() || out.is_null() || out_written.is_null() {
        return TFHE_ERR_NULL;
    }
    let a_slice = unsafe { core::slice::from_raw_parts(pk_a, TFHE_TRLWE_N) };
    let b_slice = unsafe { core::slice::from_raw_parts(pk_b, TFHE_TRLWE_N) };
    let a = crate::poly::Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(a_slice);
    let b = crate::poly::Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(b_slice);
    let pk = crate::tfhe::TFHEPublicKey::<TFHE_TRLWE_N, Q> {
        ct: crate::tfhe::TRLWECiphertext { a, b },
    };
    match postcard::to_allocvec(&pk) {
        Ok(bytes) => {
            unsafe { *out_written = bytes.len(); }
            if bytes.len() > out_len {
                return TFHE_ERR_ZKP_BUFSZ;
            }
            let out_bytes = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
            out_bytes[..bytes.len()].copy_from_slice(&bytes);
            TFHE_OK
        }
        Err(_) => TFHE_ERR_ZKP_INPUT,
    }
}

/// Pack Merkle path arguments into a postcard-serialized opaque buffer.
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
        return TFHE_ERR_NULL;
    }
    if levels == 0 {
        return TFHE_ERR_ZKP_INPUT;
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
    let args = OpaqueMerklePathArgs { leaf8_u32: leaf, neighbors8_by_level_u32: neighbors, sides_bitflags: sides_vec };
    match postcard::to_allocvec(&args) {
        Ok(bytes) => {
            unsafe { *out_written = bytes.len(); }
            if bytes.len() > out_len {
                return TFHE_ERR_ZKP_BUFSZ;
            }
            let out_bytes = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
            out_bytes[..bytes.len()].copy_from_slice(&bytes);
            TFHE_OK
        }
        Err(_) => TFHE_ERR_ZKP_INPUT,
    }
}
