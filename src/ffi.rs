use super::Vec;
use crate::aes_ctr::aes_ctr_encrypt_in_place;
use crate::poly::Poly;
use crate::tfhe::{TFHEPublicKey, TRLWECiphertext, TRLWEPlaintext};
use crate::zkp::{self, Val};
use p3_field::integers::QuotientMap;
use p3_field::PrimeField32;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Concrete production parameters
pub const TFHE_TRLWE_N: usize = 1024;
const Q: u64 = 1 << 50;
const ERR_B: i64 = 1 << 30;

// FFI status and size constants
pub const TFHE_OK: i32 = 0;
pub const TFHE_ERR_NULL: i32 = -1; // null pointer
pub const TFHE_ERR_BADLEN: i32 = -2; // incorrect buffer length
pub const TFHE_ERR_ALIGN: i32 = -4; // misaligned u64 pointer
pub const TFHE_ERR_SEEDLEN: i32 = -6; // incorrect seed length
pub const TFHE_ERR_ZKP_INPUT: i32 = -8; // invalid zkp inputs
pub const TFHE_ERR_ZKP_BUFSZ: i32 = -10; // proof buffer too small

pub const TFHE_SEED_LEN: usize = 32;
pub const TFHE_AES_KEY_LEN: usize = 16;
pub const TFHE_AES_IV_LEN: usize = 16;

#[inline]
fn is_aligned_u64(p: *const u64) -> bool {
    (p as usize) & (core::mem::align_of::<u64>() - 1) == 0
}

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

// Encrypt an AES-128 key directly. Encodes each bit of the 16-byte key into the first
// 128 coefficients of the plaintext polynomial as 0 -> 0, 1 -> Q/4; remaining coeffs zero.
// Writes output ciphertext into (a_out, b_out).
// Returns TFHE_OK on success, or TFHE_ERR_* on error.
#[unsafe(no_mangle)]
pub extern "C" fn tfhe_pk_encrypt_aes_key(
    a_out: *mut u64,
    b_out: *mut u64,
    pk_a: *const u64,
    pk_b: *const u64,
    aes_key16: *const u8,
    seed32: *const u8,
    seed_len: usize,
) -> i32 {
    if a_out.is_null()
        || b_out.is_null()
        || pk_a.is_null()
        || pk_b.is_null()
        || aes_key16.is_null()
        || seed32.is_null()
    {
        return TFHE_ERR_NULL;
    }

    // Alignment checks for u64 arrays
    let aligned = is_aligned_u64(a_out)
        && is_aligned_u64(b_out)
        && is_aligned_u64(pk_a)
        && is_aligned_u64(pk_b);
    if !aligned {
        return TFHE_ERR_ALIGN;
    }
    let pk_a_slice = unsafe { core::slice::from_raw_parts(pk_a, TFHE_TRLWE_N) };
    let pk_b_slice = unsafe { core::slice::from_raw_parts(pk_b, TFHE_TRLWE_N) };
    if seed_len != TFHE_SEED_LEN {
        return TFHE_ERR_SEEDLEN;
    }
    let seed = unsafe { core::slice::from_raw_parts(seed32, TFHE_SEED_LEN) };
    let mut seed_arr = [0u8; TFHE_SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_arr);

    // Convert arrays to generic Rust types
    let a_pk = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(pk_a_slice);
    let b_pk = Poly::<TFHE_TRLWE_N, Q>::from_coeffs_mod_q_slice(pk_b_slice);
    let pk = TFHEPublicKey::<TFHE_TRLWE_N, Q> {
        ct: TRLWECiphertext { a: a_pk, b: b_pk },
    };

    // Encode AES key bits into plaintext poly
    let key = unsafe { &*(aes_key16 as *const [u8; TFHE_AES_KEY_LEN]) };

    let pt_poly = encode_aes_key_as_poly::<TFHE_TRLWE_N, Q>(key);

    let ct = TRLWECiphertext::<TFHE_TRLWE_N, Q>::encrypt_with_public_key::<_, ERR_B>(
        &pt_poly, &pk, &mut rng,
    );

    // Only now form output slices to avoid aliasing with inputs
    let a_out_slice = unsafe { core::slice::from_raw_parts_mut(a_out, TFHE_TRLWE_N) };
    let b_out_slice = unsafe { core::slice::from_raw_parts_mut(b_out, TFHE_TRLWE_N) };
    for i in 0..TFHE_TRLWE_N {
        a_out_slice[i] = ct.a.coeffs[i];
        b_out_slice[i] = ct.b.coeffs[i];
    }
    TFHE_OK
}

// AES-128 CTR encrypt in place: buf[0..len) with key[16], iv[16]
// Returns TFHE_OK on success, or TFHE_ERR_* on error.
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

/// Generate a zk proof and public values for a Merkle-style hash path.
///
/// Inputs:
/// - `leaf8_u32` (len=8): the leaf as 8 canonical field elements (u32). Each must map to a
///   valid KoalaBear field element; otherwise returns `TFHE_ERR_ZKP_INPUT`.
/// - `neighbors8_by_level_u32` (len=`levels * 8`): neighbors for each level laid out row‑major,
///   i.e., level `l` occupies indices `[l*8 .. l*8+8)`. Each u32 must be canonical.
/// - `sides_bitflags` (len=`levels`): per‑level position of the neighbor.
///   0 means neighbor on the right (concatenate [current || neighbor]);
///   1 means neighbor on the left (concatenate [neighbor || current]).
///   Only 0 or 1 are accepted; any other value returns `TFHE_ERR_ZKP_INPUT`.
///   Additionally, `sides[0]` MUST be 0 to enforce proof uniqueness; if not, returns `TFHE_ERR_ZKP_INPUT`.
/// - `levels`: Merkle depth (e.g., 32 in production). Must be > 0.
/// - `nonce32` (len=32): seed used in Fiat–Shamir; different nonces produce different proofs for
///   the same inputs but the same public root.
///
/// Outputs:
/// - `out_root8_u32` (len=8): the 8 canonical field elements of the resulting root.
/// - `proof_out`/`proof_out_len`: postcard‑serialized proof is written here. If the buffer is
///   too small, returns `TFHE_ERR_ZKP_BUFSZ` and leaves `out_proof_written` set to required size.
/// - `out_proof_written`: number of bytes written (or required if buffer too small).
///
/// Returns `TFHE_OK` on success, `TFHE_ERR_*` on invalid inputs or serialization failure.
#[unsafe(no_mangle)]
pub extern "C" fn zkp_generate_proof(
    leaf8_u32: *const u32,
    neighbors8_by_level_u32: *const u32,
    sides_bitflags: *const u8,
    levels: usize,
    nonce32: *const u8,
    out_root8_u32: *mut u32,
    proof_out: *mut u8,
    proof_out_len: usize,
    out_proof_written: *mut usize,
) -> i32 {
    if leaf8_u32.is_null()
        || neighbors8_by_level_u32.is_null()
        || sides_bitflags.is_null()
        || nonce32.is_null()
        || out_root8_u32.is_null()
        || proof_out.is_null()
        || out_proof_written.is_null()
    {
        return TFHE_ERR_NULL;
    }
    if levels == 0 {
        return TFHE_ERR_ZKP_INPUT;
    }

    let nonce = unsafe { core::slice::from_raw_parts(nonce32, TFHE_SEED_LEN) };
    let mut nonce_arr = [0u8; TFHE_SEED_LEN];
    nonce_arr.copy_from_slice(nonce);

    // Leaf
    let leaf_u32 = unsafe { core::slice::from_raw_parts(leaf8_u32, 8) };
    let mut leaf = [Val::from_canonical_checked(0).unwrap(); 8];
    for i in 0..8 {
        match Val::from_canonical_checked(leaf_u32[i]) {
            Some(v) => leaf[i] = v,
            None => return TFHE_ERR_ZKP_INPUT,
        }
    }

    // Neighbors and sides
    let neigh_u32 = unsafe { core::slice::from_raw_parts(neighbors8_by_level_u32, levels * 8) };
    let sides = unsafe { core::slice::from_raw_parts(sides_bitflags, levels) };
    let mut neighbors: Vec<([Val; 8], bool)> = Vec::with_capacity(levels);
    for lvl in 0..levels {
        let base = lvl * 8;
        let mut arr = [Val::from_canonical_checked(0).unwrap(); 8];
        for j in 0..8 {
            match Val::from_canonical_checked(neigh_u32[base + j]) {
                Some(v) => arr[j] = v,
                None => return TFHE_ERR_ZKP_INPUT,
            }
        }
        // Strictly accept only 0 or 1 to avoid ambiguous encodings.
        let side = sides[lvl];
        if side != 0 && side != 1 {
            return TFHE_ERR_ZKP_INPUT;
        }
        let is_left = side == 1;
        neighbors.push((arr, is_left));
    }

    // Enforce proof uniqueness precondition to avoid internal panic
    if neighbors[0].1 {
        return TFHE_ERR_ZKP_INPUT;
    }

    let (proof, public_values) = zkp::generate_proof(&leaf, &neighbors, &nonce_arr);

    if public_values.len() != zkp::HASH_SIZE {
        return TFHE_ERR_ZKP_INPUT;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(out_root8_u32, zkp::HASH_SIZE) };
    for i in 0..zkp::HASH_SIZE {
        out[i] = public_values[i].as_canonical_u32();
    }
    // Serialize proof with postcard into caller buffer
    match postcard::to_allocvec(&proof) {
        Ok(bytes) => {
            unsafe {
                *out_proof_written = bytes.len();
            }
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
