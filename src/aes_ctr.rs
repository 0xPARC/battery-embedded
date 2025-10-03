use aes::cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

pub type AesKey = [u8; 16];

/// Encrypts `buf` in place with AES-CTR using the provided (key, iv).
/// Caller manages IV uniqueness.
pub fn aes_ctr_encrypt_in_place(key: &AesKey, iv: &[u8; 16], buf: &mut [u8]) {
    // Construct cipher from stack arrays (no heap).
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(buf); // C = P ⊕ KS
}
