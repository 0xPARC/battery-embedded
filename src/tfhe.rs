// Minimal no_std TFHE TRLWE public-key encryption.
// using u64 coefficients with a general modulus Q and uniform-bounded errors.

use rand::Rng;

#[cfg(test)]
pub struct TFHESecretKey<const N: usize, const Q: u64> {
    pub s: [u64; N],
}

#[cfg(test)]
impl<const N: usize, const Q: u64> TFHESecretKey<N, Q> {
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let mut coeffs = [0u64; N];
        for i in 0..N {
            coeffs[i] = rng.random_range(0..2) as u64;
        }
        Self { s: coeffs }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TRLWECiphertext<const N: usize, const Q: u64> {
    #[serde(with = "serde_big_array::BigArray")]
    pub a: [u64; N],
    #[serde(with = "serde_big_array::BigArray")]
    pub b: [u64; N],
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TFHEPublicKey<const N: usize, const Q: u64> {
    #[serde(with = "serde_big_array::BigArray")]
    pub a: [u64; N],
    #[serde(with = "serde_big_array::BigArray")]
    pub b: [u64; N],
}

impl<const N: usize, const Q: u64> TRLWECiphertext<N, Q> {
    /// Encrypt `bit_len` bits from `bytes` (LSB-first)
    /// Computes: (a*u + e1, b*u + e2 + encode(bits))
    /// with: u, e1, e2 in [-B, B] as i16; fused schoolbook mul; single final reduce.
    #[inline]
    pub fn encrypt_bits<R: Rng, const B: i32>(
        bytes: &[u8],
        bit_len: usize,
        pk: &TFHEPublicKey<N, Q>,
        rng: &mut R,
    ) -> Self {
        // Compile-time invariants for this monomorphization
        const { assert!(N > 0) };
        const { assert!(Q.is_power_of_two()) };
        const { assert!((Q & 3) == 0) };
        const { assert!(B >= 0 && B <= i16::MAX as i32) };
        debug_assert!(bit_len <= N);
        debug_assert!(bytes.len() * 8 >= bit_len);

        // 1) Fused negacyclic products accumulators, with r[j] in [-B, B] sampled on-the-fly
        let mut acc_a = [0u64; N];
        let mut acc_b = [0u64; N];
        fused_mul_negacyclic_mod2k::<N, Q, B, R>(&pk.a, &pk.b, &mut acc_a, &mut acc_b, rng);

        // 2) Add plaintext bits strictly into b's accumulator
        add_bits::<N, Q>(&mut acc_b, bytes, bit_len);

        // 3) Add noise e1,e2 on the fly and store ciphertext (mod 2^k)
        let mut a_out = [0u64; N];
        let mut b_out = [0u64; N];
        for i in 0..N {
            let e1 = sample_small_i16::<B, R>(rng);
            let e2 = sample_small_i16::<B, R>(rng);
            a_out[i] = add_signed_mod::<Q>(acc_a[i], e1);
            b_out[i] = add_signed_mod::<Q>(acc_b[i], e2);
        }
        TRLWECiphertext { a: a_out, b: b_out }
    }
}

/// Add a small signed integer in [-B,B] to x modulo 2^k (mask reduction).
#[inline(always)]
fn add_signed_mod<const Q: u64>(x: u64, e: i16) -> u64 {
    const { assert!(Q.is_power_of_two()) };
    let mask = Q - 1;
    if e >= 0 {
        (x + (e as u64)) & mask
    } else {
        x.wrapping_sub((-e) as u64) & mask
    }
}

#[inline(always)]
fn reduce<const Q: u64>(x: u64) -> u64 {
    const { assert!(Q.is_power_of_two()) };
    x & (Q - 1)
}

#[inline]
pub fn coeffs_mod_q_from_slice<const N: usize, const Q: u64>(input: &[u64]) -> [u64; N] {
    const { assert!(Q.is_power_of_two()) };
    debug_assert!(input.len() == N);
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = reduce::<Q>(input[i]);
    }
    out
}

/// Sample in [-B, B]
#[inline(always)]
fn sample_small_i16<const B: i32, R: Rng>(rng: &mut R) -> i16 {
    const { assert!(B >= 0 && B <= i16::MAX as i32) };
    // NOTE: could probably be optimized better
    rng.random_range(-B..=B) as i16
}

#[inline]
fn fused_mul_negacyclic_mod2k<const N: usize, const Q: u64, const B: i32, R: Rng>(
    a: &[u64; N],
    b: &[u64; N],
    acc_a: &mut [u64; N],
    acc_b: &mut [u64; N],
    rng: &mut R,
) {
    // no mask here—let u64 wrap naturally
    for j in 0..N {
        let t = sample_small_i16::<B, R>(rng);
        if t == 0 {
            continue;
        }
        let t_abs = (t as i32).unsigned_abs() as u64;

        let lim = N - j;
        if t > 0 {
            // Non-wrap add
            for i in 0..lim {
                acc_a[j + i] = acc_a[j + i].wrapping_add(a[i].wrapping_mul(t_abs));
                acc_b[j + i] = acc_b[j + i].wrapping_add(b[i].wrapping_mul(t_abs));
            }
            // Wrap subtract
            for i in lim..N {
                let k = i - lim;
                acc_a[k] = acc_a[k].wrapping_sub(a[i].wrapping_mul(t_abs));
                acc_b[k] = acc_b[k].wrapping_sub(b[i].wrapping_mul(t_abs));
            }
        } else {
            // Non-wrap subtract
            for i in 0..lim {
                acc_a[j + i] = acc_a[j + i].wrapping_sub(a[i].wrapping_mul(t_abs));
                acc_b[j + i] = acc_b[j + i].wrapping_sub(b[i].wrapping_mul(t_abs));
            }
            // Wrap add
            for i in lim..N {
                let k = i - lim;
                acc_a[k] = acc_a[k].wrapping_add(a[i].wrapping_mul(t_abs));
                acc_b[k] = acc_b[k].wrapping_add(b[i].wrapping_mul(t_abs));
            }
        }
    }
}

#[inline]
fn add_bits<const N: usize, const Q: u64>(acc_b: &mut [u64; N], bytes: &[u8], bit_len: usize) {
    const { assert!((Q & 3) == 0) };
    let one = Q / 4;
    for i in 0..bit_len {
        let bit = (bytes[i >> 3] >> (i & 7)) & 1;
        if bit != 0 {
            acc_b[i] = acc_b[i].wrapping_add(one);
        }
    }
}

// ---------------- Tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // ----- Test-only modular helpers (assume Q is power of two) -----
    #[inline(always)]
    fn add_mod<const Q: u64>(x: u64, y: u64) -> u64 {
        const { assert!(Q.is_power_of_two()) };
        x.wrapping_add(y) & (Q - 1)
    }

    #[inline(always)]
    fn sub_mod<const Q: u64>(x: u64, y: u64) -> u64 {
        const { assert!(Q.is_power_of_two()) };
        x.wrapping_sub(y) & (Q - 1)
    }

    #[inline(always)]
    fn mul_mod<const Q: u64>(x: u64, y: u64) -> u64 {
        const { assert!(Q.is_power_of_two()) };
        x.wrapping_mul(y) & (Q - 1)
    }

    // Schoolbook negacyclic mul
    #[inline]
    fn poly_mul_negacyclic<const N: usize, const Q: u64>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut out = [0u64; N];
        let m = N - 1; // N assumed power of two in tests
        for i in 0..N {
            let ai = a[i];
            for j in 0..N {
                let sum = i + j;
                let k = sum & m;
                let prod = mul_mod::<Q>(ai, b[j]);
                if sum < N {
                    out[k] = add_mod::<Q>(out[k], prod);
                } else {
                    out[k] = sub_mod::<Q>(out[k], prod);
                }
            }
        }
        out
    }

    // ----- Test-only samplers and conversions -----
    #[inline]
    fn poly_uniform<const N: usize, const Q: u64, R: Rng>(rng: &mut R) -> [u64; N] {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = rng.random_range(0..Q);
        }
        out
    }

    #[inline]
    fn poly_error<const N: usize, const Q: u64, R: Rng, const B: i32>(rng: &mut R) -> [u64; N] {
        const { assert!(B >= 0 && B <= i16::MAX as i32) };
        let mut out = [0u64; N];
        for i in 0..N {
            let e: i32 = rng.random_range(-B..=B);
            out[i] = if e >= 0 {
                e as u64
            } else {
                sub_mod::<Q>(0, (-e) as u64)
            };
        }
        out
    }

    // ----- Test-only impls -----
    impl<const N: usize, const Q: u64> TRLWECiphertext<N, Q> {
        pub fn decrypt(&self, sk: &TFHESecretKey<N, Q>) -> [u64; N] {
            let as_prod = poly_mul_negacyclic::<N, Q>(&self.a, &sk.s);
            let mut out = self.b.clone();
            for i in 0..N {
                out[i] = add_mod::<Q>(out[i], as_prod[i]);
            }
            out
        }
    }

    impl<const N: usize, const Q: u64> TFHESecretKey<N, Q> {
        pub fn to_public_key<R: Rng, const B: i32>(&self, rng: &mut R) -> TFHEPublicKey<N, Q> {
            let a = poly_uniform::<N, Q, R>(rng);
            let mut e = poly_error::<N, Q, R, B>(rng);
            let as_prod = poly_mul_negacyclic::<N, Q>(&a, &self.s);
            for i in 0..N {
                e[i] = sub_mod::<Q>(e[i], as_prod[i]);
            }
            TFHEPublicKey { a, b: e }
        }
    }

    #[test]
    fn pk_encrypt_zero_sanity() {
        const N: usize = 1024;
        const Q: u64 = 1 << 50;
        const B: i32 = 1 << 12;
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let sk = TFHESecretKey::<N, Q>::generate(&mut rng);
        let pk = sk.to_public_key::<_, B>(&mut rng);
        let bytes: [u8; 0] = [];
        let ct = TRLWECiphertext::<N, Q>::encrypt_bits::<_, B>(&bytes, 0, &pk, &mut rng);
        let phase = ct.decrypt(&sk);

        let mut max_abs: i128 = 0;
        for &c in &phase {
            let centered = if c > Q / 2 {
                (c as i128) - (Q as i128)
            } else {
                c as i128
            };
            let a = if centered < 0 { -centered } else { centered };
            if a > max_abs {
                max_abs = a;
            }
        }
        let b = B as i128;
        let bound = (N as i128) * (b * b + b) + b;
        assert!(
            max_abs <= bound * 8,
            "pk phase too large: {} > {}",
            max_abs,
            bound * 8
        );
    }

    #[test]
    fn pk_encrypt_plaintext_decrypts_with_small_error() {
        const N: usize = 1024;
        const Q: u64 = 1 << 50;
        const B: i32 = 1 << 12;
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let sk = TFHESecretKey::<N, Q>::generate(&mut rng);
        let pk = sk.to_public_key::<_, B>(&mut rng);

        // Choose a small plaintext bitstring (LSB-first within each byte)
        let bytes = [0b1011_0010u8, 0b0000_0001u8];
        let bit_len = 12usize; // first 12 bits used
        // Expected message coefficients: 1 -> Q/4, 0 -> 0
        let one = Q / 4;
        let mut expected = [0u64; N];
        for i in 0..core::cmp::min(N, bit_len) {
            let byte = bytes[i >> 3];
            let bit = (byte >> (i & 7)) & 1;
            expected[i] = if bit != 0 { one } else { 0 };
        }

        let ct = TRLWECiphertext::<N, Q>::encrypt_bits::<_, B>(&bytes, bit_len, &pk, &mut rng);
        let m = ct.decrypt(&sk);

        let mut max_abs: i128 = 0;
        for i in 0..N {
            let diff = sub_mod::<Q>(m[i], expected[i]);
            let centered = if diff > Q / 2 {
                (diff as i128) - (Q as i128)
            } else {
                diff as i128
            };
            let a = if centered < 0 { -centered } else { centered };
            if a > max_abs {
                max_abs = a;
            }
        }
        let b = B as i128;
        let bound = (N as i128) * (b * b + b) + b;
        assert!(
            max_abs <= bound * 8,
            "error too large: {} > {}",
            max_abs,
            bound * 8
        );
    }
}
