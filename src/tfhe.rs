// Minimal no_std TFHE TRLWE public-key encryption.
// Mirrors the reference logic in tfhe/src/tfhe/trlwe.py for public-key encryption,
// using u64 coefficients with a general modulus Q and uniform-bounded errors.

use rand::Rng;

// ---------------- Modular arithmetic helpers (u64, arbitrary Q) ----------------

#[inline(always)]
fn add_mod_u64(x: u64, y: u64, q: u64) -> u64 {
    debug_assert!(q > 0);
    if q.is_power_of_two() {
        (x.wrapping_add(y)) & (q - 1)
    } else {
        (((x as u128) + (y as u128)) % (q as u128)) as u64
    }
}

#[inline(always)]
fn sub_mod_u64(x: u64, y: u64, q: u64) -> u64 {
    debug_assert!(q > 0);
    if q.is_power_of_two() {
        (x.wrapping_sub(y)) & (q - 1)
    } else {
        // (x - y) mod q  ==  (x + q - y) mod q
        (((x as u128) + (q as u128) - (y as u128)) % (q as u128)) as u64
    }
}

#[inline(always)]
fn mul_mod_u64(x: u64, y: u64, q: u64) -> u64 {
    debug_assert!(q > 0);
    if q.is_power_of_two() {
        (x.wrapping_mul(y)) & (q - 1)
    } else {
        ((x as u128 * y as u128) % (q as u128)) as u64
    }
}

// ---------------- Polynomial over Z/QZ[X]/(X^N+1) ----------------

#[derive(Clone)]
pub struct Poly<const N: usize, const Q: u64> {
    pub coeffs: [u64; N],
}

impl<const N: usize, const Q: u64> Poly<N, Q> {
    #[inline]
    pub const fn zero() -> Self {
        Self { coeffs: [0u64; N] }
    }

    #[inline]
    pub fn from_u64(coeffs: [u64; N]) -> Self {
        Self { coeffs }
    }

    /// Construct a polynomial from coefficients, reducing each modulo Q (array version).
    #[inline]
    pub fn from_coeffs_mod_q_array(input: &[u64; N]) -> Self {
        let mut out = [0u64; N];
        if Q.is_power_of_two() {
            let mask = Q - 1;
            for i in 0..N {
                out[i] = input[i] & mask;
            }
        } else {
            for i in 0..N {
                out[i] = input[i] % Q;
            }
        }
        Poly { coeffs: out }
    }

    /// Construct a polynomial from a slice of length N, reducing each modulo Q.
    /// The caller must ensure `input.len() == N`.
    #[inline]
    pub fn from_coeffs_mod_q_slice(input: &[u64]) -> Self {
        debug_assert!(input.len() == N);
        let mut out = [0u64; N];
        if Q.is_power_of_two() {
            let mask = Q - 1;
            for i in 0..N {
                out[i] = input[i] & mask;
            }
        } else {
            for i in 0..N {
                out[i] = input[i] % Q;
            }
        }
        Poly { coeffs: out }
    }

    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = add_mod_u64(self.coeffs[i], other.coeffs[i], Q);
        }
    }

    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = sub_mod_u64(self.coeffs[i], other.coeffs[i], Q);
        }
    }

    // Negacyclic convolution modulo X^N + 1 in Z/QZ: c = a * b (mod X^N + 1, Q)
    #[inline]
    pub fn mul_negacyclic(&self, other: &Self) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            let ai = self.coeffs[i];
            let limit = N - i; // indices where i + j < N → add
            for j in 0..limit {
                let prod = mul_mod_u64(ai, other.coeffs[j], Q);
                let k = i + j;
                out[k] = add_mod_u64(out[k], prod, Q);
            }
            for j in limit..N {
                // wrap-around subtract
                let prod = mul_mod_u64(ai, other.coeffs[j], Q);
                let k = i + j - N;
                out[k] = sub_mod_u64(out[k], prod, Q);
            }
        }
        Poly { coeffs: out }
    }

    // Sampling
    #[inline]
    pub fn uniform<R: Rng>(rng: &mut R) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = rng.random_range(0..Q);
        }
        Poly { coeffs: out }
    }

    #[inline]
    pub fn error<R: Rng, const B: i64>(rng: &mut R) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            let e: i64 = rng.random_range(-B..=B);
            out[i] = if e >= 0 {
                e as u64
            } else {
                sub_mod_u64(0, (-e) as u64, Q)
            };
        }
        Poly { coeffs: out }
    }
}

pub type TRLWEPlaintext<const N: usize, const Q: u64> = Poly<N, Q>;

// ---------------- Keys and ciphertext ----------------

#[cfg(test)]
pub struct TFHESecretKey<const N: usize, const Q: u64> {
    pub s: Poly<N, Q>,
}

#[cfg(test)]
impl<const N: usize, const Q: u64> TFHESecretKey<N, Q> {
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let mut coeffs = [0u64; N];
        for i in 0..N {
            coeffs[i] = rng.random_range(0..2) as u64;
        }
        Self { s: Poly { coeffs } }
    }
}

#[derive(Clone)]
pub struct TRLWECiphertext<const N: usize, const Q: u64> {
    pub a: Poly<N, Q>,
    pub b: Poly<N, Q>,
}

#[derive(Clone)]
pub struct TFHEPublicKey<const N: usize, const Q: u64> {
    pub ct: TRLWECiphertext<N, Q>,
}

impl<const N: usize, const Q: u64> TRLWECiphertext<N, Q> {
    #[cfg(test)]
    pub fn decrypt(&self, sk: &TFHESecretKey<N, Q>) -> Poly<N, Q> {
        let as_prod = self.a.mul_negacyclic(&sk.s);
        let mut out = self.b.clone();
        out.add_assign(&as_prod);
        out
    }

    #[inline]
    pub fn encrypt_with_public_key<R: Rng, const B: i64>(
        pt: &TRLWEPlaintext<N, Q>,
        pk: &TFHEPublicKey<N, Q>,
        rng: &mut R,
    ) -> Self {
        let u = Poly::<N, Q>::error::<R, B>(rng);
        let a_scaled = pk.ct.a.mul_negacyclic(&u);
        let b_scaled = pk.ct.b.mul_negacyclic(&u);
        let e1 = Poly::<N, Q>::error::<R, B>(rng);
        let e2 = Poly::<N, Q>::error::<R, B>(rng);
        let mut a = a_scaled;
        a.add_assign(&e1);
        let mut b = b_scaled;
        b.add_assign(&e2);
        b.add_assign(pt);
        TRLWECiphertext { a, b }
    }
}

impl<const N: usize, const Q: u64> TFHEPublicKey<N, Q> {
    #[cfg(test)]
    pub fn from_secret_key<R: Rng, const B: i64>(sk: &TFHESecretKey<N, Q>, rng: &mut R) -> Self {
        let a = Poly::<N, Q>::uniform(rng);
        let e = Poly::<N, Q>::error::<R, B>(rng);
        let as_prod = a.mul_negacyclic(&sk.s);
        let mut b = e.clone();
        b.sub_assign(&as_prod);
        TFHEPublicKey {
            ct: TRLWECiphertext { a, b },
        }
    }
}

// ---------------- Tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn pk_encrypt_zero_sanity() {
        const N: usize = 32;
        const Q: u64 = 1_000_000_000;
        const B: i64 = 10;
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let sk = TFHESecretKey::<N, Q>::generate(&mut rng);
        let pk = TFHEPublicKey::<N, Q>::from_secret_key::<_, B>(&sk, &mut rng);
        let pt0 = TRLWEPlaintext::<N, Q>::zero();
        let ct = TRLWECiphertext::<N, Q>::encrypt_with_public_key::<_, B>(&pt0, &pk, &mut rng);
        let phase = ct.decrypt(&sk);

        let mut max_abs: i128 = 0;
        for &c in &phase.coeffs {
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
        let bound = (N as i128) * ((B as i128) * (B as i128) + (B as i128)) + (B as i128);
        assert!(
            max_abs <= bound * 8,
            "pk phase too large: {} > {}",
            max_abs,
            bound * 8
        );
    }

    #[test]
    fn pk_encrypt_plaintext_decrypts_with_small_error() {
        const N: usize = 64;
        const Q: u64 = 4_000_000_000;
        const B: i64 = 10;
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let sk = TFHESecretKey::<N, Q>::generate(&mut rng);
        let pk = TFHEPublicKey::<N, Q>::from_secret_key::<_, B>(&sk, &mut rng);

        let mut pt = TRLWEPlaintext::<N, Q>::zero();
        for i in 0..N {
            pt.coeffs[i] = if i % 4 >= 2 { Q / 2 } else { 0 };
        }

        let ct = TRLWECiphertext::<N, Q>::encrypt_with_public_key::<_, B>(&pt, &pk, &mut rng);
        let phase = ct.decrypt(&sk);

        let mut max_abs: i128 = 0;
        for i in 0..N {
            let diff = sub_mod_u64(phase.coeffs[i], pt.coeffs[i], Q);
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
        let bound = (N as i128) * ((B as i128) * (B as i128) + (B as i128)) + (B as i128);
        assert!(
            max_abs <= bound * 8,
            "error too large: {} > {}",
            max_abs,
            bound * 8
        );
    }
}
