// Minimal no_std TFHE TRLWE public-key encryption.
// using u64 coefficients with a general modulus Q and uniform-bounded errors.

use crate::poly::Poly;
use rand::Rng;

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
    use crate::poly::sub_mod_u64;

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
        let m = ct.decrypt(&sk);

        let mut max_abs: i128 = 0;
        for i in 0..N {
            let diff = sub_mod_u64(m.coeffs[i], pt.coeffs[i], Q);
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
