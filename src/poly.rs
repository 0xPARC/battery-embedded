use rand::Rng;

// ---------------- Modular arithmetic helpers ----------------

// Const-generic helpers over fixed modulus Q
#[inline(always)]
const fn qmask<const Q: u64>() -> u64 {
    if Q.is_power_of_two() { Q - 1 } else { 0 }
}

#[inline(always)]
fn add_mod<const Q: u64>(x: u64, y: u64) -> u64 {
    const { assert!(Q > 0) };
    if Q.is_power_of_two() {
        x.wrapping_add(y) & qmask::<Q>()
    } else {
        (((x as u128) + (y as u128)) % (Q as u128)) as u64
    }
}

#[inline(always)]
pub(crate) fn sub_mod<const Q: u64>(x: u64, y: u64) -> u64 {
    const { assert!(Q > 0) };
    if Q.is_power_of_two() {
        x.wrapping_sub(y) & qmask::<Q>()
    } else {
        // (x - y) mod Q == (x + Q - y) mod Q
        (((x as u128) + (Q as u128) - (y as u128)) % (Q as u128)) as u64
    }
}

#[inline(always)]
fn mul_mod<const Q: u64>(x: u64, y: u64) -> u64 {
    const { assert!(Q > 0) };
    if Q.is_power_of_two() {
        x.wrapping_mul(y) & qmask::<Q>()
    } else {
        (((x as u128) * (y as u128)) % (Q as u128)) as u64
    }
}

#[inline(always)]
fn reduce<const Q: u64>(x: u64) -> u64 {
    const { assert!(Q > 0) };
    if Q.is_power_of_two() {
        x & qmask::<Q>()
    } else {
        x % Q
    }
}

// ---------------- Polynomial over Z/QZ[X]/(X^N+1) ----------------

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Poly<const N: usize, const Q: u64> {
    #[serde(with = "serde_big_array::BigArray")]
    pub coeffs: [u64; N],
}

impl<const N: usize, const Q: u64> Poly<N, Q> {
    #[inline]
    pub const fn zero() -> Self {
        Self { coeffs: [0u64; N] }
    }

    /// Return a + b (mod Q), computed in a single pass.
    #[inline]
    pub fn add(a: &Self, b: &Self) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = add_mod::<Q>(a.coeffs[i], b.coeffs[i]);
        }
        Poly { coeffs: out }
    }

    /// Return a + b + c (mod Q), computed in a single pass.
    #[inline]
    pub fn add3(a: &Self, b: &Self, c: &Self) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            let t = add_mod::<Q>(b.coeffs[i], c.coeffs[i]);
            out[i] = add_mod::<Q>(a.coeffs[i], t);
        }
        Poly { coeffs: out }
    }

    #[inline]
    pub fn from_u64(coeffs: [u64; N]) -> Self {
        Self { coeffs }
    }

    /// Construct a polynomial from coefficients, reducing each modulo Q (array version).
    #[inline]
    pub fn from_coeffs_mod_q_array(input: &[u64; N]) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = reduce::<Q>(input[i]);
        }
        Poly { coeffs: out }
    }

    /// Construct a polynomial from a slice of length N, reducing each modulo Q.
    /// The caller must ensure `input.len() == N`.
    #[inline]
    pub fn from_coeffs_mod_q_slice(input: &[u64]) -> Self {
        debug_assert!(input.len() == N);
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = reduce::<Q>(input[i]);
        }
        Poly { coeffs: out }
    }

    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = add_mod::<Q>(self.coeffs[i], other.coeffs[i]);
        }
    }

    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = sub_mod::<Q>(self.coeffs[i], other.coeffs[i]);
        }
    }

    // Negacyclic convolution modulo X^N + 1 in Z/QZ: c = a * b (mod X^N + 1, Q)
    // Branchless inner loop by splitting no-wrap/wrap regions.
    #[inline]
    pub fn mul_negacyclic(&self, other: &Self) -> Self {
        const { assert!(N.is_power_of_two()) }; // power of two
        let mut out = [0u64; N];
        for i in 0..N {
            let ai = self.coeffs[i];
            let limit = N - i; // first region: no wrap
            // out[i + j] += ai * other[j] for j in 0..limit
            for j in 0..limit {
                out[i + j] = add_mod::<Q>(out[i + j], mul_mod::<Q>(ai, other.coeffs[j]));
            }
            // out[i + j - N] -= ai * other[j] for j in limit..N
            for j in limit..N {
                out[i + j - N] = sub_mod::<Q>(out[i + j - N], mul_mod::<Q>(ai, other.coeffs[j]));
            }
        }
        Poly { coeffs: out }
    }

    /// Fast-path negacyclic multiply by a binary polynomial (coeffs in {0,1}).
    /// Avoids multiplications; performs rotate-and-add/sub when bin[i] == 1.
    #[inline]
    pub fn mul_negacyclic_by_binary(&self, bin: &Self) -> Self {
        const { assert!(N.is_power_of_two()) };
        let mut out = [0u64; N];
        for i in 0..N {
            if bin.coeffs[i] == 0 { continue; }
            let limit = N - i;
            // No-wrap region: out[i + j] += self[j]
            for j in 0..limit {
                out[i + j] = add_mod::<Q>(out[i + j], self.coeffs[j]);
            }
            // Wrap region: out[i + j - N] -= self[j]
            for j in limit..N {
                out[i + j - N] = sub_mod::<Q>(out[i + j - N], self.coeffs[j]);
            }
        }
        Poly { coeffs: out }
    }

    // Sampling
    #[inline]
    pub fn uniform<R: Rng>(rng: &mut R) -> Self {
        const { assert!(Q > 0) };
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = rng.random_range(0..Q);
        }
        Poly { coeffs: out }
    }

    /// Sample coefficients independently from a binary {0,1} distribution.
    #[inline]
    pub fn binary<R: Rng>(rng: &mut R) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = rng.random_range(0..2) as u64;
        }
        Poly { coeffs: out }
    }

    #[inline]
    pub fn error<R: Rng, const B: u64>(rng: &mut R) -> Self {
        const { assert!(Q > 0) };
        let mut out = [0u64; N];
        let b128: i128 = B as i128;
        for i in 0..N {
            let e: i128 = rng.random_range(-b128..=b128);
            out[i] = if e >= 0 {
                e as u64
            } else {
                sub_mod::<Q>(0, (-e) as u64)
            };
        }
        Poly { coeffs: out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        const N: usize = 8;
        const Q: u64 = 256;
        let mut a = Poly::<N, Q>::zero();
        let mut b = Poly::<N, Q>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u64 * 10) % Q;
            b.coeffs[i] = (i as u64 * 3 + 7) % Q;
        }
        let mut c = a.clone();
        c.add_assign(&b);
        c.sub_assign(&b);
        for i in 0..N {
            assert_eq!(c.coeffs[i], a.coeffs[i]);
        }
    }

    fn mul_negacyclic_naive<const N: usize, const Q: u64>(
        a: &Poly<N, Q>,
        b: &Poly<N, Q>,
    ) -> Poly<N, Q> {
        let mut out = [0u64; N];
        for i in 0..N {
            for j in 0..N {
                let prod = super::mul_mod::<Q>(a.coeffs[i], b.coeffs[j]);
                let sum = i + j;
                if sum < N {
                    out[sum] = super::add_mod::<Q>(out[sum], prod);
                } else {
                    out[sum - N] = super::sub_mod::<Q>(out[sum - N], prod);
                }
            }
        }
        Poly { coeffs: out }
    }

    #[test]
    fn mul_negacyclic_matches_naive_power_of_two() {
        const N: usize = 8; // power of two to hit specialization
        const Q: u64 = 256;
        let mut a = Poly::<N, Q>::zero();
        let mut b = Poly::<N, Q>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u64 * 5 + 1) % Q;
            b.coeffs[i] = (i as u64 * 7 + 2) % Q;
        }
        let got = a.mul_negacyclic(&b);
        let exp = mul_negacyclic_naive(&a, &b);
        for i in 0..N {
            assert_eq!(got.coeffs[i], exp.coeffs[i]);
        }
    }
}
