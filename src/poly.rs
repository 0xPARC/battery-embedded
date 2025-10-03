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
pub fn sub_mod_u64(x: u64, y: u64, q: u64) -> u64 {
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

// Serde for Poly<N, Q>: serialize as a sequence of N u64s.
// Enabled under the `ffi` feature since opaque FFI uses postcard.
#[cfg(feature = "ffi")]
impl<const N: usize, const Q: u64> serde::Serialize for Poly<N, Q> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(N))?;
        for i in 0..N {
            seq.serialize_element(&self.coeffs[i])?;
        }
        seq.end()
    }
}

#[cfg(feature = "ffi")]
impl<'de, const N: usize, const Q: u64> serde::Deserialize<'de> for Poly<N, Q> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PolyVisitor<const N: usize, const Q: u64>;
        impl<'de, const N: usize, const Q: u64> serde::de::Visitor<'de> for PolyVisitor<N, Q> {
            type Value = Poly<N, Q>;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "sequence of {} u64 coefficients", N)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut coeffs = [0u64; N];
                for i in 0..N {
                    coeffs[i] = match seq.next_element::<u64>()? {
                        Some(v) => v,
                        None => return Err(serde::de::Error::invalid_length(i, &self)),
                    };
                }
                // Ensure there are no extra elements
                if let Some(_) = seq.next_element::<serde::de::IgnoredAny>()? {
                    return Err(serde::de::Error::custom("too many coefficients"));
                }
                Ok(Poly { coeffs })
            }
        }
        deserializer.deserialize_seq(PolyVisitor::<N, Q>)
    }
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
        // Specialized path for power-of-two N: single loop with bitmask wrap
        if (N & (N - 1)) == 0 {
            let mask = N - 1;
            for i in 0..N {
                let ai = self.coeffs[i];
                for j in 0..N {
                    let prod = mul_mod_u64(ai, other.coeffs[j], Q);
                    let sum = i + j;
                    let k = sum & mask;
                    if sum < N {
                        out[k] = add_mod_u64(out[k], prod, Q);
                    } else {
                        out[k] = sub_mod_u64(out[k], prod, Q);
                    }
                }
            }
            return Poly { coeffs: out };
        }
        // General path
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

    fn mul_negacyclic_naive<const N: usize, const Q: u64>(a: &Poly<N, Q>, b: &Poly<N, Q>) -> Poly<N, Q> {
        let mut out = [0u64; N];
        for i in 0..N {
            for j in 0..N {
                let prod = ((a.coeffs[i] as u128 * b.coeffs[j] as u128) % Q as u128) as u64;
                let sum = i + j;
                if sum < N {
                    out[sum] = super::add_mod_u64(out[sum], prod, Q);
                } else {
                    out[sum - N] = super::sub_mod_u64(out[sum - N], prod, Q);
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

    #[test]
    fn mul_negacyclic_matches_naive_non_power_of_two() {
        const N: usize = 6; // general path
        const Q: u64 = 1009; // prime to exercise non-2^k path
        let mut a = Poly::<N, Q>::zero();
        let mut b = Poly::<N, Q>::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u64 * 9 + 3) % Q;
            b.coeffs[i] = (i as u64 * 4 + 5) % Q;
        }
        let got = a.mul_negacyclic(&b);
        let exp = mul_negacyclic_naive(&a, &b);
        for i in 0..N {
            assert_eq!(got.coeffs[i], exp.coeffs[i]);
        }
    }
}
