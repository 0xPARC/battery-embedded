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
