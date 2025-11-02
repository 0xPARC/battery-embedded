use super::{HALF_FULL_ROUNDS, HASH_SIZE, PARTIAL_ROUNDS, Val, WIDTH, constants::RoundConstants};
use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear as PoseidonLayers;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[inline]
fn permute_with_constants(
    mut state: [Val; WIDTH],
    constants: &RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) -> [Val; WIDTH] {
    // External linear layer before the first full rounds, matching AIR/generation.
    PoseidonLayers::external_linear_layer(&mut state);

    // Beginning full rounds.
    for r in 0..HALF_FULL_ROUNDS {
        for i in 0..WIDTH {
            state[i] += constants.beginning_full_round_constants[r][i];
            state[i] = state[i].cube();
        }
        PoseidonLayers::external_linear_layer(&mut state);
    }

    // Partial rounds.
    for r in 0..PARTIAL_ROUNDS {
        state[0] += constants.partial_round_constants[r];
        state[0] = state[0].cube();
        PoseidonLayers::internal_linear_layer(&mut state);
    }

    // Ending full rounds.
    for r in 0..HALF_FULL_ROUNDS {
        for i in 0..WIDTH {
            state[i] += constants.ending_full_round_constants[r][i];
            state[i] = state[i].cube();
        }
        PoseidonLayers::external_linear_layer(&mut state);
    }
    state
}

/// Poseidon2 two-to-one compression consistent with the Merkle node computation.
/// Orientation is defined by argument order: state = [left || right].
pub fn parent_from_pair(left: &[Val; HASH_SIZE], right: &[Val; HASH_SIZE]) -> [Val; HASH_SIZE] {
    let mut state = [Val::from_canonical_checked(0).unwrap(); WIDTH];
    state[..HASH_SIZE].copy_from_slice(left);
    state[HASH_SIZE..2 * HASH_SIZE].copy_from_slice(right);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let out = permute_with_constants(state, &constants);
    let mut digest = [Val::from_canonical_checked(0).unwrap(); HASH_SIZE];
    digest.copy_from_slice(&out[..HASH_SIZE]);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orientation_changes_output() {
        let a = [Val::from_canonical_checked(1).unwrap(); HASH_SIZE];
        let b = [Val::from_canonical_checked(2).unwrap(); HASH_SIZE];
        let ab = parent_from_pair(&a, &b);
        let ba = parent_from_pair(&b, &a);
        assert_ne!(ab, ba);
    }
}
