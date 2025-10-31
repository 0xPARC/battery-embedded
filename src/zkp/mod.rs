//use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField, integers::QuotientMap};
use p3_fri::{HidingFriPcs, create_benchmark_fri_params_zk};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2::poseidon2_round_numbers_128;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use air::MerkleInclusionAir;
use constants::RoundConstants;

use super::Vec;

pub mod air;
pub mod constants;
pub mod generation;

pub const WIDTH: usize = 16;
pub const HASH_SIZE: usize = 8;

// BabyBear parameters
// BabyBear seems to use about 5% more memory than KoalaBear
// const SBOX_DEGREE: u64 = 7;
// const SBOX_REGISTERS: usize = 1;

// KoalaBear parameters
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;

const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = match poseidon2_round_numbers_128::<Val>(WIDTH, SBOX_DEGREE) {
    Ok((_, partial)) => partial,
    Err(_) => panic!("Failed to get number of rounds"),
};

pub type Val = KoalaBear;
type PoseidonLayers = GenericPoseidon2LinearLayersKoalaBear;
type Dft = p3_dft::Radix2Dit<Val>;
type Challenge = BinomialExtensionField<Val, 4>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, ChaCha20Rng>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    ChaCha20Rng,
    4,
    4,
>;

pub type MerkleInclusionConfig = StarkConfig<Pcs, Challenge, Challenger>;
pub type MerkleInclusionProof = Proof<MerkleInclusionConfig>;

pub fn nonce_field_rep(nonce: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_int(u32::from_le_bytes(
            nonce[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}

/// Compute the Poseidon2-based leaf commitment from a secret (8 field elements).
/// This mirrors the leaf hashing row used inside the AIR: Poseidon2(state = [zeros(8) || secret(8)]).
pub fn leaf_from_secret(secret: &[Val; 8]) -> [Val; 8] {
    use p3_poseidon2::GenericPoseidon2LinearLayers;
    type Layers = PoseidonLayers;
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let constants: RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> =
        RoundConstants::from_rng(&mut rng);
    // Build initial state as in the circuit: [zeros || secret]
    let mut state = [Val::from_canonical_checked(0).unwrap(); WIDTH];
    state[WIDTH - 8..WIDTH].copy_from_slice(secret);
    Layers::external_linear_layer(&mut state);
    // Beginning full rounds
    for r in 0..HALF_FULL_ROUNDS {
        for i in 0..WIDTH {
            state[i] += constants.beginning_full_round_constants[r][i];
            // S-box degree is SBOX_DEGREE with SBOX_REGISTERS=0 in our config
            state[i] = match SBOX_DEGREE {
                3 => state[i].cube(),
                5 => state[i].exp_const_u64::<5>(),
                7 => state[i].exp_const_u64::<7>(),
                _ => panic!("Unsupported SBOX_DEGREE {}", SBOX_DEGREE),
            };
        }
        Layers::external_linear_layer(&mut state);
    }
    // Partial rounds
    for r in 0..PARTIAL_ROUNDS {
        state[0] += constants.partial_round_constants[r];
        state[0] = match SBOX_DEGREE {
            3 => state[0].cube(),
            5 => state[0].exp_const_u64::<5>(),
            7 => state[0].exp_const_u64::<7>(),
            _ => unreachable!(),
        };
        Layers::internal_linear_layer(&mut state);
    }
    // Ending full rounds
    for r in 0..HALF_FULL_ROUNDS {
        for i in 0..WIDTH {
            state[i] += constants.ending_full_round_constants[r][i];
            state[i] = match SBOX_DEGREE {
                3 => state[i].cube(),
                5 => state[i].exp_const_u64::<5>(),
                7 => state[i].exp_const_u64::<7>(),
                _ => unreachable!(),
            };
        }
        Layers::external_linear_layer(&mut state);
    }
    let mut out = [Val::from_canonical_checked(0).unwrap(); 8];
    out.copy_from_slice(&state[WIDTH - 8..WIDTH]);
    out
}

pub fn generate_proof(
    secret: &[Val; 8],
    neighbors: &[([Val; 8], bool)],
    nonce: &[u8; 32],
) -> (MerkleInclusionProof, Vec<Val>) {
    let byte_hash = ByteHash {};

    let u64_hash = U64Hash::new(KeccakF {});

    let field_hash = FieldHash::new(u64_hash);

    let compress = MyCompress::new(u64_hash);

    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let val_mmcs = ValMmcs::new(field_hash, compress, rng);

    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let challenger = Challenger::from_hasher(nonce.to_vec(), byte_hash);

    let air = MerkleInclusionAir::<
        Val,
        PoseidonLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >::new(constants);

    let fri_params = create_benchmark_fri_params_zk(challenge_mmcs);

    let nonce_field = nonce_field_rep(nonce);
    // Sanity: neighbors.len() + 2 must be power-of-two for the radix-2 FFTs
    debug_assert!((neighbors.len() + 2).is_power_of_two());
    let trace = air.generate_trace_rows(secret, neighbors, &nonce_field);
    // PV layout: [root(8) | nonce_field(8) | hash(leaf||nonce)(8)]
    let mut public_values = trace.row_slice(trace.height() - 1).unwrap()
        [trace.width() - WIDTH..trace.width() - WIDTH + HASH_SIZE]
        .to_vec();
    public_values.extend_from_slice(&nonce_field);
    // PV[16..24] = binding hash from row 1 output (last 8 words)
    {
        let row1 = trace.row_slice(1).unwrap();
        let binding: Vec<Val> = row1[row1.len() - WIDTH..row1.len() - WIDTH + HASH_SIZE].to_vec();
        public_values.extend_from_slice(&binding);
    }

    let dft = Dft::default();

    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, ChaCha20Rng::from_seed(*nonce));

    let config = MerkleInclusionConfig::new(pcs, challenger);

    let proof = prove(&config, &air, trace, &public_values);
    (proof, public_values)
}

pub fn verify_proof(
    nonce: &[u8; 32],
    proof: &MerkleInclusionProof,
    public_values: &Vec<Val>,
) -> Result<
    (),
    p3_uni_stark::VerificationError<
        p3_fri::verifier::FriError<
            p3_merkle_tree::MerkleTreeError,
            p3_merkle_tree::MerkleTreeError,
        >,
    >,
> {
    let byte_hash = ByteHash {};

    let u64_hash = U64Hash::new(KeccakF {});

    let field_hash = FieldHash::new(u64_hash);

    let compress = MyCompress::new(u64_hash);

    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let val_mmcs = ValMmcs::new(field_hash, compress, rng);

    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let challenger = Challenger::from_hasher(nonce.to_vec(), byte_hash);

    let air = MerkleInclusionAir::<
        Val,
        PoseidonLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >::new(constants);

    let fri_params = create_benchmark_fri_params_zk(challenge_mmcs);

    let dft = Dft::default();

    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, ChaCha20Rng::from_seed(*nonce));

    let config = MerkleInclusionConfig::new(pcs, challenger);

    verify(&config, &air, proof, public_values)
}

#[cfg(test)]
mod test {
    use p3_field::integers::QuotientMap;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    type TestAir = MerkleInclusionAir<
        Val,
        PoseidonLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;

    fn build_fixture(
        secret: &[Val; 8],
        neighbors: &[([Val; 8], bool)],
        nonce: &[u8; 32],
    ) -> (
        MerkleInclusionConfig,
        TestAir,
        RowMajorMatrix<Val>,
        Vec<Val>,
    ) {
        let byte_hash = ByteHash {};
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = MyCompress::new(u64_hash);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let constants = RoundConstants::from_rng(&mut rng);
        let val_mmcs = ValMmcs::new(field_hash, compress, rng);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let challenger = Challenger::from_hasher(nonce.to_vec(), byte_hash);
        let air = TestAir::new(constants);
        let fri_params = create_benchmark_fri_params_zk(challenge_mmcs);
        let dft = Dft::default();
        let pcs = Pcs::new(
            dft,
            val_mmcs,
            fri_params,
            4,
            rand_chacha::ChaCha20Rng::from_seed(nonce.clone()),
        );
        let config = MerkleInclusionConfig::new(pcs, challenger);

        let nonce_field = nonce_field_rep(nonce);
        let trace = air.generate_trace_rows(secret, neighbors, &nonce_field);
        let mut pv = trace.row_slice(trace.height() - 1).unwrap()
            [trace.width() - WIDTH..trace.width() - WIDTH + HASH_SIZE]
            .to_vec();
        pv.extend_from_slice(&nonce_field);
        // Copy binding hash (row 1) before moving the trace
        let row1_binding: Vec<Val> = {
            let row1 = trace.row_slice(1).unwrap();
            row1[row1.len() - WIDTH..row1.len() - WIDTH + HASH_SIZE].to_vec()
        };
        pv.extend_from_slice(&row1_binding);
        (config, air, trace, pv)
    }

    #[test]
    fn test_root_independent_of_nonce() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce1 = [0; 32];
        let nonce2 = [1; 32];
        let (_, public1) = generate_proof(&secret, &neighbors, &nonce1);
        let (_, public2) = generate_proof(&secret, &neighbors, &nonce2);
        let nonce_field1 = nonce_field_rep(&nonce1);
        let nonce_field2 = nonce_field_rep(&nonce2);
        assert_eq!(public1[0..8], public2[0..8]);
        assert_eq!(public1[8..16], nonce_field1);
        assert_eq!(public2[8..16], nonce_field2);
        assert_ne!(public1[16..24], public2[16..24]);
    }

    #[test]
    fn test_hash_nonce_leaf_independent_of_neighbors() {
        // Keeping secret and nonce constant while changing neighbors should:
        // - Change the Merkle root (PV[0..8])
        // - Keep the nonce field rep the same (PV[8..16])
        // - Keep hash(leaf(secret)||nonce) the same (PV[16..24])
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors1 = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let mut neighbors2 = [([Val::from_canonical_checked(5).unwrap(); 8], true); 30];
        neighbors2[0].1 = false; // small variation in side flags
        let nonce = [7u8; 32];

        let (_, public1) = generate_proof(&secret, &neighbors1, &nonce);
        let (_, public2) = generate_proof(&secret, &neighbors2, &nonce);

        // Nonce field rep identical
        assert_eq!(&public1[8..16], &public2[8..16]);
        // hash(leaf||nonce) identical
        assert_eq!(&public1[16..24], &public2[16..24]);
        // Merkle root should differ when neighbors differ
        assert_ne!(&public1[0..8], &public2[0..8]);
    }

    #[test]
    fn test_hash_nonce_leaf_depends_on_nonce_and_leaf() {
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];

        // Change in nonce should change PV[16..24]
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let nonce_a = [1u8; 32];
        let nonce_b = [2u8; 32];
        let (_, pv_a) = generate_proof(&secret, &neighbors, &nonce_a);
        let (_, pv_b) = generate_proof(&secret, &neighbors, &nonce_b);
        assert_ne!(&pv_a[16..24], &pv_b[16..24]);

        // Change in leaf(secret) should change PV[16..24] (same nonce)
        let mut secret2 = secret;
        secret2[0] = Val::from_canonical_checked(5).unwrap();
        let (_, pv_c) = generate_proof(&secret2, &neighbors, &nonce_a);
        assert_ne!(&pv_a[16..24], &pv_c[16..24]);
    }

    #[test]
    fn test_verify_proof_1() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [0; 32];
        let (proof, public_values) = generate_proof(&secret, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).unwrap();
    }

    #[test]
    fn test_verify_proof_2() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let mut neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], true); 30];
        neighbors[0].1 = false;
        let nonce = [0; 32];
        let (proof, public_values) = generate_proof(&secret, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).unwrap();
    }

    #[test]
    fn verifier_should_reject_inconsistent_nonce_public_values() {
        // Build a valid proof first
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [7u8; 32];
        let (proof, public_values) = generate_proof(&secret, &neighbors, &nonce);

        // Tamper with the public values after proving: flip one value in the
        // nonce field region or the hash(leaf||nonce) region. Either should fail.
        let one = Val::from_canonical_checked(1).unwrap();

        // Case 1: change nonce field rep (PV[8..16])
        let mut pv_bad = public_values.clone();
        pv_bad[8] = pv_bad[8] + one;
        assert!(verify_proof(&nonce, &proof, &pv_bad).is_err());

        // Case 2: change hash(leaf||nonce) (PV[16..24])
        let mut pv_bad2 = public_values.clone();
        pv_bad2[16] = pv_bad2[16] + one;
        assert!(verify_proof(&nonce, &proof, &pv_bad2).is_err());
    }

    #[test]
    #[should_panic]
    fn prove_fails_when_forging_root() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&secret, &neighbors, &nonce);
        pv[0] = pv[0] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    #[should_panic]
    fn prove_fails_when_forging_nonce_field() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&secret, &neighbors, &nonce);
        pv[8] = pv[8] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    #[should_panic]
    fn prove_fails_when_forging_hash() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&secret, &neighbors, &nonce);
        pv[16] = pv[16] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    fn proof_postcard_roundtrip_verifies() {
        use postcard::{from_bytes, to_allocvec};
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [5u8; 32];
        let (proof, public_values) = generate_proof(&secret, &neighbors, &nonce);
        let bytes = to_allocvec(&proof).unwrap();
        let proof2: MerkleInclusionProof = from_bytes(&bytes).unwrap();
        verify_proof(&nonce, &proof2, &public_values).expect("verify after roundtrip");
    }

    #[test]
    fn proof_verifies() {
        let secret = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [9u8; 32];
        let (proof, public_values) = generate_proof(&secret, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).expect("verify ok");
    }

    #[test]
    fn leaf_from_secret_matches_air_row0() {
        // Build a non-trivial secret with increasing canonical limbs 1..=8
        let secret: [Val; 8] = core::array::from_fn(|i| {
            Val::from_canonical_checked((i as u32) + 1).unwrap()
        });
        // 30 levels -> rows = 32 (power of two), neighbors[0].1 must be false
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 30];
        let nonce = [0xABu8; 32];

        let (_, _, trace, _) = build_fixture(&secret, &neighbors, &nonce);

        // Row 1 second input (indices [HASH_SIZE..2*HASH_SIZE]) is populated with
        // the leaf computed from row 0 inside generate_trace_rows.
        let row1 = trace.row_slice(1).unwrap();
        let mut leaf_from_air = [Val::from_canonical_checked(0).unwrap(); 8];
        leaf_from_air.copy_from_slice(&row1[HASH_SIZE..(2 * HASH_SIZE)]);

        let leaf_expected = leaf_from_secret(&secret);
        assert_eq!(leaf_from_air, leaf_expected);
    }
}
