//use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::{extension::BinomialExtensionField, integers::QuotientMap};
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
pub mod hash;

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

pub fn generate_proof(
    leaf: &[Val; 8],
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
    // Sanity: neighbors.len() + 1 must be power-of-two for the radix-2 FFTs
    debug_assert!((neighbors.len() + 1).is_power_of_two());
    let trace = air.generate_trace_rows(leaf, neighbors, &nonce_field);
    let mut public_values: Vec<Val> = Vec::with_capacity(3 * HASH_SIZE);
    {
        let last_row = trace.row_slice(trace.height() - 1).unwrap();
        let start = trace.width() - WIDTH;
        let end = start + HASH_SIZE;
        public_values.extend_from_slice(&last_row[start..end]);
        public_values.extend_from_slice(&nonce_field);
        public_values.extend_from_slice(&trace.values[start..end]);
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
        leaf: &[Val; 8],
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
        let trace = air.generate_trace_rows(leaf, neighbors, &nonce_field);
        let mut pv: Vec<Val> = Vec::with_capacity(3 * HASH_SIZE);
        {
            let last_row = trace.row_slice(trace.height() - 1).unwrap();
            let start = trace.width() - WIDTH;
            let end = start + HASH_SIZE;
            pv.extend_from_slice(&last_row[start..end]);
            pv.extend_from_slice(&nonce_field);
            pv.extend_from_slice(&trace.values[start..end]);
        }
        (config, air, trace, pv)
    }

    #[test]
    fn test_root_independent_of_nonce() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce1 = [0; 32];
        let nonce2 = [1; 32];
        let (_, public1) = generate_proof(&leaf, &neighbors, &nonce1);
        let (_, public2) = generate_proof(&leaf, &neighbors, &nonce2);
        let nonce_field1 = nonce_field_rep(&nonce1);
        let nonce_field2 = nonce_field_rep(&nonce2);
        assert_eq!(public1[0..8], public2[0..8]);
        assert_eq!(public1[8..16], nonce_field1);
        assert_eq!(public2[8..16], nonce_field2);
        assert_ne!(public1[16..24], public2[16..24]);
    }

    #[test]
    fn test_hash_nonce_leaf_independent_of_neighbors() {
        // Keeping leaf and nonce constant while changing neighbors should:
        // - Change the Merkle root (PV[0..8])
        // - Keep the nonce field rep the same (PV[8..16])
        // - Keep hash(leaf||nonce) the same (PV[16..24])
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors1 = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let mut neighbors2 = [([Val::from_canonical_checked(5).unwrap(); 8], true); 31];
        neighbors2[0].1 = false; // small variation in side flags
        let nonce = [7u8; 32];

        let (_, public1) = generate_proof(&leaf, &neighbors1, &nonce);
        let (_, public2) = generate_proof(&leaf, &neighbors2, &nonce);

        // Nonce field rep identical
        assert_eq!(&public1[8..16], &public2[8..16]);
        // hash(leaf||nonce) identical
        assert_eq!(&public1[16..24], &public2[16..24]);
        // Merkle root should differ when neighbors differ
        assert_ne!(&public1[0..8], &public2[0..8]);
    }

    #[test]
    fn test_hash_nonce_leaf_depends_on_nonce_and_leaf() {
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];

        // Change in nonce should change PV[16..24]
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let nonce_a = [1u8; 32];
        let nonce_b = [2u8; 32];
        let (_, pv_a) = generate_proof(&leaf, &neighbors, &nonce_a);
        let (_, pv_b) = generate_proof(&leaf, &neighbors, &nonce_b);
        assert_ne!(&pv_a[16..24], &pv_b[16..24]);

        // Change in leaf should change PV[16..24] (same nonce)
        let mut leaf2 = leaf;
        leaf2[0] = Val::from_canonical_checked(5).unwrap();
        let (_, pv_c) = generate_proof(&leaf2, &neighbors, &nonce_a);
        assert_ne!(&pv_a[16..24], &pv_c[16..24]);
    }

    #[test]
    fn test_verify_proof_1() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [0; 32];
        let (proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).unwrap();
    }

    #[test]
    fn test_verify_proof_2() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let mut neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], true); 31];
        neighbors[0].1 = false;
        let nonce = [0; 32];
        let (proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).unwrap();
    }

    #[test]
    fn verifier_should_reject_inconsistent_nonce_public_values() {
        // Build a valid proof first
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [7u8; 32];
        let (proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);

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
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&leaf, &neighbors, &nonce);
        pv[0] = pv[0] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    #[should_panic]
    fn prove_fails_when_forging_nonce_field() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&leaf, &neighbors, &nonce);
        pv[8] = pv[8] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    #[should_panic]
    fn prove_fails_when_forging_hash() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [7u8; 32];
        let (config, air, trace, mut pv) = build_fixture(&leaf, &neighbors, &nonce);
        pv[16] = pv[16] + Val::from_canonical_checked(1).unwrap();
        let _ = prove(&config, &air, trace, &pv);
    }

    #[test]
    fn proof_postcard_roundtrip_verifies() {
        use postcard::{from_bytes, to_allocvec};
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [5u8; 32];
        let (proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        let bytes = to_allocvec(&proof).unwrap();
        let proof2: MerkleInclusionProof = from_bytes(&bytes).unwrap();
        verify_proof(&nonce, &proof2, &public_values).expect("verify after roundtrip");
    }

    #[test]
    fn proof_verifies() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 31];
        let nonce = [9u8; 32];
        let (proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        verify_proof(&nonce, &proof, &public_values).expect("verify ok");
    }

    #[test]
    fn merkle_root_matches_hash_utils() {
        use crate::zkp::hash::parent_from_pair;

        // Build a path: parent = H(leaf || sibling), then 30 levels to root.
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let sibling = [Val::from_canonical_checked(3).unwrap(); 8];
        let levels_above_parent = 30usize; // rows = 32 = neighbors.len() + 1
        let mut neighbors: Vec<([Val; 8], bool)> = Vec::with_capacity(levels_above_parent + 1);
        neighbors.push((sibling, false));
        for i in 0..levels_above_parent {
            let is_left = i % 2 == 0;
            let val = if is_left { 5 } else { 6 };
            neighbors.push(([Val::from_canonical_checked(val).unwrap(); 8], is_left));
        }

        // Compute expected root by folding with our hash utils.
        let mut digest = parent_from_pair(&leaf, &sibling);
        for i in 1..neighbors.len() {
            let (ref n, is_left) = neighbors[i];
            digest = if is_left { parent_from_pair(n, &digest) } else { parent_from_pair(&digest, n) };
        }
        let expected_root = digest;

        // Prove and compare PV[0..HASH_SIZE] with expected root.
        let nonce = [7u8; 32];
        let (_proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        assert_eq!(&public_values[0..HASH_SIZE], &expected_root[..]);
    }

    #[test]
    fn row0_hash_equals_helper() {
        use crate::zkp::hash::parent_from_pair;

        let leaf = core::array::from_fn(|i| Val::from_canonical_checked((i as u32) + 1).unwrap());
        let sibling = [Val::from_canonical_checked(2).unwrap(); 8];
        let neighbors = [(sibling, false)]; // rows = 2 (power of two)
        let nonce = [0xABu8; 32];
        let (.., public_values) = generate_proof(&leaf, &neighbors, &nonce);
        let nonce_field = nonce_field_rep(&nonce);
        let expected_row0 = parent_from_pair(&leaf, &nonce_field);
        assert_eq!(&public_values[2 * HASH_SIZE..3 * HASH_SIZE], &expected_row0);
    }

    #[test]
    fn zero_level_path_parent_is_root() {
        use crate::zkp::hash::parent_from_pair;
        let leaf = [Val::from_canonical_checked(7).unwrap(); 8];
        let sibling = [Val::from_canonical_checked(11).unwrap(); 8];
        let neighbors = [(sibling, false)]; // parent is the root
        let nonce = [3u8; 32];
        let (_proof, public_values) = generate_proof(&leaf, &neighbors, &nonce);
        let expected_root = parent_from_pair(&leaf, &sibling);
        assert_eq!(&public_values[0..HASH_SIZE], &expected_root);
        verify_proof(&nonce, &_proof, &public_values).expect("verify ok for rows=2");
    }

    #[test]
    fn orientation_strictness_changes_root() {
        // Build two paths with the same neighbor values but opposite side flags.
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let sibling = [Val::from_canonical_checked(3).unwrap(); 8];
        let levels_above_parent = 30usize; // rows = 32

        let mut neighbors_a: Vec<([Val; 8], bool)> = Vec::with_capacity(levels_above_parent + 1);
        neighbors_a.push((sibling, false));
        for i in 0..levels_above_parent {
            let is_left = i % 2 == 0; // mix of left/right
            let val = if is_left { 5 } else { 6 };
            neighbors_a.push(([Val::from_canonical_checked(val).unwrap(); 8], is_left));
        }
        let mut neighbors_b = neighbors_a.clone();
        for i in 1..neighbors_b.len() {
            neighbors_b[i].1 = !neighbors_b[i].1; // flip sides
        }
        let nonce = [0x55u8; 32];
        let (_proof_a, pv_a) = generate_proof(&leaf, &neighbors_a, &nonce);
        let (_proof_b, pv_b) = generate_proof(&leaf, &neighbors_b, &nonce);
        assert_ne!(&pv_a[0..HASH_SIZE], &pv_b[0..HASH_SIZE]);
    }

    #[test]
    fn single_step_air_matches_hash() {
        use crate::zkp::hash::parent_from_pair;
        use p3_matrix::Matrix;
        // Prepare a single-step Merkle fold (rows=2)
        let leaf = [Val::from_canonical_checked(8).unwrap(); 8];
        let sibling = [Val::from_canonical_checked(9).unwrap(); 8];
        let neighbors = [(sibling, false)];
        let nonce = [0x77u8; 32];

        let (_config, _air, trace, _pv) = build_fixture(&leaf, &neighbors, &nonce);
        let expected = parent_from_pair(&leaf, &sibling);
        let last_row = trace.row_slice(trace.height() - 1).unwrap();
        let start = trace.width() - WIDTH;
        let end = start + HASH_SIZE;
        assert_eq!(&last_row[start..end], &expected);
    }
}
