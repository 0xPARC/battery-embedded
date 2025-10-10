//use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::integers::QuotientMap;
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

pub(super) const WIDTH: usize = 16;
pub(super) const HASH_SIZE: usize = 8;
// Public-values layout (internal): [root(8) | H(8) | nonce(8)]

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
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
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

pub fn generate_proof(
    leaf: &[Val; 8],
    neighbors: &[([Val; 8], bool)],
    nonce: &[u8; 32],
) -> (Proof<StarkConfig<Pcs, Challenge, Challenger>>, Vec<Val>) {
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

    // Convert nonce bytes into 8 field elements (little‑endian u32 chunks).
    let mut nonce_f = [Val::from_canonical_checked(0).unwrap(); HASH_SIZE];
    for i in 0..HASH_SIZE {
        let base = i * 4;
        let word = u32::from_le_bytes([
            nonce[base],
            nonce[base + 1],
            nonce[base + 2],
            nonce[base + 3],
        ]);
        nonce_f[i] = Val::from_canonical_checked(word).unwrap();
    }

    let trace = air.generate_trace_rows(leaf, neighbors, &nonce_f, fri_params.log_blowup);

    // Extract public outputs from the last row.
    let last_row: Vec<Val> = {
        let row = trace.row_slice(trace.height() - 1).unwrap();
        row.to_vec()
    };
    let cols = trace.width();
    let poseidon_cols = p3_poseidon2_air::num_cols::<
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >();
    let root_start = cols - poseidon_cols - WIDTH; // end of merkle block minus WIDTH
    let h_start = cols - WIDTH; // end of commit block minus WIDTH

    let mut public_values = Vec::with_capacity(3 * HASH_SIZE);
    public_values.extend_from_slice(&last_row[root_start..root_start + HASH_SIZE]);
    public_values.extend_from_slice(&last_row[h_start..h_start + HASH_SIZE]);
    public_values.extend_from_slice(&nonce_f);

    let dft = Dft::default();

    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, ChaCha20Rng::from_seed(*nonce));

    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &air, trace, &public_values);
    (proof, public_values)
}

pub fn verify_proof(
    nonce: &[u8; 32],
    proof: &Proof<StarkConfig<Pcs, Challenge, Challenger>>,
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

    let config = MyConfig::new(pcs, challenger);

    // Overwrite the nonce slice in public values with the verifier's nonce binding when length matches exactly.
    let mut pv = public_values.clone();
    if pv.len() == 3 * HASH_SIZE {
        let mut nonce_f = [Val::from_canonical_checked(0).unwrap(); HASH_SIZE];
        for i in 0..HASH_SIZE {
            let base = i * 4;
            let word = u32::from_le_bytes([
                nonce[base],
                nonce[base + 1],
                nonce[base + 2],
                nonce[base + 3],
            ]);
            nonce_f[i] = Val::from_canonical_checked(word).unwrap();
        }
        let start = 2 * HASH_SIZE; // nonce slice offset
        for i in 0..HASH_SIZE {
            pv[start + i] = nonce_f[i];
        }
    }

    verify(&config, &air, proof, &pv)
}

#[cfg(test)]
mod test {
    use p3_field::integers::QuotientMap;

    use super::{HASH_SIZE, Val, generate_proof, verify_proof};

    #[test]
    fn test_root_independent_of_nonce() {
        let leaf = [Val::from_canonical_checked(4).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(3).unwrap(); 8], false); 32];
        let nonce1 = [0; 32];
        let nonce2 = [1; 32];
        let (_, public1) = generate_proof(&leaf, &neighbors, &nonce1);
        let (_, public2) = generate_proof(&leaf, &neighbors, &nonce2);
        // Root (first 8) must be independent of nonce.
        assert_eq!(&public1[0..HASH_SIZE], &public2[0..HASH_SIZE]);
    }

    #[test]
    fn verify_fails_with_wrong_nonce() {
        let leaf = [Val::from_canonical_checked(7).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(5).unwrap(); 8], false); 16];
        let nonce = [9u8; 32];
        let wrong = [8u8; 32];
        let (proof, publics) = generate_proof(&leaf, &neighbors, &nonce);
        assert!(verify_proof(&wrong, &proof, &publics).is_err());
        assert!(verify_proof(&nonce, &proof, &publics).is_ok());
    }

    #[test]
    fn verify_overrides_public_nonce_slice() {
        let leaf = [Val::from_canonical_checked(11).unwrap(); 8];
        let neighbors = [([Val::from_canonical_checked(13).unwrap(); 8], false); 8];
        let nonce = [42u8; 32];
        let (proof, mut publics) = generate_proof(&leaf, &neighbors, &nonce);
        // Corrupt the published nonce slice; verifier should ignore and still accept using its argument.
        for i in 0..HASH_SIZE {
            publics[2 * HASH_SIZE + i] = Val::from_canonical_checked(123456u32 + i as u32).unwrap();
        }
        assert!(verify_proof(&nonce, &proof, &publics).is_ok());
    }

    #[test]
    fn commit_stable_across_tree_changes_but_changes_with_nonce() {
        let leaf = [Val::from_canonical_checked(3).unwrap(); 8];
        let neighbors_a = [([Val::from_canonical_checked(2).unwrap(); 8], false); 16];
        let neighbors_b = [([Val::from_canonical_checked(4).unwrap(); 8], false); 16];
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        let (_, pa) = generate_proof(&leaf, &neighbors_a, &nonce1);
        let (_, pb) = generate_proof(&leaf, &neighbors_b, &nonce1);
        // H equal across different trees with same nonce
        assert_eq!(&pa[HASH_SIZE..2 * HASH_SIZE], &pb[HASH_SIZE..2 * HASH_SIZE]);
        // Root likely differs if neighbors differ
        assert_ne!(&pa[0..HASH_SIZE], &pb[0..HASH_SIZE]);
        // H must differ across nonces
        let (_, pc) = generate_proof(&leaf, &neighbors_a, &nonce2);
        assert_ne!(&pa[HASH_SIZE..2 * HASH_SIZE], &pc[HASH_SIZE..2 * HASH_SIZE]);
    }
}
