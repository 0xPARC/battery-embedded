use super::WIDTH;

use core::borrow::{Borrow, BorrowMut};
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{FullRound, PartialRound, Poseidon2Cols, SBox};

use super::{HASH_SIZE, Vec, constants::RoundConstants, generation::generate_trace_rows_for_perm};

const HASH_SIZE_2: usize = 2 * HASH_SIZE;
const HASH_OFFSET: usize = HASH_SIZE_2 + 1;

pub struct MerkleInclusionAir<
    F: Field,
    LinearLayers,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    _phantom: PhantomData<LinearLayers>,
}

impl<
    F: Field,
    LinearLayers: Sync,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> BaseAir<F>
    for MerkleInclusionAir<
        F,
        LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn width(&self) -> usize {
        HASH_OFFSET
            + p3_poseidon2_air::num_cols::<
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >()
    }
}

impl<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, WIDTH>,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    MerkleInclusionAir<
        F,
        LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    pub fn new(constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>) -> Self {
        Self {
            constants,
            _phantom: PhantomData,
        }
    }

    pub fn generate_trace_rows(
        &self,
        leaf: &[F; HASH_SIZE],
        neighbors: &[([F; HASH_SIZE], bool)],
        nonce: &[F; HASH_SIZE],
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let rows = neighbors.len() + 1;
        assert!(
            rows > 1 && !neighbors[0].1,
            "neighbors[0].1 must be false to ensure uniqueness of proof"
        );
        let cols = self.width();
        let trace_size = rows * cols;
        let mut vec = Vec::with_capacity(trace_size << extra_capacity_bits);
        vec.resize(trace_size, F::ZERO);
        for row_num in 0..rows {
            let row_offset = row_num * cols;
            let (pvs, current) = vec.split_at_mut(row_offset);
            let first_input = if row_num == 0 {
                nonce
            } else {
                &neighbors[row_num - 1].0
            };
            current[..HASH_SIZE].copy_from_slice(first_input);
            let second_input = if row_num <= 1 {
                leaf
            } else {
                &pvs[pvs.len() - WIDTH..pvs.len() - WIDTH + HASH_SIZE]
            };
            current[HASH_SIZE..HASH_SIZE_2].copy_from_slice(second_input);
            let mut state = [F::ZERO; WIDTH];
            current[HASH_SIZE_2] = if row_num > 0 && neighbors[row_num - 1].1 {
                state[0..HASH_SIZE_2].copy_from_slice(&current[0..HASH_SIZE_2]);
                F::ONE
            } else {
                state[0..HASH_SIZE].copy_from_slice(&current[HASH_SIZE..HASH_SIZE_2]);
                state[HASH_SIZE..HASH_SIZE_2].copy_from_slice(&current[0..HASH_SIZE]);
                F::ZERO
            };
            let hash_slice = &mut current[HASH_OFFSET..cols];
            // The memory is initialized, but generate_trace_rows_for_perm
            // is copied from p3_poseidon2_air and it expects MaybeUninit.
            let hash_slice_maybe_uninit = unsafe {
                core::slice::from_raw_parts_mut(
                    hash_slice.as_mut_ptr() as *mut MaybeUninit<F>,
                    hash_slice.len(),
                )
            };
            generate_trace_rows_for_perm::<
                F,
                LinearLayers,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(hash_slice_maybe_uninit.borrow_mut(), state, &self.constants);
            // For some reason, Poseidon2Cols has an `export` field that is always
            // set to 1 by the generator and ignored by the eval.  We instead use
            // this field for the row number.
            hash_slice[0] = F::from_int(row_num);
        }
        RowMajorMatrix::new(vec, cols)
    }
}

impl<
    AB: AirBuilderWithPublicValues,
    LinearLayers: GenericPoseidon2LinearLayers<AB::Expr, WIDTH>,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Air<AB>
    for MerkleInclusionAir<
        AB::F,
        LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        let (inputs, hash) = local.split_at(HASH_OFFSET);
        // We need a selector for "transition but not first row".
        // For some reason, builder.first_row() is not 1 in the first row,
        // so using 1 - builder.first_row() won't work.
        // Instead, we store the row number in local[HASH_OFFSET] = hash[0].
        builder.when_first_row().assert_zero(hash[0]);
        builder
            .when_transition()
            .assert_one(next[HASH_OFFSET] - hash[0]);
        let selector = inputs[HASH_SIZE_2];
        let one_minus_selector = AB::Expr::from(AB::F::ONE) - selector;
        builder.assert_zero(selector * one_minus_selector);
        // Force the first selector to be zero; otherwise it's easy to construct 2 valid proofs
        builder.when_first_row().assert_zero(selector);
        builder.when_first_row().assert_zero(next[HASH_SIZE_2]);
        let transition_not_first_row = builder.is_transition() * hash[0];
        for i in 0..HASH_SIZE {
            // The offset of 1 is due to the `export` field in `Poseidon2Cols`.
            // We are using it to store the row number.
            let left = (inputs[i] - inputs[i + HASH_SIZE]) * selector + inputs[i + HASH_SIZE];
            builder.assert_eq(hash[i + 1], left);
            builder.assert_eq(
                inputs[i] + inputs[i + HASH_SIZE],
                hash[i + 1] + hash[i + HASH_SIZE + 1],
            );
            builder
                .when(transition_not_first_row.clone())
                .assert_eq(hash[hash.len() - WIDTH + i], next[i + HASH_SIZE]);
        }
        for i in HASH_SIZE_2..WIDTH {
            builder.assert_zero(hash[i + 1]);
        }
        eval_poseidon2(self, builder, hash.borrow());
        let public_values = builder.public_values().to_vec();
        for i in 0..HASH_SIZE {
            builder
                .when_first_row()
                .assert_eq(inputs[i], public_values[HASH_SIZE + i]);
            builder.when_first_row().assert_eq(
                hash[hash.len() - WIDTH + i],
                public_values[2 * HASH_SIZE + i],
            );
        }
        // Bind last-row output to PV[0..HASH_SIZE] = Merkle root.
        for i in 0..HASH_SIZE {
            builder
                .when_last_row()
                .assert_eq(hash[hash.len() - WIDTH + i], public_values[i])
        }
    }
}

// Adapted from Plonky3 (https://github.com/Plonky3/Plonky3)
fn eval_poseidon2<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<AB::Expr, WIDTH>,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &MerkleInclusionAir<
        AB::F,
        LinearLayers,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local: &Poseidon2Cols<
        AB::Var,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
) {
    let mut state: [_; WIDTH] = local.inputs.map(|x| x.into());

    LinearLayers::external_linear_layer(&mut state);

    for round in 0..HALF_FULL_ROUNDS {
        eval_full_round::<_, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.beginning_full_rounds[round],
            &air.constants.beginning_full_round_constants[round],
            builder,
        );
    }

    for round in 0..PARTIAL_ROUNDS {
        eval_partial_round::<_, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.partial_rounds[round],
            &air.constants.partial_round_constants[round],
            builder,
        );
    }

    for round in 0..HALF_FULL_ROUNDS {
        eval_full_round::<_, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.ending_full_rounds[round],
            &air.constants.ending_full_round_constants[round],
            builder,
        );
    }
}

#[inline]
fn eval_full_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<AB::Expr, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [AB::Expr; WIDTH],
    full_round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[AB::F; WIDTH],
    builder: &mut AB,
) {
    for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
        *s += *r;
        eval_sbox(&full_round.sbox[i], s, builder);
    }
    LinearLayers::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(full_round.post) {
        builder.assert_eq(state_i.clone(), post_i);
        *state_i = post_i.into();
    }
}

#[inline]
fn eval_partial_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<AB::Expr, WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [AB::Expr; WIDTH],
    partial_round: &PartialRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: &AB::F,
    builder: &mut AB,
) {
    state[0] += *round_constant;
    eval_sbox(&partial_round.sbox, &mut state[0], builder);

    builder.assert_eq(state[0].clone(), partial_round.post_sbox);
    state[0] = partial_round.post_sbox.into();

    LinearLayers::internal_linear_layer(state);
}

/// Evaluates the S-box over a degree-1 expression `x`.
///
/// # Panics
///
/// This method panics if the number of `REGISTERS` is not chosen optimally for the given
/// `DEGREE` or if the `DEGREE` is not supported by the S-box. The supported degrees are
/// `3`, `5`, `7`, and `11`.
#[inline]
fn eval_sbox<AB, const DEGREE: u64, const REGISTERS: usize>(
    sbox: &SBox<AB::Var, DEGREE, REGISTERS>,
    x: &mut AB::Expr,
    builder: &mut AB,
) where
    AB: AirBuilder,
{
    *x = match (DEGREE, REGISTERS) {
        (3, 0) => x.cube(),
        (5, 0) => x.exp_const_u64::<5>(),
        (7, 0) => x.exp_const_u64::<7>(),
        (5, 1) => {
            let committed_x3 = sbox.0[0].into();
            let x2 = x.square();
            builder.assert_eq(committed_x3.clone(), x2.clone() * x.clone());
            committed_x3 * x2
        }
        (7, 1) => {
            let committed_x3 = sbox.0[0].into();
            builder.assert_eq(committed_x3.clone(), x.cube());
            committed_x3.square() * x.clone()
        }
        (11, 2) => {
            let committed_x3 = sbox.0[0].into();
            let committed_x9 = sbox.0[1].into();
            let x2 = x.square();
            builder.assert_eq(committed_x3.clone(), x2.clone() * x.clone());
            builder.assert_eq(committed_x9.clone(), committed_x3.cube());
            committed_x9 * x2
        }
        _ => panic!(
            "Unexpected (DEGREE, REGISTERS) of ({}, {})",
            DEGREE, REGISTERS
        ),
    }
}
