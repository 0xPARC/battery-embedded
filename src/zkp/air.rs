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
        secret: &[F; HASH_SIZE],
        neighbors: &[([F; HASH_SIZE], bool)],
        nonce: &[F; HASH_SIZE],
    ) -> RowMajorMatrix<F> {
        // Rows layout:
        //   0: leaf = Poseidon2(zeros, secret)
        //   1: bind = Poseidon2(nonce, leaf)
        //   2..: Merkle path parents with neighbors[0..]
        let rows = neighbors.len() + 2;
        assert!(
            rows > 2 && !neighbors[0].1,
            "neighbors[0].1 must be false to ensure uniqueness of proof",
        );
        let cols = self.width();
        let trace_size = rows * cols;
        // Reserve exactly the concrete trace size; FRI blowup applies later.
        let mut vec = Vec::with_capacity(trace_size);
        vec.resize(trace_size, F::ZERO);

        // Cache leaf hash from row 0 to use in the binding row and first parent.
        let mut leaf_row0: [F; HASH_SIZE] = [F::ZERO; HASH_SIZE];
        let mut leaf_row0_set = false;
        let poseidon_cols = p3_poseidon2_air::num_cols::<
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >();

        for row_num in 0..rows {
            let row_offset = row_num * cols;
            let (pvs, current) = vec.split_at_mut(row_offset);

            // Inputs: current[0..HASH_SIZE] = L, current[HASH_SIZE..2*HASH_SIZE] = R
            if row_num == 0 {
                // Row 0: leaf from secret
                current[..HASH_SIZE].copy_from_slice(secret); // L = secret
                for x in &mut current[HASH_SIZE..HASH_SIZE_2] {
                    *x = F::ZERO; // R = zeros
                }
            } else if row_num == 1 {
                // Row 1: bind nonce with leaf
                current[..HASH_SIZE].copy_from_slice(nonce); // L = nonce
                debug_assert!(leaf_row0_set);
                current[HASH_SIZE..HASH_SIZE_2].copy_from_slice(&leaf_row0); // R = leaf
            } else {
                // Path rows
                let lvl = row_num - 2;
                current[..HASH_SIZE].copy_from_slice(&neighbors[lvl].0); // L = neighbor[lvl]
                if row_num == 2 {
                    debug_assert!(leaf_row0_set);
                    current[HASH_SIZE..HASH_SIZE_2].copy_from_slice(&leaf_row0); // R = leaf
                } else {
                    // R = previous parent; read from `pvs` (previous rows) to avoid borrowing `vec` again
                    let prev_row_base = pvs.len() - cols;
                    let start = prev_row_base + (HASH_OFFSET + poseidon_cols - WIDTH);
                    let end = start + HASH_SIZE;
                    let prev_parent = &pvs[start..end];
                    current[HASH_SIZE..HASH_SIZE_2].copy_from_slice(prev_parent);
                }
            }

            // selector: 0 -> [R||L], 1 -> [L||R]; rows 0 and 1 act as selector = 0
            let mut state = [F::ZERO; WIDTH];
            let sel = if row_num > 1 && neighbors[row_num - 2].1 { F::ONE } else { F::ZERO };
            if sel == F::ONE {
                state[0..HASH_SIZE_2].copy_from_slice(&current[0..HASH_SIZE_2]); // [L||R]
            } else {
                state[0..HASH_SIZE].copy_from_slice(&current[HASH_SIZE..HASH_SIZE_2]); // [R
                state[HASH_SIZE..HASH_SIZE_2].copy_from_slice(&current[0..HASH_SIZE]); //  || L]
            }
            current[HASH_SIZE_2] = sel;

            let hash_slice = &mut current[HASH_OFFSET..cols];
            // The memory is initialized, but the generator expects MaybeUninit.
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

            // Export: store row index; eval enforces row0=0 and increments by 1 each row.
            hash_slice[0] = F::from_int(row_num);
            if row_num == 0 {
                // Capture last 8 words of the final state as the leaf value
                let start = poseidon_cols - HASH_SIZE;
                leaf_row0.copy_from_slice(&hash_slice[start..poseidon_cols]);
                leaf_row0_set = true;
            }
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

        // Enforce row index in export: row0 = 0 and next.index = index + 1 across transitions.
        let one = AB::Expr::from(AB::F::ONE);
        builder.when_first_row().assert_zero(hash[0].clone());
        builder
            .when_transition()
            .assert_eq(next[HASH_OFFSET].clone(), hash[0].clone() + one.clone());

        // Selector must be boolean; first two rows must have selector = 0
        let selector = inputs[HASH_SIZE_2];
        let one_minus_selector = AB::Expr::from(AB::F::ONE) - selector;
        builder.assert_zero(selector * one_minus_selector);
        builder.when_first_row().assert_zero(selector);
        builder.when_first_row().assert_zero(next[HASH_SIZE_2]);

        // Apply chaining constraint only for transitions from rows >= 2 (exclude rows 0 and 1)
        let row_idx = hash[0].clone();
        let transition_from_row_ge_2 = builder.is_transition() * (row_idx.clone() * (row_idx - one.clone()));

        for i in 0..HASH_SIZE {
            // Left/right linear relations
            let left = (inputs[i] - inputs[i + HASH_SIZE]) * selector + inputs[i + HASH_SIZE];
            builder.assert_eq(hash[i + 1], left);
            builder.assert_eq(
                inputs[i] + inputs[i + HASH_SIZE],
                hash[i + 1] + hash[i + HASH_SIZE + 1],
            );
            // Chain parent hash into next row's right input for rows >= 2
            builder
                .when(transition_from_row_ge_2.clone())
                .assert_eq(hash[hash.len() - WIDTH + i], next[i + HASH_SIZE]);
        }

        // Row 0 (leaf hashing) must feed row 1 second input with its hash output (last 8 words).
        for i in 0..HASH_SIZE {
            builder
                .when_first_row()
                .assert_eq(hash[hash.len() - HASH_SIZE + i], next[i + HASH_SIZE]);
        }

        for i in HASH_SIZE_2..WIDTH {
            builder.assert_zero(hash[i + 1]);
        }

        eval_poseidon2(self, builder, hash.borrow());

        // Bind public values: row 1 inputs/outputs under first-row gating, and last-row root
        let public_values = builder.public_values().to_vec();
        let poseidon_cols = p3_poseidon2_air::num_cols::<
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >();
        let next_hash_last_base = HASH_OFFSET + poseidon_cols - WIDTH;
        for i in 0..HASH_SIZE {
            // Nonce field (row 1 first input)
            builder
                .when_first_row()
                .assert_eq(next[i], public_values[HASH_SIZE + i]);
            // hash(leaf || nonce) = row 1 hash output last 8 words
            builder
                .when_first_row()
                .assert_eq(next[next_hash_last_base + i], public_values[2 * HASH_SIZE + i]);
        }

        // Bind last-row output to PV[0..HASH_SIZE] = Merkle root.
        for i in 0..HASH_SIZE {
            builder
                .when_last_row()
                .assert_eq(hash[hash.len() - WIDTH + i], public_values[i]);
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
