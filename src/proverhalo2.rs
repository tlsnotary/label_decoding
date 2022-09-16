use std::convert::TryInto;

use group::ff::Field;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::{FailureLocation, MockProver, VerifyFailure},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::arithmetic::FieldExt;
use pasta_curves::pallas;
use pasta_curves::Fp;

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Challenge255;
use instant::Instant;
use num::{BigUint, FromPrimitive};
use pasta_curves::EqAffine;
use rand::{thread_rng, Rng};
use web_sys::console;

// The labelsum protocol decodes a chunk of X bits at a time.
// Each of the bit requires 1 corresponding public input - a delta.
// We want the deltas to use up as few instance columns as possible
// because more instance columns means more prover time. We also want
// K to stay as low as possible since low K also improves prover time.
// The best ratio is achieved with K==6 and 68 instance columns.

// However, 68-bit limbs are awkward to work with. So we choose to have
// 64 columns and 4 rows, to place all the field element's bits into.

// Our circuit's K is 6, which gives us 2^6-6=58 useful rows
// (halo2 reserves 6 rows for internal purposes).
// It requires 4 64-cell rows in order to hold all the bits of one field element.

// The total amount of field elements we can decode is 58/4 = 14 1/2,
// which equals to 14 253-bit field elements plus 1 field element of 128 bits.
// The last 128 bits of the 15th element will be used for the salt.

// We could have much simpler logic if we just used 253 instance columns.
// But compared to 64 columns, that would increase the prover time 2x.
const FULL_FIELD_ELEMENTS: usize = 14;
const K: u32 = 6;
const CELLS_PER_ROW: usize = 64;
const USEFUL_ROWS: usize = 58;

type F = pallas::Base;

// Poseidon spec for 16-rate Poseidon
#[derive(Debug, Clone, Copy)]
struct Spec15;

impl Spec<Fp, 16, 15> for Spec15 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}

// Poseidon spec for 1-rate Poseidon
#[derive(Debug, Clone, Copy)]
struct Spec1;

impl Spec<Fp, 2, 1> for Spec1 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}

#[derive(Clone, Debug)]
struct TopLevelConfig {
    // each plaintext field element is decomposed into 256 bits
    // and each 64-bit limb is places on a row
    bits: [Column<Advice>; CELLS_PER_ROW],
    // space to calculate intermediate sums
    scratchpad: [Column<Advice>; 5],
    // dot product for each 64-bit limb
    dot_product: Column<Advice>,
    // expected 64-bit limb composed into an integer
    expected_limbs: Column<Advice>,
    // When calling assign_advice_from_instance() we store the resulting cell
    // in this column. TODO: we don't need a new column but could store it in
    // any of the above advice column's free cell, e.g. in scratchpad, but
    // when I tried to use them, assign_advice_from_instance() was giving me an error
    // NotEnoughRowsAvailable { current_k: 6 }, even though the offset
    // was < USEFUL_ROWS
    poseidon_misc: Column<Advice>,

    // SELECTORS. below is the description of what happens when a selector
    // is activated for a given row.

    // computes a dot product
    selector_dot_product: Selector,
    // composes a given limb from bits into an integer.
    // The highest limb corresponds to the selector with index 0.
    selector_compose: [Selector; 4],
    // checks binaryness of bits
    selector_binary_check: Selector,
    // sums 4 cells
    selector_sum4: Selector,
    // sums 2 cells
    selector_sum2: Selector,

    // config for Poseidon with rate 15
    poseidon_config_rate15: Pow5Config<Fp, 16, 15>,
    poseidon_config_rate1: Pow5Config<Fp, 2, 1>,

    // Contains 3 public input [plaintext hash, labelsum hash, zero sum]
    // Does not contain deltas (even though deltas are also public inputs)
    public_inputs: Column<Instance>,
}

struct MyCircuit {
    // plaintext is private input
    plaintext: [BigUint; 15],
    // deltas is a public input. We already inputted it as circuit's
    // public input but halo2 won't allow us to access instance columns'
    // values to compute expected values, so we input it here again.
    // This is a vector of rows, as opposed to the instances delta
    // which is a vector of columns.
    deltas: [Vec<Fp>; USEFUL_ROWS],
}

impl MyCircuit {
    // Computes the sum of 58 `cells` and outputs the cell containing the sum
    // and the amount of rows used up during computation.
    // Computations are done in the `scratchpad` area starting at the `row_offset`
    // row. This method constrain all intermediate values as necessary, so that
    // the resulting cell is a properly constrained sum.
    fn compute_58_cell_sum(
        &self,
        cells: &Vec<AssignedCell<Fp, Fp>>,
        region: &mut Region<F>,
        config: &TopLevelConfig,
        row_offset: usize,
    ) -> Result<(AssignedCell<F, F>, usize), Error> {
        let original_offset = row_offset;
        let mut offset = row_offset;

        // copy chunks of 4 cells to scratchpad and compute their sums
        let l1_chunks: Vec<Vec<AssignedCell<F, F>>> = cells.chunks(4).map(|c| c.to_vec()).collect();

        // do not process the last chunk of level1 as it will be
        // later combined with the last chunk of level2
        let l2_sums = self.fold_sum(&l1_chunks[..l1_chunks.len() - 1], region, &config, offset)?;

        offset += l1_chunks.len() - 1;

        // we now have 14 level 2 subsums which need to be summed with each
        // other in batches of 4. There are 2 subsums from level 1 which we
        // will combine with level 2 subsums.

        let l2_chunks: Vec<Vec<AssignedCell<F, F>>> =
            l2_sums.chunks(4).map(|c| c.to_vec()).collect();

        // do not process the last chunk as it will be combined with
        // level1's last chunk's sums
        let mut l3_sums =
            self.fold_sum(&l2_chunks[..l2_chunks.len() - 1], region, &config, offset)?;

        offset += l2_chunks.len() - 1;

        // we need to find the sum of level1's last chunk's 2 elements and level2's
        // last chunks 2 elements
        let chunk = [
            l1_chunks[l1_chunks.len() - 1][0].clone(),
            l1_chunks[l1_chunks.len() - 1][1].clone(),
            l2_chunks[l2_chunks.len() - 1][0].clone(),
            l2_chunks[l2_chunks.len() - 1][1].clone(),
        ];
        let sum = self.fold_sum(&[chunk.to_vec()], region, &config, offset)?;

        offset += 1;

        l3_sums.push(sum[0].clone());

        // 4 level3 subsums into the final level4 sum which is the final
        // sum

        let l3_chunks: Vec<Vec<AssignedCell<F, F>>> =
            l3_sums.chunks(4).map(|c| c.to_vec()).collect();

        let final_sum = self.fold_sum(&l3_chunks, region, &config, offset)?[0].clone();

        offset += 1;

        Ok((final_sum, offset - original_offset))
    }

    fn fold_sum(
        &self,
        chunks: &[Vec<AssignedCell<F, F>>],
        region: &mut Region<F>,
        config: &TopLevelConfig,
        row_offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        (0..chunks.len())
            .map(|i| {
                let size = chunks[i].len();
                assert!(size == 2 || size == 4);

                let mut sum = Value::known(F::from(0));
                for j in 0..size {
                    chunks[i][j].copy_advice(
                        || "",
                        region,
                        config.scratchpad[j],
                        row_offset + i,
                    )?;
                    sum = sum + chunks[i][j].value();
                }
                let assigned_sum =
                    region.assign_advice(|| "", config.scratchpad[4], row_offset + i, || sum)?;
                if size == 4 {
                    config.selector_sum4.enable(region, row_offset + i)?;
                } else {
                    config.selector_sum2.enable(region, row_offset + i)?;
                }

                Ok(assigned_sum)
            })
            .collect()
    }
}

/// Configures Poseidon for rate 15 and returns the config
fn configure_poseidon_rate_15<S: Spec<F, 16, 15>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<Fp, 16, 15> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    meta.enable_constant(rc_b[0]);

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

/// Configures Poseidon for rate 1 and returns the config
fn configure_poseidon_rate_1<S: Spec<F, 2, 1>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<Fp, 2, 1> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    meta.enable_constant(rc_b[0]);

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

impl Circuit<F> for MyCircuit {
    type Config = TopLevelConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            plaintext: (0..FULL_FIELD_ELEMENTS + 1)
                .map(|_| BigUint::default())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            deltas: (0..USEFUL_ROWS)
                .map(|_| vec![F::from(0)])
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        println!(
            "{:?} available rows ",
            ((1 << K) as usize) - (meta.blinding_factors() + 1)
        );

        // ADVICE COLUMNS

        let bits: [Column<Advice>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let dot_product = meta.advice_column();
        meta.enable_equality(dot_product);

        let expected_limbs = meta.advice_column();
        meta.enable_equality(expected_limbs);

        let scratchpad: [Column<Advice>; 5] = (0..5)
            .map(|_| {
                let c = meta.advice_column();
                meta.enable_equality(c);
                c
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let poseidon_misc = meta.advice_column();
        meta.enable_equality(poseidon_misc);

        // INSTANCE COLUMNS

        let deltas: [Column<Instance>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
            .map(|_| meta.instance_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let public_inputs = meta.instance_column();
        meta.enable_equality(public_inputs);

        // SELECTORS

        let selector_dot_product = meta.selector();
        let selector_binary_check = meta.selector();
        let selector_compose: [Selector; 4] = (0..4)
            .map(|_| meta.selector())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let selector_sum4 = meta.selector();
        let selector_sum2 = meta.selector();

        // POSEIDON

        let poseidon_config_rate15 = configure_poseidon_rate_15::<Spec15>(15, meta);
        let poseidon_config_rate1 = configure_poseidon_rate_1::<Spec1>(1, meta);

        // MISC

        // Build Expressions with powers of 2, so be used later
        // to compose field elements from bits.
        let two = BigUint::from_u8(2).unwrap();
        let pow_2_x: Vec<_> = (0..256)
            .map(|i| Expression::Constant(bigint_to_f(two.pow(i as u32))))
            .collect();

        // GATES

        meta.create_gate("dot product", |meta| {
            let mut product = Expression::Constant(F::from(0));

            for i in 0..CELLS_PER_ROW {
                let delta = meta.query_instance(deltas[i], Rotation::cur());
                let bit = meta.query_advice(bits[i], Rotation::cur());
                product = product + delta * bit;
            }

            let expected = meta.query_advice(dot_product, Rotation::cur());
            let sel = meta.query_selector(selector_dot_product);
            vec![sel * (product - expected)]
        });

        // batch-checking binariness of all bits on the row
        meta.create_gate("binary check", |meta| {
            let expressions: [Expression<F>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
                .map(|i| {
                    let bit = meta.query_advice(bits[i], Rotation::cur());
                    bit.clone() * bit.clone() - bit
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let sel = meta.query_selector(selector_binary_check);
            Constraints::with_selector(sel, expressions)
        });

        for idx in 0..4 {
            // compose the bits of a 64-bit limb into a field element and shift the
            // limb to the left depending in the limb's index `idx`
            meta.create_gate("compose limb", |meta| {
                let mut sum_total = Expression::Constant(F::from(0));

                for i in 0..CELLS_PER_ROW {
                    let bit = meta.query_advice(bits[i], Rotation::cur());
                    sum_total = sum_total + bit * pow_2_x[255 - (CELLS_PER_ROW * idx) - i].clone();
                }

                let expected = meta.query_advice(expected_limbs, Rotation::cur());
                let sel = meta.query_selector(selector_compose[idx]);

                vec![sel * (sum_total - expected)]
            });
        }

        // sums 4 cells
        meta.create_gate("sum4", |meta| {
            let mut sum = Expression::Constant(F::from(0));

            for i in 0..4 {
                let dot_product = meta.query_advice(scratchpad[i], Rotation::cur());
                sum = sum + dot_product;
            }

            let expected = meta.query_advice(scratchpad[4], Rotation::cur());
            let sel = meta.query_selector(selector_sum4);
            vec![sel * (sum - expected)]
        });

        // sums 2 cells
        meta.create_gate("sum2", |meta| {
            let mut sum = Expression::Constant(F::from(0));

            for i in 0..2 {
                let dot_product = meta.query_advice(scratchpad[i], Rotation::cur());
                sum = sum + dot_product;
            }

            let expected = meta.query_advice(scratchpad[4], Rotation::cur());
            let sel = meta.query_selector(selector_sum2);
            vec![sel * (sum - expected)]
        });

        TopLevelConfig {
            bits,
            scratchpad,
            dot_product,
            expected_limbs,
            poseidon_misc,

            selector_dot_product,
            selector_compose,
            selector_binary_check,
            selector_sum4,
            selector_sum2,

            poseidon_config_rate15,
            poseidon_config_rate1,

            public_inputs,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let (labelsum, plaintext) = layouter.assign_region(
            || "main",
            |mut region| {
                // dot products for each row
                let mut assigned_dot_products = Vec::new();
                // limb for each row
                let mut assigned_limbs = Vec::new();

                for j in 0..FULL_FIELD_ELEMENTS + 1 {
                    // decompose the private input into bits
                    let bits = bigint_to_bits(self.plaintext[j].clone());

                    // The last field element has only 2 limbs, so we use 2 rows for its
                    // bits and we skip processing the 2 high limbs
                    let max_row = if j == FULL_FIELD_ELEMENTS { 2 } else { 4 };
                    let skip = if j == FULL_FIELD_ELEMENTS { 2 } else { 0 };

                    for row in 0..max_row {
                        // place bits on same row
                        for i in 0..CELLS_PER_ROW {
                            region.assign_advice(
                                || "",
                                config.bits[i],
                                j * 4 + row,
                                || Value::known(F::from(bits[CELLS_PER_ROW * (row + skip) + i])),
                            )?;
                        }
                        // constrain the whole row of bits to be binary
                        config
                            .selector_binary_check
                            .enable(&mut region, j * 4 + row)?;

                        let limbs = bits_to_limbs(bits);
                        // place expected limbs for each row
                        assigned_limbs.push(region.assign_advice(
                            || "",
                            config.expected_limbs,
                            j * 4 + row,
                            || Value::known(bigint_to_f(limbs[row + skip].clone())),
                        )?);
                        // constrain the expected limb to match what the gate
                        // composes from bits
                        config.selector_compose[row + skip].enable(&mut region, j * 4 + row)?;

                        // compute the expected dot product for this row
                        let mut dot_product = F::from(0);
                        for i in 0..CELLS_PER_ROW {
                            dot_product += self.deltas[j * 4 + row][i]
                                * F::from(bits[CELLS_PER_ROW * (row + skip) + i]);
                        }
                        // place it in a cell
                        assigned_dot_products.push(region.assign_advice(
                            || "",
                            config.dot_product,
                            j * 4 + row,
                            || Value::known(dot_product),
                        )?);
                        // constrain the expected dot product to match what the gate computes
                        config
                            .selector_dot_product
                            .enable(&mut region, j * 4 + row)?;
                    }
                }

                // the grand sum of all dot products + the zero sum == the
                // sum of all labels.
                let (label_sum, mut offset) =
                    self.compute_58_cell_sum(&assigned_dot_products, &mut region, &config, 0)?;

                // Constrains each chunks of 4 limbs to be equal to a cell and
                // returns the constrained cells containing the original plaintext,
                // the private input to the circuit.
                let plaintext: Result<Vec<AssignedCell<Fp, Fp>>, Error> = assigned_limbs
                    .chunks(4)
                    .map(|c| {
                        let sum =
                            self.fold_sum(&[c.to_vec()], &mut region, &config, offset)?[0].clone();
                        offset += 1;
                        Ok(sum)
                    })
                    .collect();

                println!("{:?} final scrathchpad offset", offset);

                Ok((label_sum, plaintext?))
            },
        )?;

        // Hash the labelsum and constrain the digest to match the public input

        let chip = Pow5Chip::construct(config.poseidon_config_rate1.clone());

        let hasher = Hash::<F, _, Spec1, ConstantLength<1>, 2, 1>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), [labelsum])?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected = region.assign_advice_from_instance(
                    || "",
                    config.public_inputs,
                    1,
                    config.poseidon_misc,
                    0,
                )?;
                region.constrain_equal(output.cell(), expected.cell())?;
                Ok(())
            },
        )?;

        // Hash the plaintext and constrain the digest to match the public input

        let chip = Pow5Chip::construct(config.poseidon_config_rate15.clone());

        let hasher = Hash::<F, _, Spec15, ConstantLength<15>, 16, 15>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), plaintext.try_into().unwrap())?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected = region.assign_advice_from_instance(
                    || "",
                    config.public_inputs,
                    0,
                    config.poseidon_misc,
                    1,
                )?;
                region.constrain_equal(output.cell(), expected.cell())?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn main() {
    let mut rng = thread_rng();

    // generate random plaintext to fill all cells. The first 3 bits of each
    // full field element are not used, so we zero them out
    const TOTAL_PLAINTEXT_SIZE: usize = CELLS_PER_ROW * USEFUL_ROWS;
    let mut plaintext_bits: [bool; TOTAL_PLAINTEXT_SIZE] =
        core::iter::repeat_with(|| rng.gen::<bool>())
            .take(TOTAL_PLAINTEXT_SIZE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    for i in 0..FULL_FIELD_ELEMENTS {
        plaintext_bits[256 * i + 0] = false;
        plaintext_bits[256 * i + 1] = false;
        plaintext_bits[256 * i + 2] = false;
    }

    // random deltas. The first 3 deltas of each set of 256 are not used, so we
    // zero them out.
    let mut deltas: [F; TOTAL_PLAINTEXT_SIZE] =
        core::iter::repeat_with(|| F::from_u128(rng.gen::<u128>()))
            .take(TOTAL_PLAINTEXT_SIZE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    for i in 0..FULL_FIELD_ELEMENTS {
        deltas[256 * i + 0] = F::from(0);
        deltas[256 * i + 1] = F::from(0);
        deltas[256 * i + 2] = F::from(0);
    }

    let pt_chunks = plaintext_bits.chunks(256);
    // plaintext has 15 BigUint field elements - this is how the User is
    // expected to call this halo2 prover
    let plaintext: [BigUint; FULL_FIELD_ELEMENTS + 1] = pt_chunks
        .map(|c| {
            // convert each chunk of bits into a field element
            BigUint::from_bytes_be(&boolvec_to_u8vec(c))
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // number of chunks should be equal to USEFUL_ROWS
    let all_deltas: [Vec<F>; USEFUL_ROWS] = deltas
        .chunks(CELLS_PER_ROW)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // transpose to make CELLS_PER_ROW instance columns
    let input_deltas: [Vec<F>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
        .map(|i| {
            all_deltas
                .iter()
                .map(|inner| inner[i].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut hash_input = [F::default(); 15];
    for i in 0..hash_input.len() {
        hash_input[i] = bigint_to_f(plaintext[i].clone());
    }
    let plaintext_digest =
        poseidon::Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(hash_input);

    // compute labelsum digest
    let mut labelsum = F::from(0);
    for it in plaintext_bits.iter().zip(deltas.clone()) {
        let (p, d) = it;
        let dot_product = F::from(*p) * d;
        labelsum += dot_product;
    }
    let labelsum_digest =
        poseidon::Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash([labelsum]);

    let circuit: MyCircuit = MyCircuit {
        plaintext,
        deltas: all_deltas.clone(),
    };

    // let prover = MockProver::<pallas::Base>::run(k, &circuit, input_deltas.clone()).unwrap();

    // assert_eq!(prover.verify(), Ok(()));

    use instant::Instant;

    let now = Instant::now();

    let params: Params<EqAffine> = Params::new(K);

    let vk = plonk::keygen_vk(&params, &circuit).unwrap();
    let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

    //console::log_1(&format!("ProvingKey built {:?}", now.elapsed()).into());
    println!("ProvingKey built [{:?}]", now.elapsed());

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let mut all_inputs: Vec<&[F]> = Vec::new();
    for i in 0..input_deltas.len() {
        let d = input_deltas[i].as_slice();
        all_inputs.push(d);
    }

    let tmp = &[plaintext_digest, labelsum_digest];
    all_inputs.push(tmp);
    println!("{:?} all inputs len", all_inputs.len());

    let now = Instant::now();
    plonk::create_proof(
        &params,
        &pk,
        &[circuit],
        &[all_inputs.as_slice()],
        &mut rng,
        &mut transcript,
    )
    .unwrap();
    //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

    println!("Proof created [{:?}]", now.elapsed());

    let proof = transcript.finalize();

    let now = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[all_inputs.as_slice()],
        &mut transcript,
    )
    .unwrap();
    //console::log_1(&format!("Proof verified {:?}", now.elapsed()).into());
    //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

    println!("Proof verified [{:?}]", now.elapsed());
    println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
}

// Decomposes a `BigUint` into bits and returns the bits in BE bit order,
// left padding them with zeroes to the size of 256.
pub fn bigint_to_bits(bigint: BigUint) -> [bool; 256] {
    let bits = u8vec_to_boolvec(&bigint.to_bytes_be());
    let mut bits256 = vec![false; 256];
    bits256[256 - bits.len()..].copy_from_slice(&bits);
    bits256.try_into().unwrap()
}

pub fn bigint_to_f(bigint: BigUint) -> F {
    let le = bigint.to_bytes_le();
    let mut wide = [0u8; 64];
    wide[0..le.len()].copy_from_slice(&le);
    F::from_bytes_wide(&wide)
}

// Splits up 256 bits into 4 limbs, shifts each limb left
// and return the shifted limb as BigUint
fn bits_to_limbs(bits: [bool; 256]) -> [BigUint; 4] {
    // break up the field element into 4 64-bit limbs
    // the limb at index 0 is the high limb
    let limbs: [BigUint; 4] = bits
        .chunks(64)
        .map(|c| BigUint::from_bytes_be(&boolvec_to_u8vec(c)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // shift each limb to the left
    let two = BigUint::from_u8(2).unwrap();
    let shift_by: [BigUint; 4] = [192, 128, 64, 0]
        .iter()
        .map(|s| two.pow(*s))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    limbs
        .iter()
        .zip(shift_by.iter())
        .map(|(l, s)| l * s)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

// Convert bits into bytes. The bits will be left-padded with zeroes to the
// multiple of 8.
#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let rem = bv.len() % 8;
    let first_byte_bitsize = if rem == 0 { 8 } else { rem };
    let offset = if rem == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    // implicitely left-pad the first byte with zeroes
    for (i, b) in bv[0..first_byte_bitsize].iter().enumerate() {
        v[i / 8] |= (*b as u8) << (first_byte_bitsize - 1 - i);
    }
    for (i, b) in bv[first_byte_bitsize..].iter().enumerate() {
        v[1 + i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

#[test]
fn test() {
    let two = BigUint::from_u8(2).unwrap();
    let pow_2_64 = two.pow(64);
    let pow_2_128 = two.pow(128);
    let pow_2_192 = two.pow(192);
}
