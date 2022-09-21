use super::circuit::{CELLS_PER_ROW, USEFUL_ROWS};
use crate::utils::{boolvec_to_u8vec, u8vec_to_boolvec};
use crate::Delta;
use halo2_proofs::arithmetic::FieldExt;
use num::{BigUint, FromPrimitive};
use pasta_curves::Fp as F;

/// Decomposes a `BigUint` into bits and returns the bits in MSB-first bit order,
/// left padding them with zeroes to the size of 256.
pub fn bigint_to_256bits(bigint: BigUint) -> [bool; 256] {
    let bits = u8vec_to_boolvec(&bigint.to_bytes_be());
    let mut bits256 = vec![false; 256];
    bits256[256 - bits.len()..].copy_from_slice(&bits);
    bits256.try_into().unwrap()
}

/// Converts a `BigUint` into an field element type.
/// The assumption is that `bigint` was sanitized earlier and is not larger
/// than [crate::verifier::Verify::field_size]
pub fn bigint_to_f(bigint: &BigUint) -> F {
    let le = bigint.to_bytes_le();
    let mut wide = [0u8; 64];
    wide[0..le.len()].copy_from_slice(&le);
    F::from_bytes_wide(&wide)
}

/// Converts `F` into a `BigUint` type
pub fn f_to_bigint(f: &F) -> BigUint {
    let tmp: [u8; 32] = f.try_into().unwrap();
    BigUint::from_bytes_le(&tmp)
}

/// Splits up 256 bits into 4 limbs, shifts each limb left
/// and returns the shifted limbs as `BigUint`s.
pub fn bits_to_limbs(bits: [bool; 256]) -> [BigUint; 4] {
    // break up the field element into 4 64-bit limbs
    // the limb at index 0 is the high limb
    let limbs: [BigUint; 4] = bits
        .chunks(64)
        .map(|c| BigUint::from_bytes_be(&boolvec_to_u8vec(c)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // shift each limb to the left:

    let two = BigUint::from_u8(2).unwrap();
    // how many bits to shift each limb by
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

/// Converts a vec of padded deltas into a matrix of rows and a matrix of
/// columns and returns them.
pub fn deltas_to_matrices(
    deltas: &Vec<Delta>,
    useful_bits: usize,
) -> (
    [[F; CELLS_PER_ROW]; USEFUL_ROWS],
    [[F; USEFUL_ROWS]; CELLS_PER_ROW],
) {
    let deltas = convert_and_pad_deltas(deltas, useful_bits);
    let deltas_as_rows = deltas_to_matrix_of_rows(&deltas, useful_bits);

    let deltas_as_columns = transpose_rows(&deltas_as_rows);

    (deltas_as_rows, deltas_as_columns)
}

/// To make handling inside the circuit simpler, we pad each chunk (except for
/// the last one) of deltas with zero values on the left to the size 256.
/// Note that the last chunk (corresponding to the 15th field element) will
/// contain only 128 deltas, so we do NOT pad it.
///
/// Returns padded deltas
fn convert_and_pad_deltas(deltas: &Vec<Delta>, useful_bits: usize) -> Vec<F> {
    // convert deltas into F type
    let deltas: Vec<F> = deltas.iter().map(|d| bigint_to_f(d)).collect();

    deltas
        .chunks(useful_bits)
        .enumerate()
        .map(|(i, c)| {
            if i < 14 {
                let mut v = vec![F::from(0); 256 - c.len()];
                v.extend(c.to_vec());
                v
            } else {
                c.to_vec()
            }
        })
        .flatten()
        .collect()
}

/// Converts a vec of padded deltas into a matrix of rows and returns it.
fn deltas_to_matrix_of_rows(
    deltas: &Vec<F>,
    useful_bits: usize,
) -> ([[F; CELLS_PER_ROW]; USEFUL_ROWS]) {
    deltas
        .chunks(CELLS_PER_ROW)
        .map(|c| c.try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Transposes a matrix of rows.
fn transpose_rows(matrix: &[[F; CELLS_PER_ROW]; USEFUL_ROWS]) -> [[F; USEFUL_ROWS]; CELLS_PER_ROW] {
    (0..CELLS_PER_ROW)
        .map(|i| {
            matrix
                .iter()
                .map(|inner| inner[i].clone().try_into().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a vec of deltas into a matrix of columns and returns it.
fn deltas_to_matrix_of_columns(
    deltas: &Vec<F>,
    useful_bits: usize,
) -> [[F; USEFUL_ROWS]; CELLS_PER_ROW] {
    transpose_rows(&deltas_to_matrix_of_rows(deltas, useful_bits))
}
