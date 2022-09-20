use halo2_proofs::arithmetic::FieldExt;
use num::{BigUint, FromPrimitive};
use pasta_curves::Fp as F;

// Decomposes a `BigUint` into bits and returns the bits in BE bit order,
// left padding them with zeroes to the size of 256.
pub fn bigint_to_bits(bigint: BigUint) -> [bool; 256] {
    let bits = u8vec_to_boolvec(&bigint.to_bytes_be());
    let mut bits256 = vec![false; 256];
    bits256[256 - bits.len()..].copy_from_slice(&bits);
    bits256.try_into().unwrap()
}

pub fn bigint_to_f(bigint: &BigUint) -> F {
    let le = bigint.to_bytes_le();
    let mut wide = [0u8; 64];
    wide[0..le.len()].copy_from_slice(&le);
    F::from_bytes_wide(&wide)
}

pub fn f_to_bigint(f: &F) -> BigUint {
    let tmp: [u8; 32] = f.try_into().unwrap();
    BigUint::from_bytes_le(&tmp)
}

// Splits up 256 bits into 4 limbs, shifts each limb left
// and returns the shifted limbs as `BigUint`s.
pub fn bits_to_limbs(bits: [bool; 256]) -> [BigUint; 4] {
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
