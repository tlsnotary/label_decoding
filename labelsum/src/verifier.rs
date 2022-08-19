use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use json::{array, object, stringify, stringify_pretty, JsonValue};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use std::env::temp_dir;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use uuid::Uuid;

use crate::VerifierCore;

#[derive(Debug)]
pub enum VerifierError {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
}

// This is a template containing all the fields which must be present in the
// implementor of `Verifier`. It is here for convenience to be copy-pasted into
// the implementor's struct.
// The implementor must also #[derive(VerifierGetSetM)]
#[allow(dead_code)]
pub struct VerfierImplementorTemplate {
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Option<Vec<BigUint>>,
    labelsum_hashes: Option<Vec<BigUint>>,
    // if set to true, then we must send the proving key to the Prover
    // before this protocol begins. Otherwise, it is assumed that the Prover
    // already has the proving key from a previous interaction with us.
    proving_key_needed: bool,
    deltas: Option<Vec<BigUint>>,
    zero_sums: Option<Vec<BigUint>>,
    ciphertexts: Option<Vec<[Vec<u8>; 2]>>,
    useful_bits: usize,
}

pub trait Verifier: VerifierGetSet {
    // these methods must be implemented:

    fn get_proving_key(&mut self) -> Result<Vec<u8>, VerifierError>;

    fn verify(
        &mut self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError>;

    // the rest of the methods have default implementations

    // Convert binary labels into encrypted arithmetic labels.
    // Prepare JSON objects to be converted into proof.json before verification
    fn setup(&mut self, labels: &Vec<[u128; 2]>) {
        // generate as many 128-bit arithm label pairs as there are plaintext bits.
        // The 128-bit size is for convenience to be able to encrypt the label with 1
        // call to AES.
        // To keep the handling simple, we want to avoid a negative delta, that's why
        // W_0 and delta must be 127-bit values and W_1 will be set to W_0 + delta

        let bitsize = labels.len();
        let chunk_size = 253 * 16 - 128;
        // count of chunks rounded up
        let chunk_count = (bitsize + (chunk_size - 1)) / chunk_size;

        let mut zero_sums: Vec<BigUint> = Vec::with_capacity(chunk_count);
        let mut deltas: Vec<BigUint> = Vec::with_capacity(bitsize);
        let mut all_arithm_labels: Vec<[BigUint; 2]> = Vec::with_capacity(bitsize);

        for count in 0..chunk_count {
            // calculate zero_sum for each chunk of plaintext separately
            let mut zero_sum = BigUint::from_u8(0).unwrap();
            // end of range is different for the last chunk
            let end = if count < chunk_count - 1 {
                (count + 1) * chunk_size
            } else {
                // compute the size of the gap at the end of the last chunk
                let last_size = bitsize % chunk_size;
                let gap_size = if last_size == 0 {
                    0
                } else {
                    chunk_size - last_size
                };
                (count + 1) * chunk_size - gap_size
            };
            all_arithm_labels.append(
                &mut (count * chunk_size..end)
                    .map(|_| {
                        let zero_label = random_bigint(127);
                        let delta = random_bigint(127);
                        let one_label = zero_label.clone() + delta.clone();
                        zero_sum += zero_label.clone();
                        deltas.push(delta);
                        [zero_label, one_label]
                    })
                    .collect(),
            );
            zero_sums.push(zero_sum);
        }
        self.set_zero_sums(Some(zero_sums));
        self.set_deltas(Some(deltas));

        // encrypt each arithmetic label using a corresponding binary label as a key
        // place ciphertexts in an order based on binary label's p&p bit
        let ciphertexts: Vec<[Vec<u8>; 2]> = labels
            .iter()
            .zip(all_arithm_labels)
            .map(|(bin_pair, arithm_pair)| {
                let zero_key = Aes128::new_from_slice(&bin_pair[0].to_be_bytes()).unwrap();
                let one_key = Aes128::new_from_slice(&bin_pair[1].to_be_bytes()).unwrap();
                let mut label0 = [0u8; 16];
                let mut label1 = [0u8; 16];
                let ap0 = arithm_pair[0].to_bytes_be();
                let ap1 = arithm_pair[1].to_bytes_be();
                // need to zero-pad on the left
                label0[16 - ap0.len()..].copy_from_slice(&ap0);
                label1[16 - ap1.len()..].copy_from_slice(&ap1);
                let mut label0: GenericArray<u8, U16> = GenericArray::from(label0);
                let mut label1: GenericArray<u8, U16> = GenericArray::from(label1);
                zero_key.encrypt_block(&mut label0);
                one_key.encrypt_block(&mut label1);
                // ciphertext 0 and ciphertext 1
                let ct0 = label0.to_vec();
                let ct1 = label1.to_vec();
                // place ar. labels based on the point and permute bit of bin. label 0
                if (bin_pair[0] & 1) == 0 {
                    [ct0, ct1]
                } else {
                    [ct1, ct0]
                }
            })
            .collect();
        self.set_ciphertexts(Some(ciphertexts));
    }

    // receive hashes of plaintext and reveal the encrypted arithmetic labels
    fn receive_pt_hashes(&mut self, hashes: Vec<BigUint>) -> Vec<[Vec<u8>; 2]> {
        self.set_plaintext_hashes(Some(hashes));
        self.ciphertexts().as_ref().unwrap().clone()
    }

    // receive the hash commitment to the Prover's sum of labels and reveal all
    // deltas and zero_sums.
    fn receive_labelsum_hash(&mut self, hashes: Vec<BigUint>) -> (Vec<BigUint>, Vec<BigUint>) {
        self.set_labelsum_hashes(Some(hashes));
        (
            self.deltas().as_ref().unwrap().clone(),
            self.zero_sums().as_ref().unwrap().clone(),
        )
    }

    fn verify_many(&mut self, proofs: Vec<Vec<u8>>) -> Result<bool, VerifierError> {
        // // Write public.json. The elements must be written in the exact order
        // // as below, that's the order snarkjs expects them to be in.

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        let useful_bits = self.useful_bits();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count = (self.deltas().as_ref().unwrap().len() + (chunk_size - 1)) / chunk_size;
        assert!(proofs.len() == chunk_count);

        let mut deltas = self.deltas().as_ref().unwrap().clone();
        // pad deltas with 0 values to make their count a multiple of a chunk size
        let delta_pad_count = chunk_size * chunk_count - self.deltas().as_ref().unwrap().len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);
        let deltas_chunks: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunk_count {
            // There are as many deltas as there are bits in the chunk of the
            // plaintext (not counting the salt)
            let delta_str: Vec<String> =
                deltas_chunks[count].iter().map(|v| v.to_string()).collect();

            let res = self.verify(
                proofs[count].clone(),
                delta_str,
                self.plaintext_hashes().as_ref().unwrap()[count].clone(),
                self.labelsum_hashes().as_ref().unwrap()[count].clone(),
                self.zero_sums().as_ref().unwrap()[count].clone(),
            );
            if res.is_err() {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}

/// accessors for the fields defined in [`VerfierImplementorTemplate`] which are
/// auto-implemented when using #[derive(VerifierGetSetM)]
pub trait VerifierGetSet {
    /// hashes for each chunk of Prover's plaintext
    fn plaintext_hashes(&self) -> &Option<Vec<BigUint>>;
    fn set_plaintext_hashes(&mut self, new: Option<Vec<BigUint>>);

    fn labelsum_hashes(&self) -> &Option<Vec<BigUint>>;
    fn set_labelsum_hashes(&mut self, new: Option<Vec<BigUint>>);

    // if set to true, then we must send the proving key to the Prover
    // before this protocol begins. Otherwise, it is assumed that the Prover
    // already has the proving key from a previous interaction with us.
    fn proving_key_needed(&self) -> &bool;
    fn set_proving_key_needed(&mut self, new: bool);

    fn deltas(&self) -> &Option<Vec<BigUint>>;
    fn set_deltas(&mut self, new: Option<Vec<BigUint>>);

    fn zero_sums(&self) -> &Option<Vec<BigUint>>;
    fn set_zero_sums(&mut self, new: Option<Vec<BigUint>>);

    fn ciphertexts(&self) -> &Option<Vec<[Vec<u8>; 2]>>;
    fn set_ciphertexts(&mut self, new: Option<Vec<[Vec<u8>; 2]>>);

    fn useful_bits(&self) -> &usize;
    fn set_useful_bits(&mut self, new: usize);
}

fn random_bigint(bitsize: usize) -> BigUint {
    assert!(bitsize <= 128);
    let r: [u8; 16] = thread_rng().gen();
    // take only those bits which we need
    BigUint::from_bytes_be(&boolvec_to_u8vec(&u8vec_to_boolvec(&r)[0..bitsize]))
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
