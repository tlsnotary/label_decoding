use super::ARITHMETIC_LABEL_SIZE;
use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use derive_macro::{define_accessors_trait, VerifierDataGetSet};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub enum VerifierError {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
    VerificationFailed,
}

pub trait State {}

pub struct Setup {
    binary_labels: Vec<[u128; 2]>,
}

pub struct ReceivePlaintextHashes {
    deltas: Vec<BigUint>,
    zero_sums: Vec<BigUint>,
    ciphertexts: Vec<[Vec<u8>; 2]>,
}

pub struct ReceiveLabelsumHashes {
    deltas: Vec<BigUint>,
    zero_sums: Vec<BigUint>,
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Vec<BigUint>,
}

pub struct VerifyMany {
    deltas: Vec<BigUint>,
    zero_sums: Vec<BigUint>,
    plaintext_hashes: Vec<BigUint>,
    labelsum_hashes: Vec<BigUint>,
}

pub struct VerificationSuccessfull {
    plaintext_hashes: Vec<BigUint>,
}

impl State for Setup {}
impl State for ReceivePlaintextHashes {}
impl State for ReceiveLabelsumHashes {}
impl State for VerifyMany {}
impl State for VerificationSuccessfull {}

pub trait Verify {
    fn verify(
        &self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError>;
}
pub struct LabelsumVerifier<S = Setup>
where
    S: State,
{
    verifier: Box<dyn Verify>,
    state: S,
}

impl LabelsumVerifier {
    pub fn new(
        binary_labels: Vec<[u128; 2]>,
        verifier: Box<dyn Verify>,
    ) -> LabelsumVerifier<Setup> {
        LabelsumVerifier {
            state: Setup { binary_labels },
            verifier,
        }
    }
}

impl LabelsumVerifier<Setup> {
    /// Convert binary labels into encrypted arithmetic labels.
    /// TODO more comments about this method
    pub fn setup(self) -> Result<LabelsumVerifier<ReceivePlaintextHashes>, VerifierError> {
        let bitsize = self.state.binary_labels.len();
        // TODO POSEIDON_WIDTH here
        // Compute useful bits from the field prime
        let chunk_size = 253 * 16 - 128;
        // count of chunks rounded up
        let chunk_count = (bitsize + (chunk_size - 1)) / chunk_size;

        let mut zero_sums: Vec<BigUint> = Vec::with_capacity(chunk_count);
        let mut deltas: Vec<BigUint> = Vec::with_capacity(bitsize);
        // Generate as many arithmetic label pairs as there are plaintext bits.
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
                        // To keep the handling simple, we want to avoid a negative delta, that's why
                        // W_0 and delta must be (ARITHMETIC_LABEL_SIZE - 1)-bit values and W_1 will be
                        // set to W_0 + delta
                        let zero_label = random_bigint(ARITHMETIC_LABEL_SIZE - 1);
                        let delta = random_bigint(ARITHMETIC_LABEL_SIZE - 1);
                        let one_label = zero_label.clone() + delta.clone();
                        zero_sum += zero_label.clone();
                        deltas.push(delta);
                        [zero_label, one_label]
                    })
                    .collect(),
            );
            zero_sums.push(zero_sum);
        }

        // encrypt each arithmetic label using a corresponding binary label as a key
        // place ciphertexts in an order based on binary label's p&p bit
        let ciphertexts: Vec<[Vec<u8>; 2]> = self
            .state
            .binary_labels
            .iter()
            .zip(all_arithm_labels)
            .map(|(bin_pair, arithm_pair)| {
                let zero_key = Aes128::new_from_slice(&bin_pair[0].to_be_bytes()).unwrap();
                let one_key = Aes128::new_from_slice(&bin_pair[1].to_be_bytes()).unwrap();
                let mut label0 = [0u8; 16];
                let mut label1 = [0u8; 16];
                let ap0 = arithm_pair[0].to_bytes_be();
                let ap1 = arithm_pair[1].to_bytes_be();
                // pad with zeroes on the left
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

        Ok(LabelsumVerifier {
            state: ReceivePlaintextHashes {
                zero_sums,
                deltas,
                ciphertexts,
            },
            verifier: self.verifier,
        })
    }
}

impl LabelsumVerifier<ReceivePlaintextHashes> {
    // receive hashes of plaintext and reveal the encrypted arithmetic labels
    pub fn receive_plaintext_hashes(
        self,
        plaintext_hashes: Vec<BigUint>,
    ) -> (Vec<[Vec<u8>; 2]>, LabelsumVerifier<ReceiveLabelsumHashes>) {
        (
            self.state.ciphertexts,
            LabelsumVerifier {
                state: ReceiveLabelsumHashes {
                    zero_sums: self.state.zero_sums,
                    deltas: self.state.deltas,
                    plaintext_hashes,
                },
                verifier: self.verifier,
            },
        )
    }
}

impl LabelsumVerifier<ReceiveLabelsumHashes> {
    // receive the hash commitment to the Prover's sum of labels and reveal all
    // deltas and zero_sums.
    pub fn receive_labelsum_hashes(
        self,
        labelsum_hashes: Vec<BigUint>,
    ) -> (Vec<BigUint>, Vec<BigUint>, LabelsumVerifier<VerifyMany>) {
        (
            self.state.deltas.clone(),
            self.state.zero_sums.clone(),
            LabelsumVerifier {
                state: VerifyMany {
                    zero_sums: self.state.zero_sums,
                    deltas: self.state.deltas,
                    plaintext_hashes: self.state.plaintext_hashes,
                    labelsum_hashes,
                },
                verifier: self.verifier,
            },
        )
    }
}

impl LabelsumVerifier<VerifyMany> {
    pub fn verify_many(
        self,
        proofs: Vec<Vec<u8>>,
    ) -> Result<LabelsumVerifier<VerificationSuccessfull>, VerifierError> {
        // // Write public.json. The elements must be written in the exact order
        // // as below, that's the order snarkjs expects them to be in.

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        // TODO remove this hard-coding
        let useful_bits = 253;
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count = (self.state.deltas.len() + (chunk_size - 1)) / chunk_size;
        assert!(proofs.len() == chunk_count);

        // pad deltas with 0 values to make their count a multiple of a chunk size
        let delta_pad_count = chunk_size * chunk_count - self.state.deltas.len();
        let mut deltas = self.state.deltas.clone();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);
        let deltas_chunks: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunk_count {
            // There are as many deltas as there are bits in the chunk of the
            // plaintext (not counting the salt)
            let delta_str: Vec<String> =
                deltas_chunks[count].iter().map(|v| v.to_string()).collect();

            let plaintext_hash = self.state.plaintext_hashes[count].clone();
            let labelsum_hash = self.state.labelsum_hashes[count].clone();
            let zero_sum = self.state.zero_sums[count].clone();

            let res = self.verifier.verify(
                proofs[count].clone(),
                delta_str,
                plaintext_hash,
                labelsum_hash,
                zero_sum,
            );
            // checking both for good measure
            if res.is_err() {
                return Err(VerifierError::VerificationFailed);
            }
            // shouldn't get here if there was an error, but will check anyway
            if res.unwrap() != true {
                return Err(VerifierError::VerificationFailed);
            }
        }

        Ok(LabelsumVerifier {
            state: VerificationSuccessfull {
                plaintext_hashes: self.state.plaintext_hashes,
            },
            verifier: self.verifier,
        })
    }
}

fn random_bigint(bitsize: usize) -> BigUint {
    assert!(bitsize <= 128);
    let r: [u8; 16] = thread_rng().gen();
    // take only those bits which we need
    BigUint::from_bytes_be(&boolvec_to_u8vec(&u8vec_to_boolvec(&r)[0..bitsize]))
}

#[inline]
fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
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
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
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
