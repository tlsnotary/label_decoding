use crate::boolvec_to_u8vec;

use super::{encrypt_arithmetic_labels, random_bigint, ARITHMETIC_LABEL_SIZE, POSEIDON_RATE};
use crate::label::{LabelGenerator, LabelPair, Seed};
use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::SeedableRng;
use rand::{thread_rng, Rng};
use rand_chacha::ChaCha20Rng;
// The PRG we use to generate arithmetic labels
type Prg = ChaCha20Rng;

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
    /// The sum of all arithmetic labels with the semantic value 0. One sum
    /// for each chunk of the plaintext.
    zero_sums: Vec<BigUint>,
    ciphertexts: Vec<[Vec<u8>; 2]>,
    /// The PRG seed from which all arithmetic labels were generated
    arith_label_seed: Seed,
}

pub struct ReceiveLabelsumHashes {
    deltas: Vec<BigUint>,
    zero_sums: Vec<BigUint>,
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Vec<BigUint>,
    arith_label_seed: [u8; 32],
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
    /// Generates arith. labels from a seed and encrypts them using binary labels
    /// as encryption keys.
    pub fn setup(self) -> Result<LabelsumVerifier<ReceivePlaintextHashes>, VerifierError> {
        let plaintext_bitsize = self.state.binary_labels.len();
        // Compute useful bits from the field prime
        let chunk_size = 253 * POSEIDON_RATE - 128;
        // count of chunks rounded up
        let chunk_count = (plaintext_bitsize + (chunk_size - 1)) / chunk_size;

        // There will be as many zero_sums as there are chunks
        let mut zero_sums: Vec<BigUint> = Vec::with_capacity(chunk_count);

        // There will be as many deltas as there are plaintext bits.
        let mut deltas: Vec<BigUint> = Vec::with_capacity(plaintext_bitsize);

        // Generate arithmetic label pairs and split them into chunks
        let generator = LabelGenerator::new();
        let (label_pairs, seed, _generator) =
            generator.generate(plaintext_bitsize, ARITHMETIC_LABEL_SIZE);
        let label_pair_chunks = label_pairs.chunks(chunk_size);

        // Calculate deltas for all chunks and zero_sums for each chunk
        for chunk in label_pair_chunks {
            let mut zero_sum = BigUint::from_u8(0).unwrap();
            for label_pair in chunk {
                zero_sum += label_pair[0].clone();
                deltas.push(label_pair[1].clone() - label_pair[0].clone());
            }
            zero_sums.push(zero_sum);
        }

        // encrypt each arithmetic label using a corresponding binary label as a key
        // place ciphertexts in an order based on binary label's p&p bit
        let ciphertexts = encrypt_arithmetic_labels(&label_pairs, &self.state.binary_labels);

        Ok(LabelsumVerifier {
            state: ReceivePlaintextHashes {
                zero_sums,
                deltas,
                ciphertexts,
                arith_label_seed: seed,
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
                    arith_label_seed: self.state.arith_label_seed,
                },
                verifier: self.verifier,
            },
        )
    }
}

impl LabelsumVerifier<ReceiveLabelsumHashes> {
    // receive the hash commitment to the Prover's sum of labels and reveal
    // the arithmetic label seed
    pub fn receive_labelsum_hashes(
        self,
        labelsum_hashes: Vec<BigUint>,
    ) -> (Seed, LabelsumVerifier<VerifyMany>) {
        (
            self.state.arith_label_seed,
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
