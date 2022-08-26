use crate::label::{LabelGenerator, LabelPair, Seed};
use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray};
use json::{object, stringify_pretty};
use num::{BigUint, FromPrimitive};
use rand::{thread_rng, Rng};
use std::env::temp_dir;
use std::fs;
use std::marker::PhantomData;
use std::process::{Command, Output};
use uuid::Uuid;

use super::{
    boolvec_to_u8vec, sha256, u8vec_to_boolvec, ARITHMETIC_LABEL_SIZE, MAX_CHUNK_SIZE,
    PERMUTATION_COUNT, POSEIDON_WIDTH,
};

#[derive(Debug)]
pub enum ProverError {
    ProvingKeyNotFound,
    WrongPrime,
    WrongPoseidonInput,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
    IncorrectEncryptedLabelSize,
    ErrorInPoseidonImplementation,
    MaxChunkSizeExceeded,
    BinaryLabelsAuthenticationFailed,
}

pub trait State {}

pub struct Setup {
    /// snarkjs proving key which was generated by the Verifier for us
    proving_key: Vec<u8>,
    /// the prime of the field in which Poseidon hash will be computed.
    field_prime: BigUint,
    /// bytes of the plaintext which was obtained from the garbled circuit
    plaintext: Vec<u8>,
}

/// for uncommented fields see comments in [`Setup`]
pub struct PlaintextCommitment {
    proving_key: Vec<u8>,
    field_prime: BigUint,
    plaintext: Vec<u8>,
    /// how many bits to pack into one field element
    useful_bits: usize,
    /// we will compute a separate Poseidon hash on each chunk of the plaintext.
    /// Each chunk contains POSEIDON_WIDTH * PERMUTATION_COUNT field elements.
    chunks: Vec<Vec<BigUint>>,
    /// each chunk's last 128 bits are used for the salt. w/o the salt, hashes
    /// of plaintext with low entropy could be brute-forced.
    /// The labelsum of a chunk also gets salted with the same salt as the chunk.
    salts: Vec<BigUint>,
    /// the size of one chunk of plaintext (not counting the salt) ==
    /// useful_bits * POSEIDON_WIDTH - 128 (salt size)
    chunk_size: usize,
}

/// for uncommented fields see comments in [`PlaintextCommitment`]
pub struct LabelsumCommitment {
    proving_key: Vec<u8>,
    field_prime: BigUint,
    plaintext: Vec<u8>,
    useful_bits: usize,
    chunks: Vec<Vec<BigUint>>,
    salts: Vec<BigUint>,
    chunk_size: usize,
    /// Poseidon hashes of each chunk of plaintext
    plaintext_hashes: Vec<BigUint>,
}

/// for uncommented fields see comments in [`LabelsumCommitment`]
pub struct BinaryLabelsAuthenticated {
    proving_key: Vec<u8>,
    plaintext: Vec<u8>,
    useful_bits: usize,
    chunks: Vec<Vec<BigUint>>,
    chunk_size: usize,
    /// hashes of the sums of arithmetic labels for each chunk of plaintext
    labelsum_hashes: Vec<BigUint>,
    plaintext_hashes: Vec<BigUint>,
    salts: Vec<BigUint>,
    // Hash of the ciphertext of arithmetic labels. We will check against
    // it during the authentication of the arithmetic labels.
    alct_hash: [u8; 32],
}

/// for uncommented fields see comments in [`LabelsumCommitment`]
pub struct AuthenticateArithmeticLabels {
    proving_key: Vec<u8>,
    plaintext: Vec<u8>,
    useful_bits: usize,
    chunks: Vec<Vec<BigUint>>,
    chunk_size: usize,
    /// hashes of the sums of arithmetic labels for each chunk of plaintext
    labelsum_hashes: Vec<BigUint>,
    plaintext_hashes: Vec<BigUint>,
    salts: Vec<BigUint>,
    // Hash of the ciphertext of arithmetic labels. We will check against
    // it during the authentication of the arithmetic labels.
    alct_hash: [u8; 32],
}

/// for uncommented fields see comments in [`LabelsumCommitment`]
pub struct ProofCreation {
    proving_key: Vec<u8>,
    plaintext: Vec<u8>,
    useful_bits: usize,
    chunks: Vec<Vec<BigUint>>,
    chunk_size: usize,
    /// hashes of the sums of arithmetic labels for each chunk of plaintext
    labelsum_hashes: Vec<BigUint>,
    plaintext_hashes: Vec<BigUint>,
    salts: Vec<BigUint>,
}

pub struct ProofReady {
    /// zk proofs which are sent to the Verifier proving that a specific Poseidon
    /// hash results from hashing the decoded output labels of the garbled
    /// circuit. Decoded output labels is the plaintext. One proof corresponds
    /// to one chunk of the plaintext.
    proofs: Vec<Vec<u8>>,
    // TODO: having just `chunks` is enough to derive `plaintext` and
    // `plaintext_hashes` since the chunks contain plaintext and salt.
    chunks: Vec<Vec<BigUint>>,
    plaintext: Vec<u8>,
    plaintext_hashes: Vec<BigUint>,
}

impl State for Setup {}
impl State for PlaintextCommitment {}
impl State for LabelsumCommitment {}
impl State for BinaryLabelsAuthenticated {}
impl State for AuthenticateArithmeticLabels {}
impl State for ProofCreation {}
impl State for ProofReady {}

pub trait Hash {
    fn hash(&self, bytes: &Vec<BigUint>) -> Result<BigUint, ProverError>;
}

pub trait Prove {
    fn prove(&self, input: String, proving_key: &Vec<u8>) -> Result<Vec<u8>, ProverError>;
}

pub struct LabelsumProver<S = Setup>
where
    S: State,
{
    poseidon: Box<dyn Hash>,
    prover: Box<dyn Prove>,
    state: S,
}

impl LabelsumProver {
    pub fn new(
        proving_key: Vec<u8>,
        field_prime: BigUint,
        plaintext: Vec<u8>,
        poseidon: Box<dyn Hash>,
        prover: Box<dyn Prove>,
    ) -> LabelsumProver<Setup> {
        LabelsumProver {
            state: Setup {
                proving_key,
                field_prime,
                plaintext,
            },
            poseidon,
            prover,
        }
    }
}

impl LabelsumProver<Setup> {
    // Performs setup. Splits plaintext into chunks and computes a hash of each
    // chunk.
    pub fn setup(self) -> Result<LabelsumProver<PlaintextCommitment>, ProverError> {
        if self.state.field_prime.bits() < 129 {
            // last field element must be large enough to contain the 128-bit
            // salt. In the future, if we need to support fields < 129 bits,
            // we can put the salt into multiple field elements.
            return Err(ProverError::WrongPrime);
        }
        let useful_bits = self.calculate_useful_bits(&self.state.field_prime);
        let (chunk_size, chunks, salts) =
            self.plaintext_to_chunks(useful_bits, &self.state.plaintext);
        if chunk_size > MAX_CHUNK_SIZE {
            return Err(ProverError::MaxChunkSizeExceeded);
        }

        Ok(LabelsumProver {
            state: PlaintextCommitment {
                proving_key: self.state.proving_key,
                field_prime: self.state.field_prime,
                useful_bits,
                plaintext: self.state.plaintext,
                chunks,
                salts,
                chunk_size,
            },
            poseidon: self.poseidon,
            prover: self.prover,
        })
    }

    /// Calculates how many bits of plaintext we will pack into one field element.
    /// Essentially, this is field_prime bit length minus 1.
    fn calculate_useful_bits(&self, field_prime: &BigUint) -> usize {
        (field_prime.bits() - 1) as usize
    }

    /// Create chunks of plaintext where each chunk consists of 16 field elements.
    /// The last element's last 128 bits are reserved for the salt of the hash.
    /// If there is not enough plaintext to fill the whole chunk, we fill the gap
    /// with zero bits.
    /// Returns (the size of a chunk (sans the salt), chunks, salts for each chunk)
    fn plaintext_to_chunks(
        &self,
        useful_bits: usize,
        plaintext: &Vec<u8>,
    ) -> (usize, Vec<Vec<BigUint>>, Vec<BigUint>) {
        // the amount of field elements in each chunk
        let fes_per_chunk = POSEIDON_WIDTH * PERMUTATION_COUNT;
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * fes_per_chunk - 128;
        // plaintext converted into bits
        let mut bits = u8vec_to_boolvec(&plaintext);
        // chunk count (rounded up)
        let chunk_count = (bits.len() + (chunk_size - 1)) / chunk_size;

        // extend bits with zeroes to fill the last chunk
        bits.extend(vec![false; chunk_count * chunk_size - bits.len()]);
        let mut chunks: Vec<Vec<BigUint>> = Vec::with_capacity(chunk_count);
        let mut salts: Vec<BigUint> = Vec::with_capacity(chunk_count);

        let mut rng = thread_rng();
        for chunk_of_bits in bits.chunks(chunk_size) {
            let mut chunk: Vec<BigUint> = Vec::with_capacity(fes_per_chunk);

            // split a chunk into field elements
            for (i, fe_bits) in chunk_of_bits.chunks(useful_bits).enumerate() {
                if i < fes_per_chunk - 1 {
                    chunk.push(BigUint::from_bytes_be(&boolvec_to_u8vec(&fe_bits)));
                } else {
                    // last field element's last 128 bits are for the salt
                    let salt = rng.gen::<[u8; 16]>();
                    salts.push(BigUint::from_bytes_be(&salt));
                    let mut bits_and_salt = fe_bits.to_vec();
                    bits_and_salt.extend(u8vec_to_boolvec(&salt).iter());
                    chunk.push(BigUint::from_bytes_be(&boolvec_to_u8vec(&bits_and_salt)));
                };
            }
            chunks.push(chunk);
        }
        (chunk_size, chunks, salts)
    }
}

impl LabelsumProver<PlaintextCommitment> {
    pub fn plaintext_commitment(
        self,
    ) -> Result<(Vec<BigUint>, LabelsumProver<LabelsumCommitment>), ProverError> {
        let hashes = self.hash_chunks(&self.state.chunks)?;

        Ok((
            hashes.clone(),
            LabelsumProver {
                state: LabelsumCommitment {
                    proving_key: self.state.proving_key,
                    field_prime: self.state.field_prime,
                    useful_bits: self.state.useful_bits,
                    plaintext: self.state.plaintext,
                    plaintext_hashes: hashes,
                    chunks: self.state.chunks,
                    salts: self.state.salts,
                    chunk_size: self.state.chunk_size,
                },
                poseidon: self.poseidon,
                prover: self.prover,
            },
        ))
    }

    /// Hashes each chunk with Poseidon and returns digests for each chunk.
    fn hash_chunks(&self, chunks: &Vec<Vec<BigUint>>) -> Result<Vec<BigUint>, ProverError> {
        chunks
            .iter()
            .map(|chunk| {
                if chunk.len() != POSEIDON_WIDTH * PERMUTATION_COUNT {
                    return Err(ProverError::WrongPoseidonInput);
                }
                Ok(self.poseidon.hash(chunk)?)
            })
            .collect()
    }
}

impl LabelsumProver<LabelsumCommitment> {
    /// Computes the sum of all arithmetic labels for each chunk of plaintext.
    /// Returns the hash of each sum.
    pub fn labelsum_commitment(
        self,
        ciphertexts: Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Result<(Vec<BigUint>, LabelsumProver<BinaryLabelsAuthenticated>), ProverError> {
        let sums = self.compute_label_sums(&ciphertexts, labels)?;

        // flatten the ciphertexts and hash them
        let flat: Vec<u8> = ciphertexts
            .iter()
            .map(|pair| {
                let v = pair.to_vec();
                v.into_iter().flatten().collect::<Vec<u8>>()
            })
            .flatten()
            .collect();
        let alct_hash = sha256(&flat);

        let res: Result<Vec<BigUint>, ProverError> = sums
            .iter()
            .zip(self.state.salts.iter())
            .map(|(sum, salt)| {
                let sum = u8vec_to_boolvec(&sum.to_bytes_be());
                let salt = u8vec_to_boolvec(&salt.to_bytes_be());

                // We want to pack `sum` and `salt` into a field element like this:
                // | leading zeroes | sum |       salt        |
                //                         \                 /
                //                          \ last 128 bits /

                let salted_sum_len = self.state.useful_bits;
                let mut salted_sum = vec![false; salted_sum_len];
                salted_sum[salted_sum_len - salt.len()..].copy_from_slice(&salt);
                salted_sum[salted_sum_len - 128 - sum.len()..salted_sum_len - 128]
                    .copy_from_slice(&sum);
                let salted_sum = BigUint::from_bytes_be(&boolvec_to_u8vec(&salted_sum));

                Ok(self.poseidon.hash(&vec![salted_sum.clone()])?)
            })
            .collect();
        if res.is_err() {
            return Err(ProverError::ErrorInPoseidonImplementation);
        }
        let labelsum_hashes = res.unwrap();

        Ok((
            labelsum_hashes.clone(),
            LabelsumProver {
                state: BinaryLabelsAuthenticated {
                    useful_bits: self.state.useful_bits,
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    chunk_size: self.state.chunk_size,
                    labelsum_hashes,
                    plaintext_hashes: self.state.plaintext_hashes,
                    proving_key: self.state.proving_key,
                    salts: self.state.salts,
                    alct_hash,
                },
                poseidon: self.poseidon,
                prover: self.prover,
            },
        ))
    }

    /// Decrypts each encrypted arithm. label based on the point-and-permute
    /// (p&p) bit of our corresponding active binary label. Computes the sum of
    /// all arithmetic labels for each chunk of plaintext. Returns the sums.
    fn compute_label_sums(
        &self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Result<Vec<BigUint>, ProverError> {
        if ciphertexts.len() != labels.len() {
            return Err(ProverError::IncorrectEncryptedLabelSize);
        }
        if self.state.plaintext.len() * 8 != ciphertexts.len() {
            return Err(ProverError::IncorrectEncryptedLabelSize);
        }

        // Each chunk is hashed separately
        let mut label_sum_hashes: Vec<BigUint> = Vec::with_capacity(self.state.chunks.len());

        let ct_iter = ciphertexts.chunks(self.state.chunk_size);
        let lb_iter = labels.chunks(self.state.chunk_size);
        // process a pair (chunk of ciphertexts, chunk of corresponding labels) at a time
        for (chunk_ct, chunk_lb) in ct_iter.zip(lb_iter) {
            // accumulate the label sum for one chunk here
            let mut label_sum = BigUint::from_u8(0).unwrap();
            for (ct_pair, label) in chunk_ct.iter().zip(chunk_lb) {
                let key = Aes128::new_from_slice(&label.to_be_bytes()).unwrap();
                // if binary label's p&p bit is 0, decrypt the 1st ciphertext,
                // otherwise decrypt the 2nd one.
                let mut ct = [0u8; 16];
                if label & 1 == 0 {
                    ct.copy_from_slice(&ct_pair[0]);
                } else {
                    ct.copy_from_slice(&ct_pair[1]);
                }
                let mut ct: GenericArray<u8, U16> = GenericArray::from(ct);
                key.decrypt_block(&mut ct);
                // add the decrypted arithmetic label to the sum
                label_sum += BigUint::from_bytes_be(&ct);
            }

            label_sum_hashes.push(label_sum);
        }
        Ok(label_sum_hashes)
    }
}

impl LabelsumProver<BinaryLabelsAuthenticated> {
    /// A signal whether the committed GC protocol succesfully authenticated
    /// the output labels which we used earlier in the protocol.
    pub fn binary_labels_authenticated(
        self,
        success: bool,
    ) -> Result<LabelsumProver<AuthenticateArithmeticLabels>, ProverError> {
        if success {
            Ok(LabelsumProver {
                state: AuthenticateArithmeticLabels {
                    useful_bits: self.state.useful_bits,
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    chunk_size: self.state.chunk_size,
                    labelsum_hashes: self.state.labelsum_hashes,
                    plaintext_hashes: self.state.plaintext_hashes,
                    proving_key: self.state.proving_key,
                    salts: self.state.salts,
                    alct_hash: self.state.alct_hash,
                },
                poseidon: self.poseidon,
                prover: self.prover,
            })
        } else {
            Err(ProverError::BinaryLabelsAuthenticationFailed)
        }
    }
}

impl LabelsumProver<AuthenticateArithmeticLabels> {
    pub fn authenticate_arithmetic_labels(
        self,
        seed: Seed,
    ) -> Result<LabelsumProver<ProofCreation>, ProverError> {
        let gen = LabelGenerator::new_from_seed(seed);
        let label_pairs = gen.generate(self.state.plaintext.len() * 8, ARITHMETIC_LABEL_SIZE);

        Ok(LabelsumProver {
            state: ProofCreation {
                useful_bits: self.state.useful_bits,
                plaintext: self.state.plaintext,
                chunks: self.state.chunks,
                chunk_size: self.state.chunk_size,
                labelsum_hashes: self.state.labelsum_hashes,
                plaintext_hashes: self.state.plaintext_hashes,
                proving_key: self.state.proving_key,
                salts: self.state.salts,
            },
            poseidon: self.poseidon,
            prover: self.prover,
        })
    }
}

impl LabelsumProver<ProofCreation> {
    // Creates a zk proof of label decoding for each chunk of plaintext. Returns
    // proofs in the snarkjs's "proof.json" format
    pub fn create_zk_proof(
        self,
        zero_sum: Vec<BigUint>,
        deltas: Vec<BigUint>,
    ) -> Result<(Vec<Vec<u8>>, LabelsumProver<ProofReady>), ProverError> {
        let inputs = self.create_proof_inputs(zero_sum, deltas);
        let mut proofs = Vec::with_capacity(inputs.len());
        for input in inputs {
            proofs.push(self.prover.prove(input, &self.state.proving_key)?);
        }
        Ok((
            proofs.clone(),
            LabelsumProver {
                state: ProofReady {
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    plaintext_hashes: self.state.plaintext_hashes,
                    proofs,
                },
                poseidon: self.poseidon,
                prover: self.prover,
            },
        ))
    }

    // Creates inputs in the "input.json" format
    fn create_proof_inputs(&self, zero_sum: Vec<BigUint>, mut deltas: Vec<BigUint>) -> Vec<String> {
        // Since the last chunk is padded with zero plaintext, we also zero-pad
        // the corresponding deltas of the last chunk.
        let delta_pad_count = self.state.chunk_size * self.state.chunks.len() - deltas.len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);

        // we will have as many proofs as there are chunks of plaintext
        let mut inputs: Vec<String> = Vec::with_capacity(self.state.chunks.len());
        let chunks_of_deltas: Vec<&[BigUint]> = deltas.chunks(self.state.chunk_size).collect();

        for count in 0..self.state.chunks.len() {
            // convert each field element of plaintext into a string
            let plaintext: Vec<String> = self.state.chunks[count]
                .iter()
                .map(|bigint| bigint.to_string())
                .collect();

            // convert all deltas to strings
            let deltas_str: Vec<String> = chunks_of_deltas[count]
                .iter()
                .map(|v| v.to_string())
                .collect();

            // split deltas into groups corresponding to the field elements
            // of our Poseidon circuit
            let deltas_fes: Vec<&[String]> = deltas_str.chunks(self.state.useful_bits).collect();

            // prepare input.json
            let input = object! {
                plaintext_hash: self.state.plaintext_hashes[count].to_string(),
                label_sum_hash: self.state.labelsum_hashes[count].to_string(),
                sum_of_zero_labels: zero_sum[count].to_string(),
                plaintext: plaintext,
                labelsum_salt: self.state.salts[count].to_string(),
                delta: deltas_fes[0..deltas_fes.len()-1],
                // last field element's deltas are a separate input
                delta_last: deltas_fes[deltas_fes.len()-1]
            };
            let s = stringify_pretty(input, 4);
            inputs.push(s);
        }
        inputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provernode::ProverNode;
    use num::ToPrimitive;

    #[test]
    // fn test_calculate_useful_bits() {
    //     use crate::BN254_PRIME;
    //     let prover = ProverMock::new();

    //     assert_eq!(
    //         prover.calculate_useful_bits(&BigUint::from_u16(13).unwrap()),
    //         3
    //     );
    //     assert_eq!(
    //         prover.calculate_useful_bits(&BigUint::from_u16(255).unwrap()),
    //         7
    //     );
    //     assert_eq!(
    //         prover.calculate_useful_bits(&String::from(BN254_PRIME,).parse::<BigUint>().unwrap()),
    //         253
    //     );
    // }
    #[test]
    // fn test_plaintext_to_chunks() {
    //     // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
    //     let mut prime = vec![false; 137];
    //     prime[0] = true;
    //     let prime = boolvec_to_u8vec(&prime);
    //     let prime = BigUint::from_bytes_be(&prime);
    //     // plaintext will spawn 2 chunks
    //     let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
    //     // first chunk's field elements
    //     for i in 0..15 {
    //         // make the last byte of each field element unique
    //         plaintext[i * 17 + 16] = i as u8;
    //     }
    //     // first chunk's last field element's plaintext is 1 zero byte. The
    //     // rest of the field element will be filled with salt
    //     plaintext[15 * 17] = 0u8;

    //     // second chunk's field elements
    //     for i in 0..5 {
    //         // make the last byte of each field element unique
    //         plaintext[(15 * 17 + 1) + i * 17 + 16] = (i + 16) as u8;
    //     }

    //     let mut prover = ProverMock::new();
    //     prover.setup(prime, plaintext);

    //     // Check chunk1 correctness
    //     let chunk1: Vec<u128> = prover.data().chunks().clone().unwrap()[0][0..15]
    //         .iter()
    //         .map(|bigint| bigint.to_u128().unwrap())
    //         .collect();
    //     assert_eq!(chunk1, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    //     // the last field element must be random salt. We just check that the
    //     // salt has been set, i.e. it is not equal 0
    //     assert!(!prover.data().chunks().clone().unwrap()[0][15].eq(&BigUint::from_u8(0).unwrap()));

    //     // Check chunk2 correctness
    //     let chunk2: Vec<u128> = prover.data().chunks().clone().unwrap()[1][0..15]
    //         .iter()
    //         .map(|bigint| bigint.to_u128().unwrap())
    //         .collect();
    //     assert_eq!(chunk2, [16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    //     // the last field element must be random salt. We just check that the
    //     // salt has been set, i.e. it is not equal 0
    //     assert!(!prover.data().chunks().clone().unwrap()[1][15].eq(&BigUint::from_u8(0).unwrap()));
    // }
    #[test]
    // fn test_compute_label_sums() {
    //     // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
    //     let mut prime = vec![false; 137];
    //     prime[0] = true;
    //     let prime = boolvec_to_u8vec(&prime);
    //     let prime = BigUint::from_bytes_be(&prime);
    //     // plaintext will spawn 2 chunks
    //     let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
    //     let mut prover = ProverNode::new();
    //     //LsumProver::hash_chunks(&mut prover);
    // }
    #[test]
    fn test_json() {
        let mut prime = vec![false; 137];
        prime[0] = true;
        let prime = boolvec_to_u8vec(&prime);
        let prime = BigUint::from_bytes_be(&prime);
        let v = vec![BigUint::from_u8(0).unwrap(), BigUint::from_u8(1).unwrap()];
        let v_str: Vec<String> = v.iter().map(|bigint| bigint.to_string()).collect();
        let mut data = object! {
            foo:v_str
        };
        println!("{:?}", data.dump());
    }
}
