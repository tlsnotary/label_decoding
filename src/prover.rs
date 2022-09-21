use std::ops::Shl;

use crate::label::{LabelGenerator, Seed};
use crate::utils::{
    bits_to_bigint, compute_zero_sum_and_deltas, encrypt_arithmetic_labels, sha256,
    u8vec_to_boolvec,
};
use crate::{Chunk, Delta, LabelsumHash, Plaintext, PlaintextHash, Proof, Salt, ZeroSum};
use crate::{ARITHMETIC_LABEL_SIZE, MAX_CHUNK_COUNT, MAX_CHUNK_SIZE};
use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray};
use num::{BigUint, FromPrimitive};
use rand::{thread_rng, Rng};

#[derive(Debug, PartialEq)]
pub enum ProverError {
    EmptyPlaintext,
    NoRoomForSalt,
    MaxChunkSizeExceeded,
    MaxChunkCountExceeded,
    WrongFieldElementCount,
    WrongPoseidonInput,
    IncorrectEncryptedLabelSize,
    IncorrectBinaryLabelSize,
    ErrorInPoseidonImplementation,
    BinaryLabelAuthenticationFailed,
    BinaryLabelsNotProvided,
    ArithmeticLabelAuthenticationFailed,
    ProvingBackendError,
    WrongLastFieldElementBitCount,
    InternalError,
}

#[derive(Clone, Default)]
// Public and private inputs to the zk circuit
pub struct ProofInput {
    // Public
    pub plaintext_hash: PlaintextHash,
    pub label_sum_hash: LabelsumHash,
    pub sum_of_zero_labels: ZeroSum,
    pub deltas: Vec<Delta>,

    // Private
    pub plaintext: Chunk,
    pub salt: Salt,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ArithmeticLabelCheck([u8; 32]);

impl ArithmeticLabelCheck {
    /// Stores the hash of encrypted arithmetic labels. This hash will be checked
    /// against later when the Notary "opens" all the arithmetic labels and
    /// the garbled circuit's output labels which were used as keys to encrypt
    /// the arithmetic labels.
    /// This technique of "opening" the labels is similar to committed OT
    /// (Oblivious Transfer), where the OT sender reveals all the OT messages that
    /// he sent and the keys which he used to encrypt those messages.
    ///
    /// The purpose of this check is to detect when a malicious Notary sends
    /// a false arithmetic label which (if chosen by the User) would prevent the
    /// User from creating a zk proof. By observing whether the User succeeded in
    /// creating a zk proof, the Notary could infer whether the false label was chosen
    /// and would learn 1 bit about the User's secret plaintext.
    pub fn new(ciphertexts: &Vec<[[u8; 16]; 2]>) -> Self {
        // flatten the ciphertexts and hash them
        let flat: Vec<u8> = ciphertexts
            .iter()
            .map(|pair| pair.to_vec().into_iter().flatten().collect::<Vec<u8>>())
            .flatten()
            .collect();
        Self(sha256(&flat))
    }
}

pub trait State {}

#[derive(Default)]
pub struct Setup {
    plaintext: Plaintext,
}
impl State for Setup {}

// see comments to the field's type.
#[derive(Default)]
pub struct PlaintextCommitment {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
}
impl State for PlaintextCommitment {}

// see comments to the field's type.
#[derive(Default)]
pub struct LabelsumCommitment {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
    plaintext_hashes: Vec<PlaintextHash>,
}
impl State for LabelsumCommitment {}

// see comments to the field's type.
#[derive(Default)]
pub struct BinaryLabelsAuthenticated {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
    plaintext_hashes: Vec<PlaintextHash>,
    labelsum_hashes: Vec<LabelsumHash>,
    arith_label_check: ArithmeticLabelCheck,
}
impl State for BinaryLabelsAuthenticated {}

// see comments to the field's type.
#[derive(Default)]
pub struct AuthenticateArithmeticLabels {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
    plaintext_hashes: Vec<PlaintextHash>,
    labelsum_hashes: Vec<LabelsumHash>,
    arith_label_check: ArithmeticLabelCheck,
    // Garbled circuit's output labels. We call them "binary" to distinguish
    // them from the arithmetic labels.
    all_binary_labels: Vec<[u128; 2]>,
}
impl State for AuthenticateArithmeticLabels {}

// see comments to the field's type.
pub struct ProofCreation {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
    plaintext_hashes: Vec<PlaintextHash>,
    labelsum_hashes: Vec<LabelsumHash>,
    deltas: Vec<Delta>,
    zero_sums: Vec<ZeroSum>,
}
impl State for ProofCreation {}

// see comments to the field's type.
pub struct Finished {
    plaintext: Plaintext,
    chunks: Vec<Chunk>,
    salts: Vec<Salt>,
    plaintext_hashes: Vec<PlaintextHash>,
    proofs: Vec<Proof>,
}
impl State for Finished {}

pub trait Prove {
    /// Given the `input` to the labelsum zk circuit, returns a serialized zk
    /// proof which can be passed to the Verifier.
    fn prove(&self, input: ProofInput) -> Result<Proof, ProverError>;

    /// Returns how many bits of plaintext we will pack into one field element.
    /// Normally, this should be [crate::Verify::field_size] minus 1.
    fn useful_bits(&self) -> usize;

    /// How many field elements the Poseidon hash consumes for one permutation.
    fn poseidon_rate(&self) -> usize;

    /// How many permutations the circuit supports. One permutation consumes
    /// [Prove::poseidon_rate()] field elements.
    fn permutation_count(&self) -> usize;

    /// The size of the hash's salt in bits. The salt takes up the least
    /// bits of the last field element.
    fn salt_size(&self) -> usize;

    /// How many bits of [Plaintext] can fit into one [Chunk]. This does not
    /// include the [Salt] of the hash - which takes up the remaining least bits
    /// of the last field element of each chunk.
    fn chunk_size(&self) -> usize;

    /// Evaluates the Poseidon hash on `inputs` and returns the digest.
    fn hash(&self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError>;
}

pub struct LabelsumProver<S = Setup>
where
    S: State,
{
    prover: Box<dyn Prove>,
    state: S,
}

impl LabelsumProver {
    /// Returns the next expected state.
    pub fn new(plaintext: Plaintext, prover: Box<dyn Prove>) -> LabelsumProver<Setup> {
        LabelsumProver {
            state: Setup { plaintext },
            prover,
        }
    }
}

impl LabelsumProver<Setup> {
    // Performs setup. Splits plaintext into chunks and computes a hash of each
    // chunk. Returns the next expected state.
    pub fn setup(self) -> Result<LabelsumProver<PlaintextCommitment>, ProverError> {
        if self.state.plaintext.len() == 0 {
            return Err(ProverError::EmptyPlaintext);
        }
        if self.prover.useful_bits() < self.prover.salt_size() {
            // last field element must be large enough to contain the salt.
            // In the future, if we need to support fields < salt,
            // we can put the salt into multiple field elements.
            return Err(ProverError::NoRoomForSalt);
        }
        if self.prover.chunk_size() > MAX_CHUNK_SIZE {
            return Err(ProverError::MaxChunkSizeExceeded);
        }
        let (chunks, salts) = self.plaintext_to_chunks(&self.state.plaintext)?;

        Ok(LabelsumProver {
            state: PlaintextCommitment {
                plaintext: self.state.plaintext,
                chunks,
                salts,
            },
            prover: self.prover,
        })
    }

    /// Creates chunks of plaintext (each chunk will have a separate zk proof).
    /// If there is not enough plaintext to fill the whole chunk, we fill the gap
    /// with zero bits. Returns all [Chunk]s and all [Salt]s.
    fn plaintext_to_chunks(
        &self,
        plaintext: &Plaintext,
    ) -> Result<(Vec<Chunk>, Vec<Salt>), ProverError> {
        // chunk size
        let cs = &self.prover.chunk_size();

        // the amount of field elements per chunk
        let fes_per_chunk = (cs + self.prover.salt_size()) / self.prover.useful_bits();

        if fes_per_chunk != self.prover.poseidon_rate() * self.prover.permutation_count() {
            // can only happen if there is a logic error in `Prove` impl
            return Err(ProverError::WrongFieldElementCount);
        }

        let mut bits = u8vec_to_boolvec(&plaintext);

        // chunk count (rounded up)
        let chunk_count = (bits.len() + (cs - 1)) / cs;
        if chunk_count > MAX_CHUNK_COUNT {
            return Err(ProverError::MaxChunkCountExceeded);
        }

        // extend bits with zeroes to fill the last chunk
        bits.extend(vec![false; chunk_count * cs - bits.len()]);

        let mut rng = thread_rng();

        Ok(bits
            .chunks(*cs)
            .map(|chunk_of_bits| {
                // chunk of field elements
                let chunk_of_fes: Chunk = chunk_of_bits
                    .chunks(self.prover.useful_bits())
                    .map(|fe| bits_to_bigint(fe))
                    .collect();

                // generate the salt for this chunk. Do not apply the salt to the
                // chunk but store it separately.
                let salt: Vec<bool> = core::iter::repeat_with(|| rng.gen::<bool>())
                    .take(self.prover.salt_size())
                    .collect::<Vec<_>>();

                (chunk_of_fes, bits_to_bigint(&salt))
            })
            .unzip())
    }
}

impl LabelsumProver<PlaintextCommitment> {
    /// Returns a vec of [Salt]ed Poseidon hashes for each [Chunk] and the next
    /// expected state.
    pub fn plaintext_commitment(
        self,
    ) -> Result<(Vec<PlaintextHash>, LabelsumProver<LabelsumCommitment>), ProverError> {
        let hashes = self.salt_and_hash_chunks(&self.state.chunks, &self.state.salts)?;

        Ok((
            hashes.clone(),
            LabelsumProver {
                state: LabelsumCommitment {
                    plaintext: self.state.plaintext,
                    plaintext_hashes: hashes,
                    chunks: self.state.chunks,
                    salts: self.state.salts,
                },
                prover: self.prover,
            },
        ))
    }

    /// Salts and hashes each chunk with Poseidon and returns digests for each
    /// salted chunk.
    fn salt_and_hash_chunks(
        &self,
        chunks: &Vec<Chunk>,
        salts: &Vec<Salt>,
    ) -> Result<Vec<BigUint>, ProverError> {
        chunks
            .iter()
            .zip(salts.iter())
            .map(|(chunk, salt)| {
                let salted_chunk = self.salt_chunk(chunk, salt)?;
                Ok(self.prover.hash(&salted_chunk)?)
            })
            .collect()
    }

    /// Puts salt into the low bits of the last field element of the chunk.
    /// Returns the salted chunk.
    fn salt_chunk(&self, chunk: &Chunk, salt: &Salt) -> Result<Chunk, ProverError> {
        let len = chunk.len();
        let last_fe = chunk[len - 1].clone();

        if last_fe.bits() as usize > self.prover.useful_bits() - self.prover.salt_size() {
            // can only happen if there is a logic error in this code
            return Err(ProverError::WrongLastFieldElementBitCount);
        }

        let mut salted_chunk = chunk.clone();
        salted_chunk[len - 1] = last_fe.shl(self.prover.salt_size()) + salt;
        Ok(salted_chunk)
    }
}

impl LabelsumProver<LabelsumCommitment> {
    /// Computes the sum of all arithmetic labels for each chunk of plaintext.
    /// Returns the [Salt]ed hash of each sum and the next expected state.
    pub fn labelsum_commitment(
        self,
        ciphertexts: Vec<[[u8; 16]; 2]>,
        labels: &Vec<u128>,
    ) -> Result<(Vec<LabelsumHash>, LabelsumProver<BinaryLabelsAuthenticated>), ProverError> {
        let sums = self.compute_label_sums(&ciphertexts, labels)?;

        let arith_label_check = ArithmeticLabelCheck::new(&ciphertexts);

        let res: Result<Vec<LabelsumHash>, ProverError> = sums
            .iter()
            .zip(self.state.salts.iter())
            .map(|(sum, salt)| {
                // We want to pack `sum` and `salt` into a field element like this:
                // | leading zeroes | sum |       salt        |
                //                         \                 /
                //                          \    low bits   /
                let salted_sum = sum.shl(self.prover.salt_size()) + salt;

                Ok(self.prover.hash(&vec![salted_sum.clone()])?)
            })
            .collect();
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        let labelsum_hashes = res.unwrap();

        Ok((
            labelsum_hashes.clone(),
            LabelsumProver {
                state: BinaryLabelsAuthenticated {
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    labelsum_hashes,
                    plaintext_hashes: self.state.plaintext_hashes,
                    salts: self.state.salts,
                    arith_label_check,
                },
                prover: self.prover,
            },
        ))
    }

    /// Returns the sum of all arithmetic labels for each [Chunk] of plaintext by
    /// first decrypting each encrypted arithmetic label based on the pointer bit
    /// of the corresponding active binary label.
    fn compute_label_sums(
        &self,
        ciphertexts: &Vec<[[u8; 16]; 2]>,
        binary_labels: &Vec<u128>,
    ) -> Result<Vec<BigUint>, ProverError> {
        if ciphertexts.len() != self.state.plaintext.len() * 8 {
            return Err(ProverError::IncorrectEncryptedLabelSize);
        }
        if binary_labels.len() != self.state.plaintext.len() * 8 {
            return Err(ProverError::IncorrectBinaryLabelSize);
        }

        let res = ciphertexts
            .chunks(self.prover.chunk_size())
            .zip(binary_labels.chunks(self.prover.chunk_size()))
            .map(|(chunk_ct, chunk_lb)| {
                // accumulate the label sum for one chunk here
                let mut label_sum = BigUint::from_u8(0).unwrap();

                for (ct_pair, label) in chunk_ct.iter().zip(chunk_lb) {
                    let key = Aes128::new_from_slice(&label.to_be_bytes()).unwrap();
                    // if binary label's LSB is 0, decrypt the 1st ciphertext,
                    // otherwise decrypt the 2nd one.
                    let mut ct = if label & 1 == 0 {
                        GenericArray::from(ct_pair[0])
                    } else {
                        GenericArray::from(ct_pair[1])
                    };
                    key.decrypt_block(&mut ct);
                    // add the decrypted arithmetic label to the sum
                    label_sum += BigUint::from_bytes_be(&ct);
                }

                label_sum
            })
            .collect();
        Ok(res)
    }
}

impl LabelsumProver<BinaryLabelsAuthenticated> {
    /// Expects a signal whether the `committed GC` protocol succesfully authenticated
    /// the output labels which we used earlier in the protocol. Returns the
    /// next expected state.
    pub fn binary_labels_authenticated(
        self,
        success: bool,
        all_binary_labels: Option<Vec<[u128; 2]>>,
    ) -> Result<LabelsumProver<AuthenticateArithmeticLabels>, ProverError> {
        if success {
            if all_binary_labels.is_none() {
                return Err(ProverError::BinaryLabelsNotProvided);
            }

            Ok(LabelsumProver {
                state: AuthenticateArithmeticLabels {
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    labelsum_hashes: self.state.labelsum_hashes,
                    plaintext_hashes: self.state.plaintext_hashes,
                    salts: self.state.salts,
                    arith_label_check: self.state.arith_label_check,
                    all_binary_labels: all_binary_labels.unwrap(),
                },
                prover: self.prover,
            })
        } else {
            Err(ProverError::BinaryLabelAuthenticationFailed)
        }
    }
}

impl LabelsumProver<AuthenticateArithmeticLabels> {
    /// Authenticates the arithmetic labels which were used earlier in
    /// [LabelsumProver<LabelsumCommitment>] by first re-generating the
    /// arithmetic labels from a seed and then encrypting them with binary
    /// labels. The resulting ciphertext must match the ciphertext which was
    /// sent to us in [LabelsumProver<LabelsumCommitment>]. Returns the next
    ///  expected state.
    pub fn authenticate_arithmetic_labels(
        self,
        seed: Seed,
    ) -> Result<LabelsumProver<ProofCreation>, ProverError> {
        let alabels = LabelGenerator::generate_from_seed(
            self.state.all_binary_labels.len(),
            ARITHMETIC_LABEL_SIZE,
            seed,
        );
        // Encrypt the arithm labels with binary labels and compare the resulting
        // ciphertext with the ciphertext which the Verifier sent to us earlier.
        let ciphertexts = match encrypt_arithmetic_labels(&alabels, &self.state.all_binary_labels) {
            Ok(ct) => ct,
            Err(_) => return Err(ProverError::InternalError),
        };

        if ArithmeticLabelCheck::new(&ciphertexts) != self.state.arith_label_check {
            return Err(ProverError::ArithmeticLabelAuthenticationFailed);
        }

        // There will be as many deltas as there are output labels in the
        // garbled circuit.
        let mut deltas: Vec<Delta> = Vec::with_capacity(self.state.all_binary_labels.len());

        let zero_sums: Vec<ZeroSum> = alabels
            .chunks(self.prover.chunk_size())
            .map(|chunk_of_alabel_pairs| {
                let (zero_sum, deltas_in_chunk) =
                    compute_zero_sum_and_deltas(chunk_of_alabel_pairs);
                deltas.extend(deltas_in_chunk);
                zero_sum
            })
            .collect();

        Ok(LabelsumProver {
            state: ProofCreation {
                plaintext: self.state.plaintext,
                chunks: self.state.chunks,
                labelsum_hashes: self.state.labelsum_hashes,
                plaintext_hashes: self.state.plaintext_hashes,
                salts: self.state.salts,
                deltas,
                zero_sums,
            },
            prover: self.prover,
        })
    }
}

impl LabelsumProver<ProofCreation> {
    // Creates zk proofs of label decoding for each chunk of plaintext. Returns
    // a vec of serialized proofs and the next expected state.
    pub fn create_zk_proofs(self) -> Result<(Vec<Vec<u8>>, LabelsumProver<Finished>), ProverError> {
        let proofs = self
            .create_zkproof_inputs(&self.state.zero_sums, self.state.deltas.clone())
            .iter()
            .map(|i| self.prover.prove(i.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok((
            proofs.clone(),
            LabelsumProver {
                state: Finished {
                    plaintext: self.state.plaintext,
                    chunks: self.state.chunks,
                    plaintext_hashes: self.state.plaintext_hashes,
                    salts: self.state.salts,
                    proofs,
                },
                prover: self.prover,
            },
        ))
    }

    /// Returns [ProofInput]s for each [Chunk].
    fn create_zkproof_inputs(
        &self,
        zero_sum: &Vec<ZeroSum>,
        mut deltas: Vec<Delta>,
    ) -> Vec<ProofInput> {
        // Since the last chunk is padded with zero plaintext, we also zero-pad
        // the corresponding deltas of the last chunk.
        let delta_pad_count = self.prover.chunk_size() * self.state.chunks.len() - deltas.len();
        deltas.extend(vec![Delta::from(0u8); delta_pad_count]);

        // we will have as many chunks of deltas as there are chunks of plaintext
        let chunks_of_deltas: Vec<Vec<Delta>> = deltas
            .chunks(self.prover.chunk_size())
            .map(|i| i.to_vec())
            .collect();

        (0..self.state.chunks.len())
            .map(|i| ProofInput {
                plaintext_hash: self.state.plaintext_hashes[i].clone(),
                label_sum_hash: self.state.labelsum_hashes[i].clone(),
                sum_of_zero_labels: zero_sum[i].clone(),
                plaintext: self.state.chunks[i].clone(),
                salt: self.state.salts[i].clone(),
                deltas: chunks_of_deltas[i].clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, FromPrimitive};
    use rayon::vec;
    use std::str::FromStr;

    use super::Prove;
    use crate::prover::AuthenticateArithmeticLabels;
    use crate::prover::BinaryLabelsAuthenticated;
    use crate::prover::LabelsumCommitment;
    use crate::prover::LabelsumProver;
    use crate::prover::PlaintextCommitment;
    use crate::prover::ProofInput;
    use crate::prover::ProverError;
    use crate::prover::Setup;
    use crate::Plaintext;
    use crate::Proof;

    /// The prover who implements `Prove` with the correct values
    struct CorrectTestProver {}
    impl Prove for CorrectTestProver {
        fn prove(&self, _: ProofInput) -> Result<Proof, ProverError> {
            Ok(Proof::default())
        }

        fn useful_bits(&self) -> usize {
            253
        }

        fn poseidon_rate(&self) -> usize {
            15
        }

        fn permutation_count(&self) -> usize {
            1
        }

        fn salt_size(&self) -> usize {
            125
        }

        fn chunk_size(&self) -> usize {
            3670
        }

        fn hash(&self, _: &Vec<BigUint>) -> Result<BigUint, ProverError> {
            Ok(BigUint::default())
        }
    }

    #[test]
    /// Inputs empty plaintext and triggers [ProverError::EmptyPlaintext]
    fn test_error_empty_plaintext() {
        let lsp = LabelsumProver {
            state: Setup { plaintext: vec![] },
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.setup();

        assert_eq!(res.err().unwrap(), ProverError::EmptyPlaintext);
    }

    #[test]
    /// Sets useful_bits() < salt_size() and triggers [ProverError::NoRoomForSalt]
    fn test_error_no_room_for_salt() {
        struct TestProver {}
        impl Prove for TestProver {
            fn prove(&self, _input: ProofInput) -> Result<Proof, ProverError> {
                Ok(Proof::default())
            }

            fn useful_bits(&self) -> usize {
                124 //changed from 253
            }

            fn poseidon_rate(&self) -> usize {
                15
            }

            fn permutation_count(&self) -> usize {
                1
            }

            fn salt_size(&self) -> usize {
                125
            }

            fn chunk_size(&self) -> usize {
                3670
            }

            fn hash(&self, _inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
                Ok(BigUint::default())
            }
        }

        let lsp = LabelsumProver {
            state: Setup {
                plaintext: vec![0u8; 1],
            },
            prover: Box::new(TestProver {}),
        };
        let res = lsp.setup();

        assert_eq!(res.err().unwrap(), ProverError::NoRoomForSalt);
    }

    #[test]
    /// Sets chunk_size() > MAX_CHUNK_SIZE and triggers [ProverError::MaxChunkSizeExceeded]
    fn test_error_max_chunk_size_exceeded() {
        struct TestProver {}
        impl Prove for TestProver {
            fn prove(&self, _input: ProofInput) -> Result<Proof, ProverError> {
                Ok(Proof::default())
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn poseidon_rate(&self) -> usize {
                15
            }

            fn permutation_count(&self) -> usize {
                1
            }

            fn salt_size(&self) -> usize {
                125
            }

            fn chunk_size(&self) -> usize {
                super::MAX_CHUNK_SIZE + 1 //changed from 3670
            }

            fn hash(&self, _inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
                Ok(BigUint::default())
            }
        }

        let lsp = LabelsumProver {
            state: Setup {
                plaintext: vec![0u8; 1],
            },
            prover: Box::new(TestProver {}),
        };
        let res = lsp.setup();

        assert_eq!(res.err().unwrap(), ProverError::MaxChunkSizeExceeded);
    }

    #[test]
    /// Sets poseidon_rate() too low and triggers [ProverError::WrongFieldElementCount]
    fn test_error_wrong_field_element_count() {
        struct TestProver {}
        impl Prove for TestProver {
            fn prove(&self, _input: ProofInput) -> Result<Proof, ProverError> {
                Ok(Proof::default())
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn poseidon_rate(&self) -> usize {
                14 //changed from 15
            }

            fn permutation_count(&self) -> usize {
                1
            }

            fn salt_size(&self) -> usize {
                125
            }

            fn chunk_size(&self) -> usize {
                3670
            }

            fn hash(&self, _inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
                Ok(BigUint::default())
            }
        }

        let lsp = LabelsumProver {
            state: Setup {
                plaintext: vec![0u8; 1],
            },
            prover: Box::new(TestProver {}),
        };
        let res = lsp.setup();

        assert_eq!(res.err().unwrap(), ProverError::WrongFieldElementCount);
    }

    #[test]
    /// Inputs too much plaintext and triggers [ProverError::MaxChunkCountExceeded]
    fn test_error_max_chunk_count_exceeded() {
        let lsp = LabelsumProver {
            state: Setup {
                plaintext: vec![0u8; 1000000],
            },
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.setup();

        assert_eq!(res.err().unwrap(), ProverError::MaxChunkCountExceeded);
    }

    #[test]
    /// Returns [ProverError::ErrorInPoseidonImplementation] when attempting to hash
    fn test_error_error_in_poseidon_implementation() {
        struct TestProver {}
        impl Prove for TestProver {
            fn prove(&self, _input: ProofInput) -> Result<Proof, ProverError> {
                Ok(Proof::default())
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn poseidon_rate(&self) -> usize {
                15
            }

            fn permutation_count(&self) -> usize {
                1
            }

            fn salt_size(&self) -> usize {
                125
            }

            fn chunk_size(&self) -> usize {
                3670
            }

            fn hash(&self, _inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
                Err(ProverError::ErrorInPoseidonImplementation)
            }
        }

        let lsp = LabelsumProver::new(Plaintext::default(), Box::new(TestProver {}));
        let res = lsp.prover.hash(&[BigUint::default()].to_vec());

        assert_eq!(
            res.err().unwrap(),
            ProverError::ErrorInPoseidonImplementation
        );
    }

    #[test]
    /// Sets too few ciphertexts and triggers [ProverError::IncorrectEncryptedLabelSize]
    fn test_error_incorrect_encrypted_label_size() {
        let ciphertexts = vec![[[0u8; 16], [0u8; 16]]];
        let labels = vec![0u128];

        let lsp = LabelsumProver {
            state: LabelsumCommitment::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.labelsum_commitment(ciphertexts, &labels);

        assert_eq!(res.err().unwrap(), ProverError::IncorrectEncryptedLabelSize);
    }

    #[test]
    /// Sets too few binary labels and triggers [ProverError::IncorrectBinaryLabelSize]
    fn test_error_incorrect_binary_label_size() {
        let pt_len = 1000;
        let ciphertexts = vec![[[0u8; 16], [0u8; 16]]; pt_len * 8];
        let labels = vec![0u128];

        let lsp = LabelsumProver {
            state: LabelsumCommitment {
                plaintext: vec![0u8; pt_len],
                ..Default::default()
            },
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.labelsum_commitment(ciphertexts, &labels);

        assert_eq!(res.err().unwrap(), ProverError::IncorrectBinaryLabelSize);
    }

    #[test]
    /// Doesn't provide binary labels and triggers [ProverError::BinaryLabelsNotProvided]
    fn test_error_binary_labels_not_provided() {
        let lsp = LabelsumProver {
            state: BinaryLabelsAuthenticated::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.binary_labels_authenticated(true, None);

        assert_eq!(res.err().unwrap(), ProverError::BinaryLabelsNotProvided);
    }

    #[test]
    /// Receives a `false` signal and triggers [ProverError::BinaryLabelAuthenticationFailed]
    fn test_error_binary_label_authentication_failed() {
        let lsp = LabelsumProver {
            state: BinaryLabelsAuthenticated::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.binary_labels_authenticated(false, Some(vec![[0u128, 0u128]]));

        assert_eq!(
            res.err().unwrap(),
            ProverError::BinaryLabelAuthenticationFailed
        );
    }

    #[test]
    /// Provides the wrong seed and triggers [ProverError::ArithmeticLabelAuthenticationFailed]
    fn test_error_arithmetic_label_authentication_failed() {
        let lsp = LabelsumProver {
            state: AuthenticateArithmeticLabels::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        let res = lsp.authenticate_arithmetic_labels([0u8; 32]);

        assert_eq!(
            res.err().unwrap(),
            ProverError::ArithmeticLabelAuthenticationFailed
        );
    }

    #[test]
    /// Returns [ProverError::ProvingBackendError] when attempting to prove
    fn test_error_proving_backend_error() {
        struct TestProver {}
        impl Prove for TestProver {
            fn prove(&self, _input: ProofInput) -> Result<Proof, ProverError> {
                Err(ProverError::ProvingBackendError)
            }

            fn useful_bits(&self) -> usize {
                253
            }

            fn poseidon_rate(&self) -> usize {
                15
            }

            fn permutation_count(&self) -> usize {
                1
            }

            fn salt_size(&self) -> usize {
                125
            }

            fn chunk_size(&self) -> usize {
                3670
            }

            fn hash(&self, _inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
                Ok(BigUint::default())
            }
        }

        let lsp = LabelsumProver::new(Plaintext::default(), Box::new(TestProver {}));
        let res = lsp.prover.prove(ProofInput::default());

        assert_eq!(res.err().unwrap(), ProverError::ProvingBackendError);
    }

    #[test]
    /// Tests LabelsumProver<Setup>::plaintext_to_chunks()
    fn test_plaintext_to_chunks() {
        let lsp = LabelsumProver {
            state: Setup::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        // Should return 1 chunk
        let size = lsp.prover.chunk_size() / 8 - 1;
        let (chunks, salts) = lsp.plaintext_to_chunks(&vec![0u8; size]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(salts.len(), 1);

        // Should return 1 chunk
        let size = lsp.prover.chunk_size() / 8;
        let (chunks, salts) = lsp.plaintext_to_chunks(&vec![0u8; size]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(salts.len(), 1);

        // Should return 2 chunks
        let size = lsp.prover.chunk_size() / 8 + 1;
        let (chunks, salts) = lsp.plaintext_to_chunks(&vec![0u8; size]).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(salts.len(), 2);
    }

    #[test]
    /// Tests LabelsumProver<PlaintextCommitment>::salt_chunk()
    fn test_salt_chunk() {
        let lsp = LabelsumProver {
            state: PlaintextCommitment::default(),
            prover: Box::new(CorrectTestProver {}),
        };
        let chunk: Vec<BigUint> = vec![0u128.into(), 0u128.into()];
        let salt = 1234567890u128.into();
        let salted_chunk = lsp.salt_chunk(&chunk, &salt).unwrap();
        assert_eq!(salted_chunk, [0u128.into(), 1234567890u128.into()]);
    }
}
