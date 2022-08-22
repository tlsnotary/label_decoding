use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray};
use derive_macro::{define_accessors_trait, ProverDataGetSet};
use json::{object, stringify_pretty};
use num::{BigUint, FromPrimitive};
use rand::{thread_rng, Rng};

use super::{PERMUTATION_COUNT, POSEIDON_WIDTH};

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
}

/// ProverData contains data common to all implementors of Prover.
/// We use a macro to define a trait with accessors and another macro
/// to implement those accessors.
#[define_accessors_trait(ProverDataGetSet)]
#[derive(ProverDataGetSet)]
pub struct ProverData {
    // bytes of the plaintext which was obtained from the garbled circuit
    plaintext: Option<Vec<u8>>,
    // the prime of the field in which Poseidon hash will be computed.
    field_prime: Option<BigUint>,
    // how many bits to pack into one field element
    useful_bits: Option<usize>,
    // the size of one chunk of plaintext ==
    // useful_bits * POSEIDON_WIDTH - 128 (salt size)
    chunk_size: Option<usize>,
    // we will compute a separate Poseidon hash on each chunk of the plaintext.
    // Each chunk contains POSEIDON_WIDTH * PERMUTATION_COUNT field elements.
    chunks: Option<Vec<Vec<BigUint>>>,
    // Poseidon hashes of each chunk
    hashes_of_chunks: Option<Vec<BigUint>>,
    // each chunk's last 128 bits are used for the salt. w/o the salt, hashes
    // of plaintext with low entropy could be brute-forced.
    salts: Option<Vec<BigUint>>,
    // hashes of all our arithmetic labels for each chunk
    label_sum_hashes: Option<Vec<BigUint>>,
}

impl ProverData {
    pub fn new() -> Self {
        Self {
            plaintext: None,
            field_prime: None,
            useful_bits: None,
            chunk_size: None,
            chunks: None,
            hashes_of_chunks: None,
            salts: None,
            label_sum_hashes: None,
        }
    }
}

/// `trait Prover` contains default implementation for most of the logic of the
/// prover in the "labelsum" label decoding protocol.
/// The implementor of Prover must wrap [ProverData]. The field MUST be called `data`
pub trait Prover {
    // these methods must be implemented:

    /// Sets snarkjs's proving key received from the Verifier. Note that this
    /// method should be invoked only once on the very first interaction with
    /// the Verifier. For future interactions with the same Verifier, a cached
    /// key can be used.
    fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError>;

    /// Hashes inputs with the Poseidon hash. Inputs are field elements (FEs). The
    /// amount of FEs must be POSEIDON_WIDTH * PERMUTATION_COUNT
    fn poseidon(&mut self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError>;

    /// Produces a groth16 proof with snarkjs. Input must be a JSON string in the
    /// "input.json" format which snarkjs expects.
    fn prove(&mut self, input: &String) -> Result<Vec<u8>, ProverError>;

    /// Returns a reference to the `data` field
    /// must be implemented as { &mut self.data }
    fn data(&mut self) -> &mut ProverData;

    /// Returns an **immutable** reference to the `data` field
    /// must be implemented as { &self.data }
    fn data_immut(&self) -> &ProverData;

    // the rest of the methods have default implementations

    // Performs setup. Splits plaintext into chunks and computes a hash of each
    // chunk.
    fn setup(&mut self, field_prime: BigUint, plaintext: Vec<u8>) -> Result<(), ProverError> {
        if field_prime.bits() < 129 {
            // last field element must be large enough to contain the 128-bit
            // salt. In the future, if we need to support fields < 129 bits,
            // we can put the salt into multiple field elements.
            return Err(ProverError::WrongPrime);
        }
        let useful_bits = self.calculate_useful_bits(&field_prime);
        let (chunk_size, chunks, salts) = self.plaintext_to_chunks(useful_bits, &plaintext);

        self.data().set_field_prime(Some(field_prime));
        self.data().set_useful_bits(Some(useful_bits));
        self.data().set_plaintext(Some(plaintext));
        self.data().set_chunks(Some(chunks.clone()));
        self.data().set_salts(Some(salts));
        self.data().set_chunk_size(Some(chunk_size));
        Ok(())
    }

    fn plaintext_commitment(&mut self) -> Result<Vec<BigUint>, ProverError> {
        let chunks = self.data().chunks().as_ref().unwrap().clone();
        let hashes = self.hash_chunks(&chunks)?;
        self.data().set_hashes_of_chunks(Some(hashes.clone()));
        Ok(hashes)
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
        if self.data_immut().plaintext().as_ref().unwrap().len() * 8 != ciphertexts.len() {
            return Err(ProverError::IncorrectEncryptedLabelSize);
        }

        // Each chunk is hashed separately
        let mut label_sum_hashes: Vec<BigUint> =
            Vec::with_capacity(self.data_immut().chunks().as_ref().unwrap().len());

        let ct_iter = ciphertexts.chunks(self.data_immut().chunk_size().unwrap());
        let lb_iter = labels.chunks(self.data_immut().chunk_size().unwrap());
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

    /// Computes the sum of all arithmetic labels for each chunk of plaintext.
    ///  Returns the hash of each sum.
    fn labelsum_commitment(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Result<Vec<BigUint>, ProverError> {
        let sums = self.compute_label_sums(ciphertexts, labels)?;

        let res: Result<Vec<BigUint>, ProverError> = sums
            .iter()
            .map(|sum| Ok(self.poseidon(&vec![sum.clone()])?))
            .collect();
        if res.is_err() {
            return Err(ProverError::ErrorInPoseidonImplementation);
        }
        let labelsum_hashes = res.unwrap();
        self.data()
            .set_label_sum_hashes(Some(labelsum_hashes.clone()));
        Ok(labelsum_hashes)
    }

    // Creates inputs in the "input.json" format
    fn create_proof_inputs(&self, zero_sum: Vec<BigUint>, mut deltas: Vec<BigUint>) -> Vec<String> {
        let label_sum_hashes = self.data_immut().label_sum_hashes().as_ref().unwrap();
        let useful_bits = self.data_immut().useful_bits().unwrap();
        let chunk_size = self.data_immut().chunk_size().unwrap();
        let chunks = self.data_immut().chunks().as_ref().unwrap();
        let pt_hashes = self.data_immut().hashes_of_chunks().as_ref().unwrap();

        // Since the last chunk is padded with zero plaintext, we also zero-pad
        // the corresponding deltas of the last chunk.
        let delta_pad_count = chunk_size * chunks.len() - deltas.len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);

        // we will have as many proofs as there are chunks of plaintext
        let mut inputs: Vec<String> = Vec::with_capacity(chunks.len());
        let chunks_of_deltas: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunks.len() {
            // convert each field element of plaintext into a string
            let plaintext: Vec<String> = chunks[count]
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
            let deltas_fes: Vec<&[String]> = deltas_str.chunks(useful_bits).collect();

            // prepare input.json
            let input = object! {
                plaintext_hash: pt_hashes[count].to_string(),
                label_sum_hash: label_sum_hashes[count].to_string(),
                sum_of_zero_labels: zero_sum[count].to_string(),
                plaintext: plaintext,
                delta: deltas_fes[0..deltas_fes.len()-1],
                // last field element's deltas form a separate input
                delta_last: deltas_fes[deltas_fes.len()-1]
            };
            let s = stringify_pretty(input, 4);
            inputs.push(s);
        }
        inputs
    }

    // Creates a zk proof of label decoding for each chunk of plaintext. Returns
    // proofs in the snarkjs's "proof.json" format
    fn create_zk_proof(
        &mut self,
        zero_sum: Vec<BigUint>,
        deltas: Vec<BigUint>,
    ) -> Result<Vec<Vec<u8>>, ProverError> {
        let inputs = self.create_proof_inputs(zero_sum, deltas);
        inputs.iter().map(|input| Ok(self.prove(input)?)).collect()
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

    /// Hashes each chunk with Poseidon and returns digests for each chunk.
    fn hash_chunks(&mut self, chunks: &Vec<Vec<BigUint>>) -> Result<Vec<BigUint>, ProverError> {
        chunks
            .iter()
            .map(|chunk| {
                if chunk.len() != POSEIDON_WIDTH * PERMUTATION_COUNT {
                    return Err(ProverError::WrongPoseidonInput);
                }
                Ok(self.poseidon(chunk)?)
            })
            .collect()
    }

    /// Calculates how many bits of plaintext we will pack into one field element.
    /// Essentially, this is field_prime bit length minus 1.
    fn calculate_useful_bits(&self, field_prime: &BigUint) -> usize {
        (field_prime.bits() - 1) as usize
    }
}

#[test]
fn test_calculate_useful_bits() {
    // use super::BN254_PRIME;
    // assert_eq!(calculate_useful_bits(&BigUint::from_u16(13).unwrap()), 3);
    // assert_eq!(calculate_useful_bits(&BigUint::from_u16(255).unwrap()), 7);
    // assert_eq!(
    //     calculate_useful_bits(&String::from(BN254_PRIME,).parse::<BigUint>().unwrap()),
    //     253
    // );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provernode::ProverNode;

    // #[test]
    //  TODO finish this test
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

    //     let mut prover = ProverNode::new();
    //     prover.setup(prime, plaintext);

    //     // Check chunk1 correctness
    //     let chunk1: Vec<u128> = prover.chunks().clone().unwrap()[0][0..15]
    //         .iter()
    //         .map(|bigint| bigint.to_u128().unwrap())
    //         .collect();
    //     assert_eq!(chunk1, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    //     // the last field element must be random salt. We just check that the
    //     // salt has been set, i.e. it is not equal 0
    //     assert!(!prover.chunks().clone().unwrap()[0][15].eq(&BigUint::from_u8(0).unwrap()));

    //     // Check chunk2 correctness
    //     let chunk2: Vec<u128> = prover.chunks().clone().unwrap()[1][0..15]
    //         .iter()
    //         .map(|bigint| bigint.to_u128().unwrap())
    //         .collect();
    //     assert_eq!(chunk2, [16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    //     // the last field element must be random salt. We just check that the
    //     // salt has been set, i.e. it is not equal 0
    //     assert!(!prover.chunks().clone().unwrap()[1][15].eq(&BigUint::from_u8(0).unwrap()));
    // }
    #[test]
    fn test_hash_chunks() {
        // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
        let mut prime = vec![false; 137];
        prime[0] = true;
        let prime = boolvec_to_u8vec(&prime);
        let prime = BigUint::from_bytes_be(&prime);
        // plaintext will spawn 2 chunks
        let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
        let mut prover = ProverNode::new();
        //LsumProver::hash_chunks(&mut prover);
    }

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
