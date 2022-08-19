use crate::provernode::ProverNode;
use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use getset::{Getters, Setters};
use json::{object, stringify_pretty};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub enum ProverError {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
}

use super::BN254_PRIME;

// This is a template containing all the fields which must be present in the
// implementor of `Prover`. It is here for convenience to be copy-pasted into
// the implementor's struct.
// The implementor must use #[derive(ProverGetSetM)]
#[allow(dead_code)]
pub struct ProverImplementorTemplate {
    // bytes of the plaintext which was obtained from the garbled circuit
    plaintext: Option<Vec<u8>>,
    // the prime of the field in which Poseidon hash will be computed.
    field_prime: Option<BigUint>,
    // how many bits to pack into one field element
    useful_bits: Option<usize>,
    // the size of one chunk == useful_bits * Poseidon_width - 128 (salt size)
    chunk_size: Option<usize>,
    // We will compute a separate Poseidon hash on each chunk of the plaintext.
    // Each chunk contains 16 field elements.
    chunks: Option<Vec<[BigUint; 16]>>,
    // Poseidon hashes of each chunk
    hashes_of_chunks: Option<Vec<BigUint>>,
    // each chunk's last 128 bits are used for the salt. w/o the salt, hashes
    // of plaintext with low entropy could be brute-forced.
    salts: Option<Vec<BigUint>>,
    // hash of all our arithmetic labels
    label_sum_hashes: Option<Vec<BigUint>>,
}

// `trait Prover` contains default implementation for most of the logic of the
// prover in the "labelsum" label decoding protocol.
pub trait Prover: ProverGetSet {
    // these methods must be implemented:

    fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError>;

    fn poseidon(&mut self, inputs: Vec<BigUint>) -> BigUint;

    fn prove(&mut self, input: String) -> Result<Vec<u8>, ProverError>;

    // the rest of the methods have default implementations

    // Return hash digests which is Prover's commitment to the plaintext
    fn setup(&mut self, field_prime: BigUint, plaintext: Vec<u8>) -> Vec<BigUint> {
        if field_prime.bits() < 129 {
            // last field element must be large enough to contain the 128-bit
            // salt. In the future, if we need to support fields < 129 bits,
            // we can put the salt into multiple field elements.
            panic!("Error: expected a prime >= 129 bits");
        }
        self.set_field_prime(Some(field_prime.clone()));
        self.set_plaintext(Some(plaintext.clone()));
        let useful_bits = calculate_useful_bits(&field_prime);
        self.set_useful_bits(Some(useful_bits));
        let (chunk_size, chunks, salts) = self.plaintext_to_chunks(useful_bits, plaintext);
        self.set_chunks(Some(chunks.clone()));
        self.set_salts(Some(salts));
        self.set_chunk_size(Some(chunk_size));
        let hashes = self.hash_chunks(chunks);
        self.set_hashes_of_chunks(Some(hashes.clone()));
        hashes
    }

    // decrypt each encrypted arithm.label based on the p&p bit of our active
    // binary label. Return the hash of the sum of all arithm. labels. Note
    // that we compute a separate label sum for each chunk of plaintext.
    fn compute_label_sum(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Vec<BigUint> {
        // if binary label's p&p bit is 0, decrypt the 1st ciphertext,
        // otherwise decrypt the 2nd one.
        assert!(ciphertexts.len() == labels.len());
        assert!(self.plaintext().as_ref().unwrap().len() * 8 == ciphertexts.len());
        let mut label_sum_hashes: Vec<BigUint> =
            Vec::with_capacity(self.chunks().as_ref().unwrap().len());

        let ct_iter = ciphertexts.chunks(self.chunk_size().unwrap());
        let lb_iter = labels.chunks(self.chunk_size().unwrap());
        // process a pair (chunk of ciphertexts, chunk of corresponding labels) at a time
        for (chunk_ct, chunk_lb) in ct_iter.zip(lb_iter) {
            // accumulate the label sum here
            let mut label_sum = BigUint::from_u8(0).unwrap();
            for (ct_pair, label) in chunk_ct.iter().zip(chunk_lb) {
                let key = Aes128::new_from_slice(&label.to_be_bytes()).unwrap();
                // choose which ciphertext to decrypt based on the point-and-permute bit
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

            println!("{:?} label_sum", label_sum);
            label_sum_hashes.push(self.poseidon(vec![label_sum]));
        }

        self.set_label_sum_hashes(Some(label_sum_hashes.clone()));
        label_sum_hashes
    }

    fn create_zk_proof(
        &mut self,
        zero_sum: Vec<BigUint>,
        mut deltas: Vec<BigUint>,
    ) -> Result<Vec<Vec<u8>>, ProverError> {
        let label_sum_hashes = self.label_sum_hashes().as_ref().unwrap().clone();

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        let useful_bits = self.useful_bits().unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count = self.chunks().as_ref().unwrap().len();

        // pad deltas with 0 values to make their count a multiple of a chunk size
        let delta_pad_count = chunk_size * chunk_count - deltas.len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);

        // we will have as many proofs as there are chunks of plaintext
        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
        let deltas_chunks: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunk_count {
            // convert plaintext to string
            let pt_str: Vec<String> = self.chunks().as_ref().unwrap()[count]
                .to_vec()
                .iter()
                .map(|bigint| bigint.to_string())
                .collect();

            // convert all deltas to strings
            let deltas_str: Vec<String> =
                deltas_chunks[count].iter().map(|v| v.to_string()).collect();

            // split deltas into 16 groups corresponding to 16 field elements
            let deltas_fes: Vec<&[String]> = deltas_str.chunks(useful_bits).collect();

            // prepare input.json
            let mut data = object! {
                plaintext_hash: self.hashes_of_chunks().as_ref().unwrap()[count].to_string(),
                label_sum_hash: label_sum_hashes[count].to_string(),
                sum_of_zero_labels: zero_sum[count].to_string(),
                plaintext: pt_str,
                // first 15 fes form a separate input
                delta: deltas_fes[0..15],
                delta_last: deltas_fes[15]
            };
            let s = stringify_pretty(data, 4);
            proofs.push(self.prove(s).unwrap());
        }
        Ok(proofs)
    }

    // create chunks of plaintext where each chunk consists of 16 field elements.
    // The last element's last 128 bits are reserved for the salt of the hash.
    // If there is not enough plaintext to fill the whole chunk, we fill the gap
    // with zero bits.
    fn plaintext_to_chunks(
        &mut self,
        useful_bits: usize,
        plaintext: Vec<u8>,
    ) -> (usize, Vec<[BigUint; 16]>, Vec<BigUint>) {
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;

        // plaintext converted into bits
        let mut bits = u8vec_to_boolvec(&plaintext);
        // chunk count (rounded up)
        let chunk_count = (bits.len() + (chunk_size - 1)) / chunk_size;
        // extend bits with zeroes to fill the last chunk
        bits.extend(vec![false; chunk_count * chunk_size - bits.len()]);
        let mut chunks: Vec<[BigUint; 16]> = Vec::with_capacity(chunk_count);
        let mut salts: Vec<BigUint> = Vec::with_capacity(chunk_count);

        let mut rng = thread_rng();
        for chunk_of_bits in bits.chunks(chunk_size) {
            // [BigUint::default(); 16] won't work since BigUint doesn't
            // implement the Copy trait, so typing out all values
            let mut chunk = [
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
            ];

            // split chunk into 16 field elements
            for (i, fe_bits) in chunk_of_bits.chunks(useful_bits).enumerate() {
                if i < 15 {
                    chunk[i] = BigUint::from_bytes_be(&boolvec_to_u8vec(&fe_bits));
                } else {
                    // last field element's last 128 bits are for the salt
                    let salt = rng.gen::<[u8; 16]>();
                    salts.push(BigUint::from_bytes_be(&salt));
                    let mut bits_and_salt = fe_bits.to_vec();
                    bits_and_salt.extend(u8vec_to_boolvec(&salt).iter());
                    chunk[15] = BigUint::from_bytes_be(&boolvec_to_u8vec(&bits_and_salt));
                };
            }
            chunks.push(chunk);
        }
        (chunk_size, chunks, salts)
    }

    // hashes each chunk with Poseidon and returns digests for each chunk
    fn hash_chunks(&mut self, chunks: Vec<[BigUint; 16]>) -> Vec<BigUint> {
        let res: Vec<BigUint> = chunks
            .iter()
            .map(|chunk| self.poseidon(chunk.to_vec()))
            .collect();
        res
    }
}

/// accessors for the fields defined in [`ProverImplementorTemplate`] which are
/// auto-implemented when using #[derive(ProverGetSetM)]
pub trait ProverGetSet {
    // bytes of the plaintext which was obtained from the garbled circuit
    fn plaintext(&self) -> &Option<Vec<u8>>;
    fn set_plaintext(&mut self, new: Option<Vec<u8>>);

    // the prime of the field in which Poseidon hash will be computed.
    fn field_prime(&self) -> &Option<BigUint>;
    fn set_field_prime(&mut self, new: Option<BigUint>);

    // how many bits to pack into one field element
    fn useful_bits(&self) -> &Option<usize>;
    fn set_useful_bits(&mut self, new: Option<usize>);

    // the size of one chunk == useful_bits * Poseidon_width - 128 (salt size)
    fn chunk_size(&self) -> &Option<usize>;
    fn set_chunk_size(&mut self, new: Option<usize>);

    // We will compute a separate Poseidon hash on each chunk of the plaintext.
    // Each chunk contains 16 field elements.
    fn chunks(&self) -> &Option<Vec<[BigUint; 16]>>;
    fn set_chunks(&mut self, new: Option<Vec<[BigUint; 16]>>);

    // Poseidon hashes of each chunk
    fn hashes_of_chunks(&self) -> &Option<Vec<BigUint>>;
    fn set_hashes_of_chunks(&mut self, new: Option<Vec<BigUint>>);

    //  each chunk's last 128 bits are used for the salt. w/o the salt, hashes
    //  of plaintext with low entropy could be brute-forced.
    fn salts(&self) -> &Option<Vec<BigUint>>;
    fn set_salts(&mut self, new: Option<Vec<BigUint>>);

    // hash of all our arithmetic labels
    fn label_sum_hashes(&self) -> &Option<Vec<BigUint>>;
    fn set_label_sum_hashes(&mut self, new: Option<Vec<BigUint>>);
}

/// Calculates how many bits of plaintext we will pack into one field element.
/// Essentially, this is field_prime bit length minus 1.
fn calculate_useful_bits(field_prime: &BigUint) -> usize {
    (field_prime.bits() - 1) as usize
}

#[test]
fn test_compute_full_bits() {
    assert_eq!(calculate_useful_bits(&BigUint::from_u16(13).unwrap()), 3);
    assert_eq!(calculate_useful_bits(&BigUint::from_u16(255).unwrap()), 7);
    assert_eq!(
        calculate_useful_bits(&String::from(BN254_PRIME,).parse::<BigUint>().unwrap()),
        253
    );
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
