use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use json::{object, stringify, stringify_pretty};
use num::bigint::ToBigUint;
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use std::fs;
use std::process::{Command, Output};
use std::str;

#[derive(Debug)]
pub enum Error {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
}

use super::BN254_PRIME;

fn check_output(output: Result<Output, std::io::Error>) -> Result<(), Error> {
    if output.is_err() {
        return Err(Error::SnarkjsError);
    }
    if !output.unwrap().status.success() {
        return Err(Error::SnarkjsError);
    }
    Ok(())
}
// implementation of the Prover in the "label_sum" protocol (aka the User).
pub struct LsumProver {
    plaintext: Option<Vec<u8>>,
    // the prime of the field in which Poseidon hash will be computed.
    field_prime: BigUint,
    // how many bits to pack into one field element
    useful_bits: Option<usize>,
    // We will compute a separate Poseidon hash on each chunk of the plaintext.
    // Each chunk contains 16 field elements.
    chunks: Option<Vec<[BigUint; 16]>>,
    // Poseidon hashes of each chunk
    hashes_of_chunks: Option<Vec<BigUint>>,
    // each chunk's last 128 bits are used for the salt. This is important for
    // security b/c w/o the salt, hashes of plaintext with low entropy could be
    // brute-forced.
    salts: Option<Vec<BigUint>>,
    // hash of all our arithmetic labels
    label_sum_hash: Option<BigUint>,
}

impl LsumProver {
    pub fn new(field_prime: BigUint) -> Self {
        if field_prime.bits() < 129 {
            // last field element must be large enough to contain the 128-bit
            // salt. In the future, if we need to support fields < 129 bits,
            // we can split the salt between multiple field elements.
            panic!("Error: expected a prime >= 129 bits");
        }
        Self {
            plaintext: None,
            field_prime,
            useful_bits: None,
            chunks: None,
            salts: None,
            hashes_of_chunks: None,
            label_sum_hash: None,
        }
    }

    pub fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), Error> {
        let res = fs::write("circuit_final.zkey", key);
        if res.is_err() {
            return Err(Error::FileSystemError);
        }
        Ok(())
    }

    // Return hash digests which is Prover's commitment to the plaintext
    pub fn setup(&mut self, plaintext: Vec<u8>) -> Vec<BigUint> {
        self.plaintext = Some(plaintext);
        let useful_bits = calculate_useful_bits(self.field_prime.clone());
        self.useful_bits = Some(useful_bits);
        let (chunks, salts) = self.plaintext_to_chunks();
        self.chunks = Some(chunks.clone());
        self.salts = Some(salts);
        self.hashes_of_chunks = Some(self.hash_chunks(chunks));
        self.hashes_of_chunks.as_ref().unwrap().to_vec()
    }

    // decrypt each encrypted arithm.label based on the p&p bit of our active
    // binary label. Return the hash of the sum of all arithm. labels.
    pub fn compute_label_sum(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> BigUint {
        // if binary label's p&p bit is 0, decrypt the 1st ciphertext,
        // otherwise - the 2nd one.
        assert!(ciphertexts.len() == labels.len());
        let mut label_sum = BigUint::from_u8(0).unwrap();
        let _unused: Vec<()> = ciphertexts
            .iter()
            .zip(labels)
            .map(|(ct_pair, label)| {
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
            })
            .collect();
        println!("{:?} label_sum", label_sum);
        let label_sum_hash = self.poseidon(vec![label_sum]);
        self.label_sum_hash = Some(label_sum_hash.clone());
        label_sum_hash
    }

    // create chunks of plaintext where each chunk consists of 16 field elements.
    // The last element's last 128 bits are reserved for the salt of the hash.
    // If there is not enough plaintext to fill the whole chunk, we fill the gap
    // with zero bits.
    fn plaintext_to_chunks(&mut self) -> (Vec<[BigUint; 16]>, Vec<BigUint>) {
        let useful_bits = self.useful_bits.unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;

        //let chunk_size = useful_bits * 16;
        // plaintext converted into bits
        let mut bits = u8vec_to_boolvec(&self.plaintext.as_ref().unwrap());
        // chunk count (rounded up)
        let chunk_count = (bits.len() + (chunk_size - 1)) / chunk_size;
        // extend bits with zeroes to fill the chunk
        bits.extend(vec![false; chunk_count * chunk_size - bits.len()]);
        let mut chunks: Vec<[BigUint; 16]> = Vec::with_capacity(chunk_count);
        let mut salts: Vec<BigUint> = Vec::with_capacity(chunk_count);
        // current offset within bits
        let mut offset: usize = 0;
        for i in 0..chunk_count {
            // TODO is there a cleaner way to init an array of BigUint b/c
            // [BigUint::default(); 16]; gave a Copy trait error
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

            for j in 0..15 {
                // convert bits into field element
                chunk[j] =
                    BigUint::from_bytes_be(&boolvec_to_u8vec(&bits[offset..offset + useful_bits]));
                offset += useful_bits;
            }

            // last field element's last 128 bits are for the salt
            let mut rng = thread_rng();
            let salt: [u8; 16] = rng.gen();
            let salt = u8vec_to_boolvec(&salt);

            let mut last_fe = vec![false; useful_bits];
            last_fe[0..useful_bits - 128]
                .copy_from_slice(&bits[offset..offset + (useful_bits - 128)]);
            offset += useful_bits - 128;
            last_fe[useful_bits - 128..].copy_from_slice(&salt);
            chunk[15] = BigUint::from_bytes_be(&boolvec_to_u8vec(&last_fe));

            let salt = BigUint::from_bytes_be(&boolvec_to_u8vec(&salt));
            salts.push(salt);
            chunks.push(chunk);
        }
        (chunks, salts)
    }

    // hashes each chunk with Poseidon and returns digests for each chunk
    fn hash_chunks(&mut self, chunks: Vec<[BigUint; 16]>) -> Vec<BigUint> {
        return chunks
            .iter()
            .map(|chunk| self.poseidon(chunk.to_vec()))
            .collect();
    }

    // hash the inputs with circomlibjs's Poseidon
    pub fn poseidon(&mut self, inputs: Vec<BigUint>) -> BigUint {
        // convert field elements into escaped strings
        let strchunks: Vec<String> = inputs
            .iter()
            .map(|fe| String::from("\"") + &fe.to_string() + &String::from("\""))
            .collect();
        // convert to JSON array
        let json = String::from("[") + &strchunks.join(", ") + &String::from("]");
        println!("json {:?}", json);

        let output = Command::new("node")
            .args(["poseidon.mjs", &json])
            .output()
            .unwrap();
        println!("{:?}", output);
        // drop the trailing new line
        let output = &output.stdout[0..output.stdout.len() - 1];
        let s = String::from_utf8(output.to_vec()).unwrap();
        let bi = s.parse::<BigUint>().unwrap();
        println!("poseidon output {:?}", bi);
        bi
    }

    pub fn create_zk_proof(
        &mut self,
        zero_sum: BigUint,
        deltas: Vec<BigUint>,
    ) -> Result<Vec<u8>, Error> {
        let label_sum_hash = self.label_sum_hash.as_ref().unwrap().clone();

        // write inputs into input.json
        let pt_str: Vec<String> = self.chunks.as_ref().unwrap()[0]
            .to_vec()
            .iter()
            .map(|bigint| bigint.to_string())
            .collect();
        // For now dealing with one chunk only
        let mut deltas_chunk: Vec<Vec<BigUint>> = Vec::with_capacity(16);
        for i in 0..15 {
            deltas_chunk.push(deltas[i * 253..(i + 1) * 253].to_vec());
        }

        // There are as many deltas as there are bits in the plaintext
        let delta_str: Vec<Vec<String>> = deltas_chunk
            .iter()
            .map(|v| v.iter().map(|b| b.to_string()).collect())
            .collect();
        let delta_last = &deltas[15 * 253..16 * 253 - 128];
        let delta_last_str: Vec<String> = delta_last.iter().map(|v| v.to_string()).collect();

        let mut data = object! {
            plaintext_hash: self.hashes_of_chunks.as_ref().unwrap()[0].to_string(),
            label_sum_hash: label_sum_hash.to_string(),
            sum_of_zero_labels: zero_sum.to_string(),
            plaintext: pt_str,
            delta: delta_str,
            delta_last: delta_last_str
        };
        let s = stringify_pretty(data, 4);
        fs::write("input.json", s).expect("Unable to write file");
        let output = Command::new("node").args(["prove.mjs"]).output();
        check_output(output)?;
        let proof = fs::read("proof.json").unwrap();
        Ok(proof)
    }
}

/// Calculates how many bits of plaintext we will pack into one field element.
/// Essentially, this is field_prime bit length minus 1.
fn calculate_useful_bits(field_prime: BigUint) -> usize {
    (field_prime.bits() - 1) as usize
}

#[test]
fn test_compute_full_bits() {
    assert_eq!(calculate_useful_bits(BigUint::from_u16(13).unwrap()), 3);
    assert_eq!(calculate_useful_bits(BigUint::from_u16(255).unwrap()), 7);
    assert_eq!(
        calculate_useful_bits(String::from(BN254_PRIME,).parse::<BigUint>().unwrap()),
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
    #[test]
    fn test_plaintext_to_chunks() {
        // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
        let mut prime = vec![false; 137];
        prime[0] = true;
        let prime = boolvec_to_u8vec(&prime);
        let prime = BigUint::from_bytes_be(&prime);
        // plaintext will spawn 2 chunks
        let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
        // first chunk's field elements
        for i in 0..15 {
            // make the last byte of each field element unique
            plaintext[i * 17 + 16] = i as u8;
        }
        // first chunk's last field element's plaintext is 1 zero byte. The
        // rest of the field element will be filled with salt
        plaintext[15 * 17] = 0u8;

        // second chunk's field elements
        for i in 0..5 {
            // make the last byte of each field element unique
            plaintext[(15 * 17 + 1) + i * 17 + 16] = (i + 16) as u8;
        }

        let mut prover = LsumProver::new(prime);
        prover.setup(plaintext);

        // Check chunk1 correctness
        let chunk1: Vec<u128> = prover.chunks.clone().unwrap()[0][0..15]
            .iter()
            .map(|bigint| bigint.to_u128().unwrap())
            .collect();
        assert_eq!(chunk1, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        // the last field element must be random salt. We just check that the
        // salt has been set, i.e. it is not equal 0
        assert!(!prover.chunks.clone().unwrap()[0][15].eq(&BigUint::from_u8(0).unwrap()));

        // Check chunk2 correctness
        let chunk2: Vec<u128> = prover.chunks.clone().unwrap()[1][0..15]
            .iter()
            .map(|bigint| bigint.to_u128().unwrap())
            .collect();
        assert_eq!(chunk2, [16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // the last field element must be random salt. We just check that the
        // salt has been set, i.e. it is not equal 0
        assert!(!prover.chunks.clone().unwrap()[1][15].eq(&BigUint::from_u8(0).unwrap()));
    }

    #[test]
    fn test_hash_chunks() {
        // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
        let mut prime = vec![false; 137];
        prime[0] = true;
        let prime = boolvec_to_u8vec(&prime);
        let prime = BigUint::from_bytes_be(&prime);
        // plaintext will spawn 2 chunks
        let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
        let mut prover = LsumProver::new(prime);
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
