use aes::{Aes128, BlockDecrypt, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use json::{object, stringify, stringify_pretty};
use num::bigint::ToBigUint;
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use std::env::temp_dir;
use std::fs;
use std::process::{Command, Output};
use std::str;
use uuid::Uuid;

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
    label_sum_hashes: Option<Vec<BigUint>>,
    chunk_size: Option<usize>,
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
            label_sum_hashes: None,
            chunk_size: None,
        }
    }

    pub fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), Error> {
        let res = fs::write("circuit_final.zkey.verifier", key);
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
        let hashes = self.hash_chunks(chunks);
        self.hashes_of_chunks = Some(hashes.clone());
        hashes
    }

    // decrypt each encrypted arithm.label based on the p&p bit of our active
    // binary label. Return the hash of the sum of all arithm. labels. Note
    // that we compute a separate label sum for each chunk of plaintext.
    pub fn compute_label_sum(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Vec<BigUint> {
        // if binary label's p&p bit is 0, decrypt the 1st ciphertext,
        // otherwise - the 2nd one.
        assert!(ciphertexts.len() == labels.len());
        assert!(self.plaintext.as_ref().unwrap().len() * 8 == ciphertexts.len());
        let mut label_sum_hashes: Vec<BigUint> =
            Vec::with_capacity(self.chunks.as_ref().unwrap().len());

        let ct_iter = ciphertexts.chunks(self.chunk_size.unwrap());
        let lb_iter = labels.chunks(self.chunk_size.unwrap());
        // process a pair (chunk of ciphertexts, chunk of corresponding labels) at a time
        for (chunk_ct, chunk_lb) in ct_iter.zip(lb_iter){
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
            };

            println!("{:?} label_sum", label_sum);
            label_sum_hashes.push(self.poseidon(vec![label_sum]));
        } 

        self.label_sum_hashes = Some(label_sum_hashes.clone());
        label_sum_hashes
    }

    // create chunks of plaintext where each chunk consists of 16 field elements.
    // The last element's last 128 bits are reserved for the salt of the hash.
    // If there is not enough plaintext to fill the whole chunk, we fill the gap
    // with zero bits.
    fn plaintext_to_chunks(&mut self) -> (Vec<[BigUint; 16]>, Vec<BigUint>) {
        let useful_bits = self.useful_bits.unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        self.chunk_size = Some(chunk_size);

        // plaintext converted into bits
        let mut bits = u8vec_to_boolvec(&self.plaintext.as_ref().unwrap());
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
            for (i, fe_bits) in chunk_of_bits.chunks(useful_bits).enumerate(){
                if i < 15 {
                    chunk[i] = BigUint::from_bytes_be(&boolvec_to_u8vec(&fe_bits));
                }
                else {
                    // last field element's last 128 bits are for the salt
                    let salt = rng.gen::<[u8;16]>();
                    salts.push(BigUint::from_bytes_be(&salt));
                    let mut bits_and_salt = fe_bits.to_vec();
                    bits_and_salt.extend(u8vec_to_boolvec(&salt).iter());
                    chunk[15] = BigUint::from_bytes_be(&boolvec_to_u8vec(&bits_and_salt));
                };
            }
            chunks.push(chunk);
        }
        (chunks, salts)
    }

    // hashes each chunk with Poseidon and returns digests for each chunk
    fn hash_chunks(&mut self, chunks: Vec<[BigUint; 16]>) -> Vec<BigUint> {
        let res: Vec<BigUint> = chunks
            .iter()
            .map(|chunk| self.poseidon(chunk.to_vec()))
            .collect();
        res
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
        //println!("poseidon output {:?}", bi);
        bi
    }

    pub fn create_zk_proof(
        &mut self,
        zero_sum: Vec<BigUint>,
        mut deltas: Vec<BigUint>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let label_sum_hashes = self.label_sum_hashes.as_ref().unwrap().clone();

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        let useful_bits = self.useful_bits.unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count = self.chunks.as_ref().unwrap().len();

        // pad deltas with 0 values to make their count a multiple of a chunk size
        let delta_pad_count = chunk_size * chunk_count - deltas.len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);


        // we will have as many proofs as there are chunks of plaintext
        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
        let deltas_chunks: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunk_count {
            // convert plaintext to string
            let pt_str: Vec<String> = self.chunks.as_ref().unwrap()[count]
                .to_vec()
                .iter()
                .map(|bigint| bigint.to_string())
                .collect();

            // convert all deltas to strings
            let deltas_str: Vec<String> = deltas_chunks[count]
            .iter()
            .map(|v| v.to_string())
            .collect();
            
            // split deltas into 16 groups corresponding to 16 field elements 
            let deltas_fes: Vec<&[String]> = deltas_str.chunks(useful_bits).collect();

            // prepare input.json
            let mut data = object! {
                plaintext_hash: self.hashes_of_chunks.as_ref().unwrap()[count].to_string(),
                label_sum_hash: label_sum_hashes[count].to_string(),
                sum_of_zero_labels: zero_sum[count].to_string(),
                plaintext: pt_str,
                // first 15 fes form a separate input
                delta: deltas_fes[0..15],
                delta_last: deltas_fes[15]
            };
            let s = stringify_pretty(data, 4);

            let mut path1 = temp_dir();
            let mut path2 = temp_dir();
            path1.push(format!("input.json.{}", Uuid::new_v4()));
            path2.push(format!("proof.json.{}", Uuid::new_v4()));

            fs::write(path1.clone(), s).expect("Unable to write file");
            let output = Command::new("node")
                .args([
                    "prove.mjs",
                    path1.to_str().unwrap(),
                    path2.to_str().unwrap(),
                ])
                .output();
            fs::remove_file(path1);
            check_output(output)?;
            let proof = fs::read(path2.clone()).unwrap();
            fs::remove_file(path2);
            proofs.push(proof);
        }
        Ok(proofs)
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
