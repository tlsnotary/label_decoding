use super::to_16_bytes;
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

#[derive(Debug)]
pub enum Error {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
}

fn check_output(output: &Result<Output, std::io::Error>) -> Result<(), Error> {
    if output.is_err() {
        return Err(Error::SnarkjsError);
    }
    if !output.as_ref().unwrap().status.success() {
        return Err(Error::SnarkjsError);
    }
    Ok(())
}
// implementation of the Verifier in the "label sum" protocol (aka the Notary).
pub struct LsumVerifier {
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Option<Vec<BigUint>>,
    labelsum_hash: Option<BigUint>,
    // if set to true, then we must send the proving key to the Prover
    // before this protocol begins. Otherwise, it is assumed that the Prover
    // already has the proving key from a previous interaction with us.
    proving_key_needed: bool,
    deltas: Option<Vec<BigUint>>,
    zero_sum: Option<BigUint>,
    ciphertexts: Option<Vec<[Vec<u8>; 2]>>,
    useful_bits: usize,
}

impl LsumVerifier {
    pub fn new(proving_key_needed: bool) -> Self {
        Self {
            plaintext_hashes: None,
            labelsum_hash: None,
            proving_key_needed,
            deltas: None,
            zero_sum: None,
            ciphertexts: None,
            useful_bits: 253,
        }
    }

    pub fn get_proving_key(&mut self) -> Result<Vec<u8>, Error> {
        if !Path::new("circuit_final.zkey.prover").exists() {
            return Err(Error::ProvingKeyNotFound);
        }
        let res = fs::read("circuit_final.zkey.prover");
        if res.is_err() {
            return Err(Error::FileSystemError);
        }
        Ok(res.unwrap())
    }

    // Convert binary labels into encrypted arithmetic labels.
    // Prepare JSON objects to be converted into proof.json before verification
    pub fn setup(&mut self, labels: &Vec<[u128; 2]>) {
        // generate as many 128-bit arithm label pairs as there are plaintext bits.
        // The 128-bit size is for convenience to be able to encrypt the label with 1
        // call to AES.
        // To keep the handling simple, we want to avoid a negative delta, that's why
        // W_0 and delta must be 127-bit values and W_1 will be set to W_0 + delta
        let bitsize = labels.len();
        let mut zero_sum = BigUint::from_u8(0).unwrap();
        let mut deltas: Vec<BigUint> = Vec::with_capacity(bitsize);
        let arithm_labels: Vec<[BigUint; 2]> = (0..bitsize)
            .map(|_| {
                let zero_label = random_bigint(127);
                let delta = random_bigint(127);
                let one_label = zero_label.clone() + delta.clone();
                zero_sum += zero_label.clone();
                deltas.push(delta);
                [zero_label, one_label]
            })
            .collect();
        self.zero_sum = Some(zero_sum);
        self.deltas = Some(deltas);

        // encrypt each arithmetic label using a corresponding binary label as a key
        // place ciphertexts in an order based on binary label's p&p bit
        let ciphertexts: Vec<[Vec<u8>; 2]> = labels
            .iter()
            .zip(arithm_labels)
            .map(|(bin_pair, arithm_pair)| {
                let zero_key = Aes128::new_from_slice(&bin_pair[0].to_be_bytes()).unwrap();
                let one_key = Aes128::new_from_slice(&bin_pair[1].to_be_bytes()).unwrap();
                let mut label0 = [0u8; 16];
                let mut label1 = [0u8; 16];
                //println!("{:?}", arithm_pair[0].to_bytes_be());
                //println!("{:?}", arithm_pair[1].to_bytes_be());
                let ap0 = arithm_pair[0].to_bytes_be();
                let ap1 = arithm_pair[1].to_bytes_be();
                label0[16 - ap0.len()..].copy_from_slice(&ap0);
                label1[16 - ap1.len()..].copy_from_slice(&ap1);
                let mut label0: GenericArray<u8, U16> = GenericArray::from(label0);
                let mut label1: GenericArray<u8, U16> = GenericArray::from(label1);
                zero_key.encrypt_block(&mut label0);
                one_key.encrypt_block(&mut label1);
                // ciphertext 0 and ciphertext 1
                let ct0 = label0.to_vec();
                let ct1 = label1.to_vec();
                // get point and permute bit of binary label 0
                if (bin_pair[0] & 1) == 0 {
                    [ct0, ct1]
                } else {
                    [ct1, ct0]
                }
            })
            .collect();
        self.ciphertexts = Some(ciphertexts);
    }

    // receive hashes of plaintext and reveal the encrypted arithmetic labels
    pub fn receive_pt_hashes(&mut self, hashes: Vec<BigUint>) -> Vec<[Vec<u8>; 2]> {
        self.plaintext_hashes = Some(hashes);
        self.ciphertexts.as_ref().unwrap().clone()
    }

    // receive the hash commitment to the Prover's sum of labels and reveal all
    // deltas and zero_sum.
    pub fn receive_labelsum_hash(&mut self, hash: BigUint) -> (Vec<BigUint>, BigUint) {
        self.labelsum_hash = Some(hash);
        (
            self.deltas.as_ref().unwrap().clone(),
            self.zero_sum.as_ref().unwrap().clone(),
        )
    }

    pub fn verify(&mut self, proof: Vec<u8>) -> Result<bool, Error> {
        // // Write public.json. The elements must be written in the exact order
        // // as below, that's the order snarkjs expects them to be in.

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        let useful_bits = self.useful_bits;
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count = (self.deltas.as_ref().unwrap().len() + (chunk_size - 1)) / chunk_size;
        let rem = self.deltas.as_ref().unwrap().len() % chunk_size;
        // amount of 0 deltas we need to add to the public inputs of the proof
        let delta_pad_count = if rem == 0 { 0 } else { chunk_size - rem };
        let padding: Vec<BigUint> = vec![BigUint::from_u8(0).unwrap(); delta_pad_count];
        let mut padded_deltas: Vec<BigUint> = Vec::with_capacity(chunk_size * 16);
        padded_deltas.extend(self.deltas.as_ref().unwrap().clone());
        padded_deltas.extend(padding);

        let mut chunks: Vec<Vec<Vec<BigUint>>> = Vec::with_capacity(chunk_count);
        // current offset within bits
        let mut offset: usize = 0;
        for _ in 0..chunk_count {
            let mut chunk: Vec<Vec<BigUint>> = Vec::with_capacity(16);
            for _ in 0..15 {
                // convert bits into field element
                chunk.push(padded_deltas[offset..offset + useful_bits].to_vec());
                offset += useful_bits;
            }
            chunk.push(padded_deltas[offset..offset + (useful_bits - 128)].to_vec());
            chunks.push(chunk);
        }

        // Even though there may be multiple chunks, we are dealing with
        // one chunk for now.

        // There are as many deltas as there are bits in the plaintext
        let delta_str: Vec<Vec<String>> = chunks[0][0..15]
            .iter()
            .map(|v| v.iter().map(|b| b.to_string()).collect())
            .collect();
        let delta_last_str: Vec<String> = chunks[0][15].iter().map(|v| v.to_string()).collect();

        // public.json is a flat array
        let mut public_json: Vec<String> = Vec::new();
        public_json.push(
            self.plaintext_hashes.as_ref().unwrap()[0]
                .clone()
                .to_string(),
        );
        public_json.push(self.labelsum_hash.as_ref().unwrap().clone().to_string());
        public_json.extend::<Vec<String>>(delta_str.into_iter().flatten().collect());
        public_json.extend(delta_last_str);
        public_json.push(self.zero_sum.as_ref().unwrap().clone().to_string());

        let s = stringify(JsonValue::from(public_json.clone()));

        let mut path1 = temp_dir();
        let mut path2 = temp_dir();
        path1.push(format!("public.json.{}", Uuid::new_v4()));
        path2.push(format!("proof.json.{}", Uuid::new_v4()));
        fs::write(path1.clone(), s).expect("Unable to write file");
        fs::write(path2.clone(), proof).expect("Unable to write file");

        let output = Command::new("node")
            .args([
                "verify.mjs",
                path1.to_str().unwrap(),
                path2.to_str().unwrap(),
            ])
            .output();
        fs::remove_file(path1);
        fs::remove_file(path2);
        check_output(&output)?;
        if output.unwrap().status.success() {
            return Ok(true);
        }
        return Ok(false);
    }
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
