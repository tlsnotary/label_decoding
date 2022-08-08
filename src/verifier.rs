use super::to_16_bytes;
use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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
        }
    }

    pub fn get_proving_key(&mut self) -> Result<Vec<u8>, Error> {
        if !Path::new("circuit_final.zkey").exists() {
            return Err(Error::ProvingKeyNotFound);
        }
        let res = fs::read("circuit_final.zkey");
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
        fs::write("proof.json", proof).expect("Unable to write file");
        let output = Command::new("node").args(["verify.mjs"]).output();
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
