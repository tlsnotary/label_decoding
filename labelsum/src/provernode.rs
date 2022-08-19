use crate::prover::ProverGetSet;
use crate::prover::{Prover, ProverError};
use derive_macro::ProverGetSetM;
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use std::env::temp_dir;
use std::fs;
use std::process::{Command, Output};
use uuid::Uuid;

// a simple wrapper which exposes only the public methods of ProverNodeInternal
pub struct ProverNode {
    parent: ProverNodeInternal,
}
impl ProverNode {
    pub fn new() -> Self {
        let parent = ProverNodeInternal::new();
        Self { parent }
    }

    pub fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError> {
        self.parent.set_proving_key(key)
    }

    pub fn setup(&mut self, field_prime: BigUint, plaintext: Vec<u8>) -> Vec<BigUint> {
        self.parent.setup(field_prime, plaintext)
    }

    pub fn compute_label_sum(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Vec<BigUint> {
        self.parent.compute_label_sum(ciphertexts, labels)
    }

    pub fn create_zk_proof(
        &mut self,
        zero_sum: Vec<BigUint>,
        deltas: Vec<BigUint>,
    ) -> Result<Vec<Vec<u8>>, ProverError> {
        self.parent.create_zk_proof(zero_sum, deltas)
    }
}

// implementation of the Prover using the node.js backend
#[derive(ProverGetSetM)]
pub struct ProverNodeInternal {
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

impl ProverNodeInternal {
    pub fn new() -> Self {
        Self {
            plaintext: None,
            field_prime: None,
            useful_bits: None,
            chunks: None,
            salts: None,
            hashes_of_chunks: None,
            label_sum_hashes: None,
            chunk_size: None,
        }
    }
}

impl Prover for ProverNodeInternal {
    fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError> {
        let res = fs::write("circuit_final.zkey.verifier", key);
        if res.is_err() {
            return Err(ProverError::FileSystemError);
        }
        Ok(())
    }

    // hash the inputs with circomlibjs's Poseidon
    fn poseidon(&mut self, inputs: Vec<BigUint>) -> BigUint {
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

    fn prove(&mut self, input: String) -> Result<Vec<u8>, ProverError> {
        let mut path1 = temp_dir();
        let mut path2 = temp_dir();
        path1.push(format!("input.json.{}", Uuid::new_v4()));
        path2.push(format!("proof.json.{}", Uuid::new_v4()));

        fs::write(path1.clone(), input).expect("Unable to write file");
        let output = Command::new("node")
            .args([
                "prove.mjs",
                path1.to_str().unwrap(),
                path2.to_str().unwrap(),
            ])
            .output();
        fs::remove_file(path1).expect("Unable to remove file");
        check_output(output)?;
        let proof = fs::read(path2.clone()).unwrap();
        fs::remove_file(path2).expect("Unable to remove file");
        Ok(proof)
    }
}

fn check_output(output: Result<Output, std::io::Error>) -> Result<(), ProverError> {
    if output.is_err() {
        return Err(ProverError::SnarkjsError);
    }
    if !output.unwrap().status.success() {
        return Err(ProverError::SnarkjsError);
    }
    Ok(())
}
