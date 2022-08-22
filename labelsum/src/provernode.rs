use crate::prover::ProverData;
use crate::prover::{Prover, ProverError};
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

    pub fn setup(&mut self, field_prime: BigUint, plaintext: Vec<u8>) -> Result<(), ProverError> {
        self.parent.setup(field_prime, plaintext)
    }

    pub fn plaintext_commitment(&mut self) -> Result<Vec<BigUint>, ProverError> {
        self.parent.plaintext_commitment()
    }

    pub fn labelsum_commitment(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Result<Vec<BigUint>, ProverError> {
        self.parent.labelsum_commitment(ciphertexts, labels)
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
pub struct ProverNodeInternal {
    data: ProverData,
}

impl ProverNodeInternal {
    pub fn new() -> Self {
        Self {
            data: ProverData::new(),
        }
    }
}

impl Prover for ProverNodeInternal {
    fn data(&mut self) -> &mut ProverData {
        &mut self.data
    }

    fn data_immut(&self) -> &ProverData {
        &self.data
    }

    /// Sets snarkjs's proving key received from the Verifier. Note that this
    /// method should be invoked only once on the very first interaction with
    /// the Verifier. For future interactions with the same Verifier, a cached
    /// key can be used.
    fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError> {
        let res = fs::write("circuit_final.zkey.verifier", key);
        if res.is_err() {
            return Err(ProverError::FileSystemError);
        }
        Ok(())
    }

    /// Hashes inputs with the Poseidon hash. Inputs are field elements (FEs). The
    /// amount of FEs must be POSEIDON_WIDTH * PERMUTATION_COUNT
    fn poseidon(&mut self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
        // convert field elements into escaped strings
        let strchunks: Vec<String> = inputs
            .iter()
            .map(|fe| String::from("\"") + &fe.to_string() + &String::from("\""))
            .collect();
        // convert to JSON array
        let json = String::from("[") + &strchunks.join(", ") + &String::from("]");

        let output = Command::new("node").args(["poseidon.mjs", &json]).output();
        if output.is_err() {
            return Err(ProverError::ErrorInPoseidonImplementation);
        }
        let output = output.unwrap();
        // drop the trailing new line
        let output = &output.stdout[0..output.stdout.len() - 1];
        let str = String::from_utf8(output.to_vec());
        if str.is_err() {
            return Err(ProverError::ErrorInPoseidonImplementation);
        }
        let bi = str.unwrap().parse::<BigUint>();
        if bi.is_err() {
            return Err(ProverError::ErrorInPoseidonImplementation);
        }
        Ok(bi.unwrap())
    }

    /// Produces a groth16 proof with snarkjs. Input must be a JSON string in the
    /// "input.json" format which snarkjs expects.
    fn prove(&mut self, input: &String) -> Result<Vec<u8>, ProverError> {
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
