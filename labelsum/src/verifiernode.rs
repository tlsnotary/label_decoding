use crate::verifier::{Verifier, VerifierData, VerifierError};
use json::{array, object, stringify, stringify_pretty, JsonValue};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use std::env::temp_dir;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use uuid::Uuid;

// a simple wrapper which exposes only the public methods of VerifierNodeInternal
pub struct VerifierNode {
    parent: VerifierNodeInternal,
}
impl VerifierNode {
    pub fn new(proving_key_needed: bool) -> Self {
        let parent = VerifierNodeInternal::new(proving_key_needed);
        Self { parent }
    }

    pub fn get_proving_key(&mut self) -> Result<Vec<u8>, VerifierError> {
        self.parent.get_proving_key()
    }

    pub fn verify(
        &mut self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError> {
        self.parent
            .verify(proof, deltas, plaintext_hash, labelsum_hash, zero_sum)
    }

    pub fn setup(&mut self, labels: &Vec<[u128; 2]>) {
        self.parent.setup(labels)
    }

    pub fn receive_pt_hashes(&mut self, hashes: Vec<BigUint>) -> Vec<[Vec<u8>; 2]> {
        self.parent.receive_pt_hashes(hashes)
    }

    pub fn receive_labelsum_hash(&mut self, hashes: Vec<BigUint>) -> (Vec<BigUint>, Vec<BigUint>) {
        self.parent.receive_labelsum_hash(hashes)
    }

    pub fn verify_many(&mut self, proofs: Vec<Vec<u8>>) -> Result<bool, VerifierError> {
        self.parent.verify_many(proofs)
    }
}

// implementation of the Verifier using the node.js backend
pub struct VerifierNodeInternal {
    data: VerifierData,
}

impl VerifierNodeInternal {
    pub fn new(proving_key_needed: bool) -> Self {
        Self {
            data: VerifierData::new(proving_key_needed),
        }
    }
}

impl Verifier for VerifierNodeInternal {
    fn data(&mut self) -> &mut VerifierData {
        &mut self.data
    }

    fn get_proving_key(&mut self) -> Result<Vec<u8>, VerifierError> {
        if !Path::new("circuit_final.zkey.prover").exists() {
            return Err(VerifierError::ProvingKeyNotFound);
        }
        let res = fs::read("circuit_final.zkey.prover");
        if res.is_err() {
            return Err(VerifierError::FileSystemError);
        }
        Ok(res.unwrap())
    }

    fn verify(
        &mut self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError> {
        // public.json is a flat array
        let mut public_json: Vec<String> = Vec::new();
        public_json.push(plaintext_hash.to_string());
        public_json.push(labelsum_hash.to_string());
        public_json.extend::<Vec<String>>(deltas);
        public_json.push(zero_sum.to_string());
        let s = stringify(JsonValue::from(public_json.clone()));

        // write into temp files and delete the files after verification
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
        fs::remove_file(path1).expect("Unable to remove file");
        fs::remove_file(path2).expect("Unable to remove file");

        check_output(&output)?;
        if !output.unwrap().status.success() {
            return Ok(false);
        }
        Ok(true)
    }
}

fn check_output(output: &Result<Output, std::io::Error>) -> Result<(), VerifierError> {
    if output.is_err() {
        return Err(VerifierError::SnarkjsError);
    }
    if !output.as_ref().unwrap().status.success() {
        return Err(VerifierError::SnarkjsError);
    }
    Ok(())
}
