use crate::verifier::VerificationInput;
use crate::verifier::{VerifierError, Verify};
use json::{array, object, stringify, stringify_pretty, JsonValue};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use std::env::temp_dir;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use uuid::Uuid;

pub struct Verifier {
    verification_key: Vec<u8>,
}
impl Verifier {
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self { verification_key }
    }
}

impl Verify for Verifier {
    fn field_size(&self) -> usize {
        254
    }

    fn useful_bits(&self) -> usize {
        253
    }

    fn chunk_size(&self) -> usize {
        3920 //253*15+125
    }

    fn verify(&self, input: VerificationInput) -> Result<bool, VerifierError> {
        // public.json is a flat array
        let mut public_json: Vec<String> = Vec::new();
        public_json.push(input.plaintext_hash.to_string());
        public_json.push(input.label_sum_hash.to_string());
        let delta_str: Vec<String> = input.deltas.iter().map(|v| v.to_string()).collect();
        public_json.extend::<Vec<String>>(delta_str);
        public_json.push(input.sum_of_zero_labels.to_string());
        let s = stringify(JsonValue::from(public_json.clone()));

        // write into temp files and delete the files after verification
        let mut path1 = temp_dir();
        let mut path2 = temp_dir();
        path1.push(format!("public.json.{}", Uuid::new_v4()));
        path2.push(format!("proof.json.{}", Uuid::new_v4()));
        fs::write(path1.clone(), s).expect("Unable to write file");
        fs::write(path2.clone(), input.proof).expect("Unable to write file");

        let output = Command::new("node")
            .args([
                "circom/verify.mjs",
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
        return Err(VerifierError::VerifyingBackendError);
    }
    if !output.as_ref().unwrap().status.success() {
        return Err(VerifierError::VerifyingBackendError);
    }
    Ok(())
}
