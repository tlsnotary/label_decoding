use super::poseidon::Poseidon;
use crate::prover::ProofInput;
use crate::prover::{Prove, ProverError};
use json::{object, stringify_pretty};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use std::env::temp_dir;
use std::fs;
use std::process::{Command, Output};
use uuid::Uuid;

pub struct Prover {
    proving_key: Vec<u8>,
    poseidon: Poseidon,
}

impl Prover {
    pub fn new(proving_key: Vec<u8>) -> Self {
        Self {
            proving_key,
            poseidon: Poseidon::new(),
        }
    }

    // Creates inputs in the "input.json" format
    fn create_proof_inputs(&self, input: ProofInput) -> String {
        // convert each field element of plaintext into a string
        let plaintext: Vec<String> = input
            .plaintext
            .iter()
            .map(|bigint| bigint.to_string())
            .collect();

        // convert all deltas to strings
        let deltas_str: Vec<String> = input.deltas.iter().map(|v| v.to_string()).collect();

        // split deltas into groups corresponding to the field elements
        // of our Poseidon circuit
        let deltas_fes: Vec<&[String]> = deltas_str.chunks(self.useful_bits()).collect();

        // prepare input.json
        let input = object! {
            plaintext_hash: input.plaintext_hash.to_string(),
            label_sum_hash: input.label_sum_hash.to_string(),
            sum_of_zero_labels: input.sum_of_zero_labels.to_string(),
            plaintext: plaintext,
            salt: input.salt.to_string(),
            delta: deltas_fes[0..deltas_fes.len()-1],
            // last field element's deltas are a separate input
            delta_last: deltas_fes[deltas_fes.len()-1]
        };
        stringify_pretty(input, 4)
    }
}

impl Prove for Prover {
    fn useful_bits(&self) -> usize {
        253
    }

    fn poseidon_rate(&self) -> usize {
        16
    }

    fn permutation_count(&self) -> usize {
        1
    }

    fn salt_size(&self) -> usize {
        128
    }

    fn chunk_size(&self) -> usize {
        3920 //253*15+125
    }

    fn hash(&self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
        Ok(self.poseidon.hash(inputs))
    }

    /// Produces a groth16 proof with snarkjs. Input must be a JSON string in the
    /// "input.json" format which snarkjs expects.
    fn prove(&self, input: ProofInput) -> Result<Vec<u8>, ProverError> {
        let mut path1 = temp_dir();
        let mut path2 = temp_dir();
        let mut path3 = temp_dir();
        path1.push(format!("input.json.{}", Uuid::new_v4()));
        path2.push(format!("proving_key.zkey.{}", Uuid::new_v4()));
        path3.push(format!("proof.json.{}", Uuid::new_v4()));

        let input = self.create_proof_inputs(input);

        fs::write(path1.clone(), input).expect("Unable to write file");
        fs::write(path2.clone(), self.proving_key.clone()).expect("Unable to write file");
        let output = Command::new("node")
            .args([
                "circom/prove.mjs",
                path1.to_str().unwrap(),
                path2.to_str().unwrap(),
                path3.to_str().unwrap(),
            ])
            .output();
        fs::remove_file(path1).expect("Unable to remove file");
        fs::remove_file(path2).expect("Unable to remove file");
        check_output(output)?;
        let proof = fs::read(path3.clone()).unwrap();
        fs::remove_file(path3).expect("Unable to remove file");
        Ok(proof)
    }
}

/// Sets snarkjs's proving key received from the Verifier. Note that this
/// method should be invoked only once on the very first interaction with
/// the Verifier. For future interactions with the same Verifier, a cached
/// key can be used.
// fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError> {
//     let res = fs::write("circuit_final.zkey.verifier", key);
//     if res.is_err() {
//         return Err(ProverError::FileSystemError);
//     }
//     Ok(())
// }

fn check_output(output: Result<Output, std::io::Error>) -> Result<(), ProverError> {
    if output.is_err() {
        return Err(ProverError::ProvingBackendError);
    }
    if !output.unwrap().status.success() {
        return Err(ProverError::ProvingBackendError);
    }
    Ok(())
}
