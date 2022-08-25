use crate::prover::{Hash, Prove, ProverError};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use std::env::temp_dir;
use std::fs;
use std::process::{Command, Output};
use uuid::Uuid;

pub struct HasherNode {}
pub struct ProverNode {}

impl Hash for HasherNode {
    /// Hashes inputs with the Poseidon hash. Inputs are field elements (FEs). The
    /// amount of FEs must be POSEIDON_WIDTH * PERMUTATION_COUNT
    fn hash(&self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
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
        println!("stderr was {:?}", String::from_utf8(output.stderr.to_vec()));
        println!("stdout was {:?}", String::from_utf8(output.stdout.to_vec()));

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
}

impl Prove for ProverNode {
    /// Produces a groth16 proof with snarkjs. Input must be a JSON string in the
    /// "input.json" format which snarkjs expects.
    fn prove(&self, input: String, proving_key: &Vec<u8>) -> Result<Vec<u8>, ProverError> {
        let mut path1 = temp_dir();
        let mut path2 = temp_dir();
        let mut path3 = temp_dir();
        path1.push(format!("input.json.{}", Uuid::new_v4()));
        path2.push(format!("proving_key.zkey.{}", Uuid::new_v4()));
        path3.push(format!("proof.json.{}", Uuid::new_v4()));

        fs::write(path1.clone(), input).expect("Unable to write file");
        fs::write(path2.clone(), proving_key).expect("Unable to write file");
        let output = Command::new("node")
            .args([
                "prove.mjs",
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
        return Err(ProverError::SnarkjsError);
    }
    if !output.unwrap().status.success() {
        return Err(ProverError::SnarkjsError);
    }
    Ok(())
}
