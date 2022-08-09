use rand::{distributions::Alphanumeric, Rng};
use std::path::Path;
use std::process::{Command, Output};

#[derive(Debug)]
pub enum Error {
    FileDoesNotExist,
    SnarkjsError,
}
pub struct OneTimeSetup {}

// OneTimeSetup should be run when Notary starts. It checks that all files needed
// by snarkjs are in place. If not, the files are generated.
// The files need to be generated only once *ever* for all future instantiations
// of the Notary.
impl OneTimeSetup {
    pub fn new() -> Self {
        Self {}
    }

    fn check_output(&mut self, output: Result<Output, std::io::Error>) -> Result<(), Error> {
        if output.is_err() {
            return Err(Error::SnarkjsError);
        }
        if !output.unwrap().status.success() {
            return Err(Error::SnarkjsError);
        }
        Ok(())
    }

    fn generate_entropy(&mut self) -> String {
        let entropy: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(500)
            .map(char::from)
            .collect();
        assert!(entropy.len() == 500);
        entropy
    }

    pub fn setup(&mut self) -> Result<(), Error> {
        // check if files which we ship are present
        if !Path::new("powersOfTau28_hez_final_14.ptau").exists()
            || !Path::new("circuit.r1cs").exists()
        {
            return Err(Error::FileDoesNotExist);
        }
        // check if any of the files hasn't been generated. If so, regenerate
        // all files.
        if !Path::new("circuit_0000.zkey").exists()
            || !Path::new("circuit_final.zkey.prover").exists()
            || !Path::new("verification_key.json").exists()
        {
            let entropy = self.generate_entropy();
            //return self.regenerate1(entropy);
            return self.regenerate2(entropy);
        }

        Ok(())
    }

    // this will work only if snarkjs is in the PATH
    fn regenerate1(&mut self, entropy: String) -> Result<(), Error> {
        let output = Command::new("snarkjs")
            .args([
                "groth16",
                "setup",
                "circuit.r1cs",
                "powersOfTau28_hez_final_14.ptau",
                "circuit_0000.zkey",
            ])
            .output();
        self.check_output(output)?;

        let output = Command::new("snarkjs")
            .args([
                "zkey",
                "contribute",
                "circuit_0000.zkey",
                "circuit_final.zkey",
                &(String::from("-e=\"") + &entropy + &String::from("\"")),
            ])
            .output();
        self.check_output(output)?;

        let output = Command::new("snarkjs")
            .args([
                "zkey",
                "export",
                "verificationkey",
                "circuit_final.zkey",
                "verification_key.json",
            ])
            .output();
        self.check_output(output)?;

        Ok(())
    }

    // call a js wrapper which does what regenerate1() above does
    fn regenerate2(&mut self, entropy: String) -> Result<(), Error> {
        let output = Command::new("node")
            .args(["onetimesetup.mjs", &entropy])
            .output();
        self.check_output(output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let mut ots = OneTimeSetup::new();
        ots.setup().unwrap();
    }
}
