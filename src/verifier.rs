use num::{BigUint, FromPrimitive, ToPrimitive, Zero};

// implementation of the Verifier in the "label sum" protocol (aka the Notary).
pub struct LsumVerifier {
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Option<Vec<BigUint>>,
    labelsum_hash: Option<BigUint>,
}

impl LsumVerifier {
    pub fn new() -> Self {
        Self {
            plaintext_hashes: None,
            labelsum_hash: None,
        }
    }

    // receive hashes of plaintext and reveal the arithmetic labels
    pub fn receive_pt_hashes(&mut self, hashes: Vec<BigUint>) {
        self.plaintext_hashes = Some(hashes);
        // TODO at this stage we send 2 ciphertexts (encrypted arithm. labels),
        // only 1 of which the User can decrypt
    }

    pub fn receive_labelsum_hash(&mut self, hash: BigUint) {
        self.labelsum_hash = Some(hash);
    }
}
