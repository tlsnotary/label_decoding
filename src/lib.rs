use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use prover::{ProverCore, ProverError};
use verifier::VerifierError;

pub mod onetimesetup;
pub mod prover;
pub mod verifier;

// bn254 prime 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
// in decimal 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// ProverVirtual describes virtual methods which must be implemented by the
// nodejs and wasm implementors
pub trait ProverVirtual {
    fn set_proving_key(&mut self, key: Vec<u8>) -> Result<(), ProverError>;

    fn poseidon(&mut self, inputs: Vec<BigUint>) -> BigUint;

    fn prove(&mut self, input: String) -> Result<Vec<u8>, ProverError>;
}

// provides default implementations for methods which must passthrough to the
// LsumProverCore. Only get_core() must be implemented.
pub trait ProverPassthrough {
    fn setup(&mut self, plaintext: Vec<u8>) -> Vec<BigUint> {
        self.get_core().setup(plaintext)
    }

    fn compute_label_sum(
        &mut self,
        ciphertexts: &Vec<[Vec<u8>; 2]>,
        labels: &Vec<u128>,
    ) -> Vec<BigUint> {
        self.get_core().compute_label_sum(ciphertexts, labels)
    }

    fn create_zk_proof(
        &mut self,
        zero_sum: Vec<BigUint>,
        mut deltas: Vec<BigUint>,
    ) -> Result<Vec<Vec<u8>>, ProverError> {
        self.get_core().create_zk_proof(zero_sum, deltas)
    }

    fn get_core(&mut self) -> &ProverCore<Box<Self>>;
}

pub trait VerifierCore {
    fn get_proving_key(&mut self) -> Result<Vec<u8>, VerifierError>;

    fn verify(
        &mut self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError>;
}

#[cfg(test)]
mod tests {
    use crate::{
        onetimesetup::OneTimeSetup,
        prover::{boolvec_to_u8vec, u8vec_to_boolvec},
    };

    use super::*;
    use num::{BigUint, FromPrimitive};
    use prover::Prover;
    use rand::{thread_rng, Rng, RngCore};
    use verifier::LsumVerifier;

    fn random_bigint(bitsize: usize) -> BigUint {
        assert!(bitsize <= 128);
        let r: [u8; 16] = thread_rng().gen();
        // take only those bits which we need
        BigUint::from_bytes_be(&boolvec_to_u8vec(&u8vec_to_boolvec(&r)[0..bitsize]))
    }
    /// Unzips a slice of pairs, returning items corresponding to choice
    fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
        assert!(items.len() == choice.len(), "arrays are different length");
        items
            .iter()
            .zip(choice)
            .map(|(items, choice)| items[*choice as usize].clone())
            .collect()
    }

    #[test]
    fn e2e_test() {
        let prime = String::from(BN254_PRIME).parse::<BigUint>().unwrap();
        let mut rng = thread_rng();

        // OneTimeSetup is a no-op if the setup has been run before
        let mut ots = OneTimeSetup::new();
        ots.setup().unwrap();

        // Our Poseidon is 16-width, so one permutation processes:
        // 16 * 253 - 128 bits (salt) == 490 bytes. This is the size of the chunk.

        // generate random plaintext of random size in range (0, 2000)
        let mut plaintext = vec![0u8; rng.gen_range(0..2000)];
        rng.fill_bytes(&mut plaintext);

        // Normally, the Prover is expected to obtain her binary labels by
        // evaluating the garbled circuit.
        // To keep this test simple, we don't evaluate the gc, but we generate
        // all labels of the Verifier and give the Prover her active labels.
        let bit_size = plaintext.len() * 8;
        let mut all_binary_labels: Vec<[u128; 2]> = Vec::with_capacity(bit_size);
        let mut delta: u128 = rng.gen();
        // set the last bit
        delta |= 1;
        for _ in 0..bit_size {
            let label_zero: u128 = rng.gen();
            all_binary_labels.push([label_zero, label_zero ^ delta]);
        }
        let prover_labels = choose(&all_binary_labels, &u8vec_to_boolvec(&plaintext));

        let mut verifier = LsumVerifier::new(true);
        // passing proving key to Prover (if he needs one)
        let proving_key = verifier.get_proving_key().unwrap();
        // produce ciphertexts which are sent to Prover for decryption
        verifier.setup(&all_binary_labels);

        let mut prover = Prover::new(prime);
        prover.set_proving_key(proving_key);
        let plaintext_hash = prover.setup(plaintext.to_vec());

        // Commitment to the plaintext is sent to the Verifier
        let cipheretexts = verifier.receive_pt_hashes(plaintext_hash);
        // Verifier sends back encrypted arithm. labels.

        let label_sum_hashes = prover.compute_label_sum(&cipheretexts, &prover_labels);
        // Hash commitment to the label_sum is sent to the Notary

        let (deltas, zero_sums) = verifier.receive_labelsum_hash(label_sum_hashes);
        // Notary sends zero_sum and all deltas
        // Prover constructs input to snarkjs
        let proofs = prover.create_zk_proof(zero_sums, deltas).unwrap();

        // Verifier verifies the proof
        assert_eq!(verifier.verify_many(proofs).unwrap(), true);
    }
}
