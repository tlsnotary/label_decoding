use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use verifier::VerifierError;

pub mod onetimesetup;
pub mod prover;
pub mod provernode;
pub mod verifier;
pub mod verifiernode;

// bn254 prime 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
// in decimal 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// How many field elements our Poseidon hash consumes for one permutation.
const POSEIDON_WIDTH: usize = 16;
/// How many permutations our circom circuit supports. One permutation consumes
/// POSEIDON_WIDTH field elements.
const PERMUTATION_COUNT: usize = 1;
/// The bitsize of an arithmetic label. MUST be > 40 to give statistical
/// security against the Prover guessing the label. For a 254-bit field,
/// the bitsize > 96 would require 2 field elements for the
/// salted labelsum instead of 1.
const ARITHMETIC_LABEL_SIZE: usize = 96;

/// The maximum size (in bits) of one chunk of plaintext that we support
/// for 254-bit fields. Calculated as 2^{Field_size - 1 - 128 - 96}, where
/// 128 is the size of salt and 96 is the size of the arithmetic label.  
const MAX_CHUNK_SIZE: usize = 1 << 29;

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
        verifiernode::VerifierNode,
    };

    use super::*;
    use num::{BigUint, FromPrimitive};
    use prover::LabelsumProver;
    use rand::{thread_rng, Rng, RngCore};
    use verifier::LabelsumVerifier;

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

    fn type_of<T>(_: &T) -> &'static str {
        std::any::type_name::<T>()
    }

    #[test]
    fn e2e_test() {
        let prime = String::from(BN254_PRIME).parse::<BigUint>().unwrap();
        let mut rng = thread_rng();

        // OneTimeSetup is a no-op if the setup has been run before
        let ots = OneTimeSetup::new();
        ots.setup().unwrap();

        // The Prover should have received the proving key (before the labelsum
        // protocol starts) like this:
        let proving_key = ots.get_proving_key().unwrap();

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

        let verifier =
            LabelsumVerifier::new(all_binary_labels, Box::new(verifiernode::VerifierNode {}));

        let verifier = verifier.setup().unwrap();

        let prover = LabelsumProver::new(
            proving_key,
            prime,
            plaintext,
            Box::new(provernode::HasherNode {}),
            Box::new(provernode::ProverNode {}),
        );

        // Perform setup
        let prover = prover.setup().unwrap();

        // Commitment to the plaintext is sent to the Verifier
        let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

        // Verifier sends back encrypted arithm. labels.
        let (cipheretexts, verifier) = verifier.receive_plaintext_hashes(plaintext_hash);

        // Hash commitment to the label_sum is sent to the Notary
        let (label_sum_hashes, prover) = prover
            .labelsum_commitment(&cipheretexts, &prover_labels)
            .unwrap();

        // Notary sends zero_sum and all deltas
        let (deltas, zero_sums, verifier) = verifier.receive_labelsum_hashes(label_sum_hashes);

        // Prover generates the proof
        let (proofs, prover) = prover.create_zk_proof(zero_sums, deltas).unwrap();

        // Verifier verifies the proof
        let verifier = verifier.verify_many(proofs).unwrap();
        assert_eq!(
            type_of(&verifier),
            "labelsum::verifier::LabelsumVerifier<labelsum::verifier::VerificationSuccessfull>"
        );
    }
}
