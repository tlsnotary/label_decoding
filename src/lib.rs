use num::BigUint;

pub mod halo2_backend;
pub mod label;
pub mod prover;
pub mod snarkjs_backend;
pub mod utils;
pub mod verifier;

/// The bitsize of an arithmetic label. MUST be > 40 to give statistical
/// security against the Prover guessing the label. For a 254-bit field,
/// the bitsize > 96 would require 2 field elements for the
/// salted labelsum instead of 1.
const ARITHMETIC_LABEL_SIZE: usize = 96;

/// The maximum supported size (in bits) of one [Chunk] of plaintext.
/// Should not exceed 2^{ [prover::Prove::useful_bits] - [prover::Prove::salt_size]
/// - [ARITHMETIC_LABEL_SIZE] }.
/// 2^20 should suffice for most use cases.
const MAX_CHUNK_SIZE: usize = 1 << 20;

/// The maximum supported amount of plaintext [Chunk]s ( which equals to the
/// amount of zk proofs). Having too many zk proofs may be a DOS vector
/// against the Notary who is the verifier of zk proofs.
const MAX_CHUNK_COUNT: usize = 128;

/// The decoded output labels of the garbled circuit. In other words, this is
/// the plaintext output resulting from the evaluation of a garbled circuit.
type Plaintext = Vec<u8>;

/// A chunk of [Plaintext]. The amount of vec elements equals
/// [Prove::poseidon_rate] * [Prove::permutation_count]. Each vec element
/// is an "Elliptic curve field element" into which [Prove::useful_bits] bits
/// of [Plaintext] is packed.
/// The chunk does NOT contain the [Salt].
type Chunk = Vec<BigUint>;

/// Before hashing a [Chunk], it is salted by shifting its last element to the
/// left by [Prove::salt_size] and placing the salt into the low bits.
/// This same salt is also used to salt the sum of all the labels corresponding
/// to the [Chunk].
/// Without the salt, a hash of plaintext with low entropy could be brute-forced.
type Salt = BigUint;

/// A Poseidon hash digest of a [Salt]ed [Chunk]. This is an EC field element.
type PlaintextHash = BigUint;

/// A Poseidon hash digest of a [Salt]ed arithmetic sum of arithmetic labels
/// corresponding to the [Chunk]. This is an EC field element.
type LabelsumHash = BigUint;

/// An arithmetic sum of all "zero" arithmetic labels ( those are the labels
/// which encode the bit value 0) corresponding to one [Chunk].
type ZeroSum = BigUint;

/// An arithmetic difference between the arithmetic label "one" and the
/// arithmetic label "zero".
type Delta = BigUint;

/// A serialized proof proving that a Poseidon hash is the result of hashing a
/// salted [Chunk].
type Proof = Vec<u8>;

#[cfg(test)]
mod tests {

    use super::*;
    use prover::LabelsumProver;
    use rand::{thread_rng, Rng};
    use verifier::LabelsumVerifier;

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

    pub mod fixtures {
        use super::utils::*;
        use super::*;
        use crate::prover::Prove;
        use crate::verifier::Verify;

        /// Accepts a concrete Prover and Verifier and runs the whole labelsum
        /// protocol end-to-end.
        pub fn e2e_test(prover: Box<dyn Prove>, verifier: Box<dyn Verify>) {
            let mut rng = thread_rng();

            // generate random plaintext of random size up to 2000 bytes
            let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
                .take(thread_rng().gen_range(0..1000))
                .collect();

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

            let verifier = LabelsumVerifier::new(all_binary_labels.clone(), verifier);

            let verifier = verifier.setup().unwrap();

            let prover = LabelsumProver::new(plaintext, prover);

            // Perform setup
            let prover = prover.setup().unwrap();

            // Commitment to the plaintext is sent to the Notary
            let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

            // Notary sends back encrypted arithm. labels.
            let (ciphertexts, verifier) =
                verifier.receive_plaintext_hashes(plaintext_hash).unwrap();

            // Hash commitment to the label_sum is sent to the Notary
            let (label_sum_hashes, prover) = prover
                .labelsum_commitment(ciphertexts, &prover_labels)
                .unwrap();

            // Notary sends the arithmetic label seed
            let (seed, verifier) = verifier.receive_labelsum_hashes(label_sum_hashes).unwrap();

            // At this point the following happens in the `committed GC` protocol:
            // - the Notary reveals the GC seed
            // - the User checks that the GC was created from that seed
            // - the User checks that her active output labels correspond to the
            // output labels derived from the seed
            // - we are called with the result of the check and (if successful)
            // with all the output labels

            let prover = prover
                .binary_labels_authenticated(true, Some(all_binary_labels))
                .unwrap();

            // Prover checks the integrity of the arithmetic labels and generates zero_sums and deltas
            let prover = prover.authenticate_arithmetic_labels(seed).unwrap();

            // Prover generates the proof
            let (proofs, prover) = prover.create_zk_proofs().unwrap();

            // Notary verifies the proof
            let verifier = verifier.verify_many(proofs).unwrap();
            assert_eq!(
                type_of(&verifier),
                "labelsum::verifier::LabelsumVerifier<labelsum::verifier::VerificationSuccessfull>"
            );
        }
    }
}
