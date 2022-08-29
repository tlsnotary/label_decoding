use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

pub mod label;
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

pub fn random_bigint(bitsize: usize) -> BigUint {
    assert!(bitsize <= 128);
    let r: [u8; 16] = thread_rng().gen();
    // take only those bits which we need
    BigUint::from_bytes_be(&boolvec_to_u8vec(&u8vec_to_boolvec(&r)[0..bitsize]))
}

#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

// Convert bits into bytes. The bits will be left-padded with zeroes to the
// multiple of 8.
#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let rem = bv.len() % 8;
    let first_byte_bitsize = if rem == 0 { 8 } else { rem };
    let offset = if rem == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    // implicitely left-pad the first byte with zeroes
    for (i, b) in bv[0..first_byte_bitsize].iter().enumerate() {
        v[i / 8] |= (*b as u8) << (first_byte_bitsize - 1 - i);
    }
    for (i, b) in bv[first_byte_bitsize..].iter().enumerate() {
        v[1 + i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Encrypts each arithmetic label using a corresponding binary label as a key
/// and returns ciphertexts in an order based on binary label's pointer bit (LSB).
pub fn encrypt_arithmetic_labels(
    alabels: &Vec<[BigUint; 2]>,
    blabels: &Vec<[u128; 2]>,
) -> Vec<[Vec<u8>; 2]> {
    assert!(alabels.len() == blabels.len());

    blabels
        .iter()
        .zip(alabels)
        .map(|(bin_pair, arithm_pair)| {
            let zero_key = Aes128::new_from_slice(&bin_pair[0].to_be_bytes()).unwrap();
            let one_key = Aes128::new_from_slice(&bin_pair[1].to_be_bytes()).unwrap();
            let mut label0 = [0u8; 16];
            let mut label1 = [0u8; 16];
            let ap0 = arithm_pair[0].to_bytes_be();
            let ap1 = arithm_pair[1].to_bytes_be();
            // pad with zeroes on the left
            label0[16 - ap0.len()..].copy_from_slice(&ap0);
            label1[16 - ap1.len()..].copy_from_slice(&ap1);
            let mut label0: GenericArray<u8, U16> = GenericArray::from(label0);
            let mut label1: GenericArray<u8, U16> = GenericArray::from(label1);
            zero_key.encrypt_block(&mut label0);
            one_key.encrypt_block(&mut label1);
            // ciphertext 0 and ciphertext 1
            let ct0 = label0.to_vec();
            let ct1 = label1.to_vec();
            // place ar. labels based on the point and permute bit of bin. label 0
            if (bin_pair[0] & 1) == 0 {
                [ct0, ct1]
            } else {
                [ct1, ct0]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::onetimesetup::OneTimeSetup;

    use super::*;
    use num::{BigUint, FromPrimitive};
    use prover::LabelsumProver;
    use rand::{thread_rng, Rng, RngCore};
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

        // generate random plaintext of random size up to 2000 bytes
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(thread_rng().gen_range(0..2000))
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

        let verifier = LabelsumVerifier::new(
            all_binary_labels.clone(),
            Box::new(verifiernode::VerifierNode {}),
        );

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

        // Commitment to the plaintext is sent to the Notary
        let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

        // Notary sends back encrypted arithm. labels.
        let (cipheretexts, verifier) = verifier.receive_plaintext_hashes(plaintext_hash);

        // Hash commitment to the label_sum is sent to the Notary
        let (label_sum_hashes, prover) = prover
            .labelsum_commitment(cipheretexts, &prover_labels)
            .unwrap();

        // Notary sends the arithmetic label seed
        let (seed, verifier) = verifier.receive_labelsum_hashes(label_sum_hashes);

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
        let (proofs, prover) = prover.create_zk_proof().unwrap();

        // Notary verifies the proof
        let verifier = verifier.verify_many(proofs).unwrap();
        assert_eq!(
            type_of(&verifier),
            "labelsum::verifier::LabelsumVerifier<labelsum::verifier::VerificationSuccessfull>"
        );
    }
}
