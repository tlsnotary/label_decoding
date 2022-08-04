pub mod prover;
pub mod verifier;

const BN254_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[cfg(test)]
mod tests {
    use crate::prover::{boolvec_to_u8vec, u8vec_to_boolvec};

    use super::*;
    use num::{BigUint, FromPrimitive};
    use prover::LsumProver;
    use rand::{thread_rng, Rng};
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
        let mut rng = thread_rng();

        // random 490 byte plaintext
        // we have 16 FE * 253 bits each - 128 bits (salt) == 490 bytes
        let mut plaintext = [0u8; 512];
        rng.fill(&mut plaintext);
        let plaintext = &plaintext[0..490];
        // bn254 prime 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        // in decimal 21888242871839275222246405745257275088548364400416034343698204186575808495617

        // TODO: this will be done internally by verifier. But for now, until b2a converter is
        // implemented, we do it here.

        // generate as many 128-bit arithm label pairs as there are plaintext bits.
        // The 128-bit size is for convenience to be able to encrypt the label with 1
        // call to AES.
        // To keep the handling simple, we want to avoid a negative delta, that's why
        // W_0 and delta must be a 127-bit value and W_1 will be set to W_0 + delta
        let bitsize = plaintext.len() * 8;
        let mut zero_sum = BigUint::from_u8(0).unwrap();
        let mut deltas: Vec<BigUint> = Vec::with_capacity(bitsize);
        let arithm_labels: Vec<[BigUint; 2]> = (0..bitsize)
            .map(|_| {
                let zero_label = random_bigint(127);
                let delta = random_bigint(127);
                let one_label = zero_label.clone() + delta.clone();
                zero_sum += zero_label.clone();
                deltas.push(delta);
                [zero_label, one_label]
            })
            .collect();

        let prime = String::from(BN254_PRIME).parse::<BigUint>().unwrap();
        let mut prover = LsumProver::new(plaintext.to_vec(), prime);
        let plaintext_hash = prover.setup();
        // Commitment to the plaintext is sent to the Notary
        let mut verifier = LsumVerifier::new();
        verifier.receive_pt_hashes(plaintext_hash);
        // Verifier sends back encrypted arithm. labels. We skip this step
        // and simulate Prover's deriving his arithm labels:
        let prover_labels = choose(&arithm_labels, &u8vec_to_boolvec(&plaintext));
        let mut label_sum = BigUint::from_u8(0).unwrap();
        for i in 0..prover_labels.len() {
            label_sum += prover_labels[i].clone();
        }
        // Prover sends a hash commitment to label_sum
        let label_sum_hash = prover.poseidon(vec![label_sum.clone()]);
        // Commitment to the label_sum is sent to the Notary
        verifier.receive_labelsum_hash(label_sum_hash);
        // Notary sends zero_sum and all deltas
        // Prover constructs input to snarkjs
        prover.create_zk_proof(zero_sum, deltas, label_sum);
    }
}
