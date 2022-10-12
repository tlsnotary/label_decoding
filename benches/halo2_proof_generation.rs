use authdecode::halo2_backend::onetimesetup::OneTimeSetup;
use authdecode::halo2_backend::prover::Prover;
use authdecode::halo2_backend::verifier::Verifier;
use authdecode::halo2_backend::Curve;
use authdecode::prover::AuthDecodeProver;
use authdecode::verifier::AuthDecodeVerifier;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use rand::Rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("proof_generation", move |bench| {
        // The Prover should have generated the proving key (before the authdecode
        // protocol starts) like this:
        let proving_key = OneTimeSetup::proving_key();

        // The Verifier should have generated the verifying key (before the authdecode
        // protocol starts) like this:
        let verification_key = OneTimeSetup::verification_key();

        let prover = Box::new(Prover::new(proving_key));
        let verifier = Box::new(Verifier::new(verification_key, Curve::Pallas));
        let mut rng = thread_rng();

        // generate random plaintext of random size up to 400 bytes
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(thread_rng().gen_range(0..400))
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

        let verifier = AuthDecodeVerifier::new(all_binary_labels.clone(), verifier);

        let verifier = verifier.setup().unwrap();

        let prover = AuthDecodeProver::new(plaintext, prover);

        // Perform setup
        let prover = prover.setup().unwrap();

        // Commitment to the plaintext is sent to the Notary
        let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

        // Notary sends back encrypted arithm. labels.
        let (ciphertexts, verifier) = verifier.receive_plaintext_hashes(plaintext_hash).unwrap();

        // Hash commitment to the label_sum is sent to the Notary
        let (label_sum_hashes, prover) = prover
            .label_sum_commitment(ciphertexts, &prover_labels)
            .unwrap();

        // Notary sends the arithmetic label seed
        let (seed, verifier) = verifier.receive_label_sum_hashes(label_sum_hashes).unwrap();

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

        bench.iter(|| {
            //Prover generates the proof
            black_box(prover.create_zk_proofs());
        });
    });
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

/// Converts BE bytes into bits in MSB-first order, left-padding with zeroes
/// to the nearest multiple of 8.
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
