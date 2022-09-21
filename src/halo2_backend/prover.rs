use super::circuit::{LabelsumCircuit, CELLS_PER_ROW, FULL_FIELD_ELEMENTS, K, USEFUL_ROWS};
use super::poseidon_spec::{Spec1, Spec15};
use super::utils::boolvec_to_u8vec;
use super::utils::{bigint_to_f, f_to_bigint};
use crate::prover::{ProofInput, Prove, ProverError, ProvingKeyTrait};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Challenge255;
use num::BigUint;
use pasta_curves::pallas::Base as F;
use pasta_curves::EqAffine;
use rand::{thread_rng, Rng};

// halo2's native ProvingKey can't be used without params, so we wrap
// them in one struct.
pub struct PK {
    key: ProvingKey<EqAffine>,
    params: Params<EqAffine>,
}
impl ProvingKeyTrait for PK {}

pub struct Prover {}

impl Prove for Prover {
    fn prove(&self, input: ProofInput, proving_key: PK) -> Result<Vec<u8>, ProverError> {
        // convert each delta into a field element type
        let deltas: Vec<F> = input.deltas.iter().map(|d| bigint_to_f(d)).collect();

        // to make handling simpler, we pad each set of 253 deltas
        // with 3 zero deltas on the left.
        let deltas: Vec<F> = deltas
            .chunks(self.useful_bits())
            .map(|c| {
                let mut v = vec![F::from(0); 3];
                v.extend(c.to_vec());
                v
            })
            .flatten()
            .collect();

        // convert plaintext into field element type
        let plaintext: [F; 15] = input
            .plaintext
            .iter()
            .map(|bigint| bigint_to_f(bigint))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // number of chunks should be equal to USEFUL_ROWS
        let all_deltas: [Vec<F>; USEFUL_ROWS] = deltas
            .chunks(CELLS_PER_ROW)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // transpose to make CELLS_PER_ROW instance columns
        let input_deltas: [Vec<F>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
            .map(|i| {
                all_deltas
                    .iter()
                    .map(|inner| inner[i].clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let circuit = LabelsumCircuit::new(plaintext, all_deltas.clone());

        use instant::Instant;

        let now = Instant::now();

        let params = proving_key;

        let params: Params<EqAffine> = Params::new(K);

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

        println!("ProvingKey built [{:?}]", now.elapsed());

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let mut all_inputs: Vec<&[F]> = Vec::new();
        for i in 0..input_deltas.len() {
            let d = input_deltas[i].as_slice();
            all_inputs.push(d);
        }

        let tmp = &[
            bigint_to_f(&input.plaintext_hash),
            bigint_to_f(&input.label_sum_hash),
        ];
        all_inputs.push(tmp);
        println!("{:?} all inputs len", all_inputs.len());

        let now = Instant::now();
        let mut rng = thread_rng();

        plonk::create_proof(
            &params,
            &pk,
            &[circuit],
            &[all_inputs.as_slice()],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

        println!("Proof created [{:?}]", now.elapsed());

        let proof = transcript.finalize();

        let now = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        plonk::verify_proof(
            &params,
            &vk,
            strategy,
            &[all_inputs.as_slice()],
            &mut transcript,
        )
        .unwrap();
        //console::log_1(&format!("Proof verified {:?}", now.elapsed()).into());
        //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

        println!("Proof verified [{:?}]", now.elapsed());
        println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
        Ok(proof)
    }

    fn useful_bits(&self) -> usize {
        253
    }

    fn poseidon_rate(&self) -> usize {
        15
    }

    fn permutation_count(&self) -> usize {
        1
    }

    fn salt_size(&self) -> usize {
        125
    }

    // we have 14 field elements of 253 bits and 128 bits of the 15th field
    // element, i.e. 14*253+128==3670 bits. The least 125 bits of the last
    // field element will be used for the salt.
    fn chunk_size(&self) -> usize {
        3670
    }

    // Hashes inputs with Poseidon and returns the digest.
    fn hash(&self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
        let d = match inputs.len() {
            15 => {
                // hash with rate-15 Poseidon
                let fes: [F; 15] = inputs
                    .iter()
                    .map(|i| bigint_to_f(i))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                poseidon::Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(fes)
            }
            1 => {
                // hash with rate-1 Poseidon
                let fes: [F; 1] = inputs
                    .iter()
                    .map(|i| bigint_to_f(i))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                poseidon::Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash(fes)
            }
            _ => return Err(ProverError::WrongPoseidonInput),
        };
        Ok(f_to_bigint(&d))
    }
}

#[test]
pub fn maintest() {
    use super::circuit::{LabelsumCircuit, CELLS_PER_ROW, FULL_FIELD_ELEMENTS, K, USEFUL_ROWS};
    use super::utils::boolvec_to_u8vec;
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::plonk;
    use halo2_proofs::plonk::SingleVerifier;
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::Blake2bRead;
    use halo2_proofs::transcript::Blake2bWrite;
    use halo2_proofs::transcript::Challenge255;
    use pasta_curves::EqAffine;
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();

    // generate random plaintext to fill all cells. The first 3 bits of each
    // full field element are not used, so we zero them out
    const TOTAL_PLAINTEXT_SIZE: usize = CELLS_PER_ROW * USEFUL_ROWS;
    let mut plaintext_bits: [bool; TOTAL_PLAINTEXT_SIZE] =
        core::iter::repeat_with(|| rng.gen::<bool>())
            .take(TOTAL_PLAINTEXT_SIZE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    for i in 0..FULL_FIELD_ELEMENTS {
        plaintext_bits[256 * i + 0] = false;
        plaintext_bits[256 * i + 1] = false;
        plaintext_bits[256 * i + 2] = false;
    }

    // random deltas. The first 3 deltas of each set of 256 are not used, so we
    // zero them out.
    let mut deltas: [F; TOTAL_PLAINTEXT_SIZE] =
        core::iter::repeat_with(|| F::from_u128(rng.gen::<u128>()))
            .take(TOTAL_PLAINTEXT_SIZE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    for i in 0..FULL_FIELD_ELEMENTS {
        deltas[256 * i + 0] = F::from(0);
        deltas[256 * i + 1] = F::from(0);
        deltas[256 * i + 2] = F::from(0);
    }

    let pt_chunks = plaintext_bits.chunks(256);
    // plaintext has 15 BigUint field elements - this is how the User is
    // expected to call this halo2 prover
    let plaintext: [BigUint; FULL_FIELD_ELEMENTS + 1] = pt_chunks
        .map(|c| {
            // convert each chunk of bits into a field element
            BigUint::from_bytes_be(&boolvec_to_u8vec(c))
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // number of chunks should be equal to USEFUL_ROWS
    let all_deltas: [Vec<F>; USEFUL_ROWS] = deltas
        .chunks(CELLS_PER_ROW)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // transpose to make CELLS_PER_ROW instance columns
    let input_deltas: [Vec<F>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
        .map(|i| {
            all_deltas
                .iter()
                .map(|inner| inner[i].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut hash_input = [F::default(); 15];
    for i in 0..hash_input.len() {
        hash_input[i] = bigint_to_f(&plaintext[i]);
    }
    let plaintext_digest =
        poseidon::Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(hash_input);

    // compute labelsum digest
    let mut labelsum = F::from(0);
    for it in plaintext_bits.iter().zip(deltas.clone()) {
        let (p, d) = it;
        let dot_product = F::from(*p) * d;
        labelsum += dot_product;
    }
    let labelsum_digest =
        poseidon::Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash([labelsum]);

    let circuit = LabelsumCircuit::new(plaintext, all_deltas.clone());

    // let prover = MockProver::<pallas::Base>::run(k, &circuit, input_deltas.clone()).unwrap();

    // assert_eq!(prover.verify(), Ok(()));

    use instant::Instant;

    let now = Instant::now();

    let params: Params<EqAffine> = Params::new(K);

    let vk = plonk::keygen_vk(&params, &circuit).unwrap();
    let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

    //console::log_1(&format!("ProvingKey built {:?}", now.elapsed()).into());
    println!("ProvingKey built [{:?}]", now.elapsed());

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let mut all_inputs: Vec<&[F]> = Vec::new();
    for i in 0..input_deltas.len() {
        let d = input_deltas[i].as_slice();
        all_inputs.push(d);
    }

    let tmp = &[plaintext_digest, labelsum_digest];
    all_inputs.push(tmp);
    println!("{:?} all inputs len", all_inputs.len());

    let now = Instant::now();
    plonk::create_proof(
        &params,
        &pk,
        &[circuit],
        &[all_inputs.as_slice()],
        &mut rng,
        &mut transcript,
    )
    .unwrap();
    //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

    println!("Proof created [{:?}]", now.elapsed());

    let proof = transcript.finalize();

    let now = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    plonk::verify_proof(
        &params,
        &vk,
        strategy,
        &[all_inputs.as_slice()],
        &mut transcript,
    )
    .unwrap();
    //console::log_1(&format!("Proof verified {:?}", now.elapsed()).into());
    //console::log_1(&format!("Proof created {:?}", now.elapsed()).into());

    println!("Proof verified [{:?}]", now.elapsed());
    println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
}

#[test]
fn test() {
    use num::FromPrimitive;

    let two = BigUint::from_u8(2).unwrap();
    let pow_2_64 = two.pow(64);
    let pow_2_128 = two.pow(128);
    let pow_2_192 = two.pow(192);
}
