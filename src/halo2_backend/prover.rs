use super::circuit::{
    LabelsumCircuit, CELLS_PER_ROW, SALT_SIZE, TOTAL_FIELD_ELEMENTS, USEFUL_ROWS,
};
use super::poseidon::{poseidon_1, poseidon_15};
use super::utils::{bigint_to_f, deltas_to_matrices, f_to_bigint};
use super::{CHUNK_SIZE, USEFUL_BITS};
use crate::prover::{ProofInput, Prove, ProverError};
use halo2_proofs::plonk;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use instant::Instant;
use num::BigUint;
use pasta_curves::pallas::Base as F;
use pasta_curves::EqAffine;
use rand::thread_rng;

/// halo2's native ProvingKey can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct PK {
    pub key: ProvingKey<EqAffine>,
    pub params: Params<EqAffine>,
}

pub struct Prover {
    proving_key: PK,
}

impl Prove for Prover {
    fn prove(&self, input: ProofInput) -> Result<Vec<u8>, ProverError> {
        if input.deltas.len() != self.chunk_size() || input.plaintext.len() != TOTAL_FIELD_ELEMENTS
        {
            // this can only be caused by an error in
            // `crate::prover::LabelsumProver` logic
            return Err(ProverError::InternalError);
        }

        // convert into matrices
        let (deltas_as_rows, deltas_as_columns) =
            deltas_to_matrices(&input.deltas, self.useful_bits());

        // convert plaintext into F type
        let plaintext: [F; TOTAL_FIELD_ELEMENTS] = input
            .plaintext
            .iter()
            .map(|bigint| bigint_to_f(bigint))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // arrange into the format which halo2 expects
        let mut all_inputs: Vec<&[F]> = deltas_as_columns.iter().map(|v| v.as_slice()).collect();

        // add another column with public inputs
        let tmp = &[
            bigint_to_f(&input.plaintext_hash),
            bigint_to_f(&input.label_sum_hash),
            bigint_to_f(&input.sum_of_zero_labels),
        ];
        all_inputs.push(tmp);

        let now = Instant::now();

        // prepare the proving system and generate the proof:

        let circuit =
            LabelsumCircuit::new(plaintext, bigint_to_f(&input.salt), deltas_as_rows.into());

        let params = &self.proving_key.params;
        let pk = &self.proving_key.key;

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let mut rng = thread_rng();

        plonk::create_proof(
            params,
            pk,
            &[circuit],
            &[all_inputs.as_slice()],
            &mut rng,
            &mut transcript,
        )
        .unwrap();

        println!("Proof created [{:?}]", now.elapsed());
        let proof = transcript.finalize();
        println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
        Ok(proof)
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }

    fn poseidon_rate(&self) -> usize {
        TOTAL_FIELD_ELEMENTS
    }

    fn permutation_count(&self) -> usize {
        1
    }

    fn salt_size(&self) -> usize {
        SALT_SIZE
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    /// Hashes `inputs` with Poseidon and returns the digest as `BigUint`.
    fn hash(&self, inputs: &Vec<BigUint>) -> Result<BigUint, ProverError> {
        let digest = match inputs.len() {
            15 => {
                // hash with rate-15 Poseidon
                let fes: [F; 15] = inputs
                    .iter()
                    .map(|i| bigint_to_f(i))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                poseidon_15(&fes)
            }
            1 => {
                // hash with rate-1 Poseidon
                let fes: [F; 1] = inputs
                    .iter()
                    .map(|i| bigint_to_f(i))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                poseidon_1(&fes)
            }
            _ => return Err(ProverError::WrongPoseidonInput),
        };
        Ok(f_to_bigint(&digest))
    }
}

impl Prover {
    pub fn new(pk: PK) -> Self {
        Self { proving_key: pk }
    }
}
