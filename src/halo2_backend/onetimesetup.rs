use super::circuit::{LabelsumCircuit, CELLS_PER_ROW, K, USEFUL_ROWS};
use super::prover::PK;
use super::verifier::VK;
use halo2_proofs::plonk;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::EqAffine;

pub struct OneTimeSetup {
    proving_key: Option<PK>,
    verification_key: Option<VK>,
}

/// OneTimeSetup generates the proving key and the verification key. It can be
/// run ahead of time before the actual zk proving/verification takes place.
///
/// Note that as of Oct 2022 halo2 does not support serializing the proving/verification
/// keys. That's why we can't use cached keys but need to call this one-time setup every
/// time when we instantiate the halo2 prover/verifier.
impl OneTimeSetup {
    pub fn new() -> Self {
        Self {
            proving_key: None,
            verification_key: None,
        }
    }

    pub fn setup(&mut self) {
        let params: Params<EqAffine> = Params::new(K);
        // we need an instance of the circuit, the exact inputs don't matter
        let circuit = LabelsumCircuit::new(
            Default::default(),
            Default::default(),
            [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        );

        // safe to unwrap, we are inputting deterministic params and circuit on every
        // invocation
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

        self.proving_key = Some(PK {
            key: pk,
            params: params.clone(),
        });
        self.verification_key = Some(VK { key: vk, params });
    }

    pub fn get_proving_key(&self) -> PK {
        self.proving_key.as_ref().unwrap().clone()
    }

    pub fn get_verification_key(&self) -> VK {
        self.verification_key.as_ref().unwrap().clone()
    }
}
