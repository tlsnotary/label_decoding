use super::circuit::{LabelsumCircuit, K, USEFUL_ROWS};
use halo2_proofs::plonk;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::pallas::Base as F;
use pasta_curves::EqAffine;

pub struct OneTimeSetup {
    proving_key: Option<ProvingKey<EqAffine>>,
    verification_key: Option<VerifyingKey<EqAffine>>,
}

#[derive(Debug)]
pub enum Error {
    FileDoesNotExist,
    SnarkjsError,
}

// OneTimeSetup should be run when Notary starts. It generates a proving and
// a verification keys.
// Note that currently halo2 does not support serializing the proving/verification
// keys. That's why we can't use cached keys but need to re-generate them every time.
impl OneTimeSetup {
    pub fn new() -> Self {
        Self {
            proving_key: None,
            verification_key: None,
        }
    }

    pub fn setup(&self) -> Result<(), Error> {
        let params: Params<EqAffine> = Params::new(K);
        // we need an instance of the circuit, the exact inputs don't matter
        let dummy1 = [F::from(0); 15];
        let dummy2: [Vec<F>; USEFUL_ROWS] = (0..USEFUL_ROWS)
            .map(|_| vec![F::from(0)])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let circuit = LabelsumCircuit::new(dummy1, dummy2);

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

        self.proving_key = Some(pk);
        self.verification_key = Some(vk);

        Ok(())
    }

    pub fn get_proving_key(&self) -> ProvingKey<EqAffine> {
        self.proving_key.unwrap()
    }
}
