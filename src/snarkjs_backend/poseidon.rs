use std::str::FromStr;

use ark_bn254::Fr as F;
use ark_sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_sponge::CryptographicSponge;
use ark_sponge::FieldBasedCryptographicSponge;
use lazy_static::lazy_static;
use num::{BigUint, Num};
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;

/// additive round keys for a specific Poseidon rate
/// outer vec length equals to total (partial + full) round count
/// inner vec length equals rate + capacity (our Poseidon's capacity is fixed at 1)
type Ark = Vec<Vec<F>>;

/// MDS matrix
/// outer vec length equals to rate+1, inner rate length also equals to rate+1
type Mds = Vec<Vec<F>>;

/// Both PARTIAL_ROUNDS and FULL_ROUNDS are copied from circomlib's poseidon.circom
/// index+1 represents the "rate" of the Poseidon
/// the value is the amount of partial rounds corresponding to that rate
/// e.g. for Poseidon with rate 2 we use 57 partial rounds
const PARTIAL_ROUNDS: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];
const FULL_ROUNDS: usize = 8;

pub struct Poseidon {
    arks: Vec<Ark>,
    mdss: Vec<Mds>,
}

impl Poseidon {
    pub fn new() -> Poseidon {
        let (arks, mdss) = setup();
        Poseidon { arks, mdss }
    }

    // hash the input with Poseidon and return the digest
    pub fn hash(&self, input: &Vec<BigUint>) -> BigUint {
        if input.len() > 16 {
            panic!("> 16 not supported");
        }
        // Each Poseidon rate requires a separate config
        let rate = input.len();
        // create the config on the fly since it is a cheap operation
        let config = PoseidonConfig {
            full_rounds: FULL_ROUNDS,
            partial_rounds: PARTIAL_ROUNDS[rate - 1],
            alpha: 5,
            ark: self.arks[rate - 1].clone(),
            mds: self.mdss[rate - 1].clone(),
            rate,
            // This is always fixed at 1
            capacity: 1,
        };

        let mut sponge = PoseidonSponge::<F>::new(&config);
        // convert input to Field elements
        let fes: Vec<F> = input
            .iter()
            .map(|x| F::from_str(&x.to_string()).unwrap())
            .collect();
        sponge.absorb(&fes);
        let fe: Vec<F> = sponge.squeeze_native_field_elements(1);
        BigUint::from_str(&fe[0].to_string()).unwrap()
    }
}

fn setup() -> (Vec<Ark>, Vec<Mds>) {
    let mut file = File::open("circom/poseidon_constants_old.circom").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    lazy_static! {
        // match either very long decimal numbers or 32-byte hex numbers
        static ref RE: Regex = Regex::new(r"([0-9]{60,90})|(0x[0-9a-f]{64})").unwrap();
    }

    // convert all matched strings into Field elements
    let v: Vec<F> = RE
        .find_iter(&contents)
        .map(|m| {
            let m = m.as_str();
            let decimal: String = if m.starts_with("0x") {
                // convert from hex to decimal
                BigUint::from_str_radix(&m[2..], 16)
                    .unwrap()
                    .to_str_radix(10)
            } else {
                // already decimal
                m.into()
            };
            F::from_str(&decimal).unwrap()
        })
        .collect();
    // discard the first hex number from the comment in the file
    let v = v[1..].to_vec();

    let mut arks: Vec<Ark> = Vec::with_capacity(16);
    // split into arks (additive round keys) for each rate
    let mut offset = 0;
    for rate in 1..17 {
        let total = (rate + 1) * (PARTIAL_ROUNDS[rate - 1] + FULL_ROUNDS);
        let elems = &v[offset..offset + total];
        offset += total;
        arks.push(elems.chunks(rate + 1).map(|x| x.to_vec()).collect());
    }

    let mut mdss: Vec<Mds> = Vec::with_capacity(16);
    for rate in 1..17 {
        let total = (rate + 1) * (rate + 1);
        let elems = &v[offset..offset + total];
        offset += total;
        mdss.push(elems.chunks(rate + 1).map(|x| x.to_vec()).collect());
    }
    // we should have consumed all elements
    assert!(v.len() == offset);
    (arks, mdss)
}
