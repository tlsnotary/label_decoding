use super::boolvec_to_u8vec;
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::SeedableRng;
use rand::{thread_rng, Rng};
use rand_chacha::ChaCha20Rng;

// The PRG for generating arithmetic labels
type Prg = ChaCha20Rng;
pub type Seed = [u8; 32];
// The arithmetic label
type Label = BigUint;
pub type LabelPair = [Label; 2];

/// typestates are used to prevent generate() from being called multiple times
/// on the same instance of LabelSeed
pub trait State {}

pub struct Generate {
    seed: Seed,
}
pub struct Finished {}

impl State for Generate {}
impl State for Finished {}

pub struct LabelGenerator<S = Generate>
where
    S: State,
{
    state: S,
}

impl LabelGenerator {
    pub fn new() -> LabelGenerator<Generate> {
        LabelGenerator {
            state: Generate {
                seed: thread_rng().gen::<Seed>(),
            },
        }
    }

    pub fn new_from_seed(seed: Seed) -> LabelGenerator<Generate> {
        LabelGenerator {
            state: Generate { seed },
        }
    }
}

impl LabelGenerator<Generate> {
    /// Generates `count` arithmetic label pairs of size `label_size`. Returns
    /// the generated label pairs and the seed.
    pub fn generate(
        self,
        count: usize,
        label_size: usize,
    ) -> (Vec<LabelPair>, Seed, LabelGenerator<Finished>) {
        // To keep the handling simple, we want to avoid a negative delta, that's why
        // W_0 and delta must be (label_size - 1)-bit values and W_1 will be
        // set to W_0 + delta
        let mut prg = Prg::from_seed(self.state.seed);

        let label_pairs: Vec<LabelPair> = (0..count)
            .map(|_| {
                let zero_label: Vec<bool> = core::iter::repeat_with(|| prg.gen::<bool>())
                    .take(label_size - 1)
                    .collect();
                let zero_label = BigUint::from_bytes_be(&boolvec_to_u8vec(&zero_label));

                let delta: Vec<bool> = core::iter::repeat_with(|| prg.gen::<bool>())
                    .take(label_size - 1)
                    .collect();
                let delta = BigUint::from_bytes_be(&boolvec_to_u8vec(&delta));

                let one_label = zero_label.clone() + delta.clone();
                [zero_label, one_label]
            })
            .collect();

        (
            label_pairs,
            self.state.seed,
            LabelGenerator { state: Finished {} },
        )
    }
}
