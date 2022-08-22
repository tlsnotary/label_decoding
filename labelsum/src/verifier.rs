use aes::{Aes128, NewBlockCipher};
use cipher::{consts::U16, generic_array::GenericArray, BlockCipher, BlockEncrypt};
use derive_macro::{define_accessors_trait, VerifierDataGetSet};
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub enum VerifierError {
    ProvingKeyNotFound,
    FileSystemError,
    FileDoesNotExist,
    SnarkjsError,
}

/// VerifierData contains fields common to all implementors of Verifier.
/// The implementor of Verifier must wrap VerifierData.
/// The field MUST be called `data`
#[define_accessors_trait(VerifierDataGetSet)]
#[derive(VerifierDataGetSet)]
pub struct VerifierData {
    // hashes for each chunk of Prover's plaintext
    plaintext_hashes: Option<Vec<BigUint>>,
    labelsum_hashes: Option<Vec<BigUint>>,
    // if set to true, then we must send the proving key to the Prover
    // before this protocol begins. Otherwise, it is assumed that the Prover
    // already has the proving key from a previous interaction with us.
    proving_key_needed: Option<bool>,
    deltas: Option<Vec<BigUint>>,
    zero_sums: Option<Vec<BigUint>>,
    ciphertexts: Option<Vec<[Vec<u8>; 2]>>,
    useful_bits: Option<usize>,
}
impl VerifierData {
    pub fn new(proving_key_needed: bool) -> Self {
        Self {
            plaintext_hashes: None,
            labelsum_hashes: None,
            proving_key_needed: Some(proving_key_needed),
            deltas: None,
            zero_sums: None,
            ciphertexts: None,
            useful_bits: Some(253),
        }
    }
}

/// The implementor of Verifier must wrap [VerifierData]. The field MUST be called `data`
pub trait Verifier {
    // these methods must be implemented:

    // Gets
    fn get_proving_key(&mut self) -> Result<Vec<u8>, VerifierError>;

    fn verify(
        &mut self,
        proof: Vec<u8>,
        deltas: Vec<String>,
        plaintext_hash: BigUint,
        labelsum_hash: BigUint,
        zero_sum: BigUint,
    ) -> Result<bool, VerifierError>;

    // return a reference to the `data` field
    fn data(&mut self) -> &mut VerifierData;

    // the rest of the methods have default implementations

    // Convert binary labels into encrypted arithmetic labels.
    // Prepare JSON objects to be converted into proof.json before verification
    fn setup(&mut self, labels: &Vec<[u128; 2]>) {
        // generate as many 128-bit arithm label pairs as there are plaintext bits.
        // The 128-bit size is for convenience to be able to encrypt the label with 1
        // call to AES.
        // To keep the handling simple, we want to avoid a negative delta, that's why
        // W_0 and delta must be 127-bit values and W_1 will be set to W_0 + delta

        let bitsize = labels.len();
        let chunk_size = 253 * 16 - 128;
        // count of chunks rounded up
        let chunk_count = (bitsize + (chunk_size - 1)) / chunk_size;

        let mut zero_sums: Vec<BigUint> = Vec::with_capacity(chunk_count);
        let mut deltas: Vec<BigUint> = Vec::with_capacity(bitsize);
        let mut all_arithm_labels: Vec<[BigUint; 2]> = Vec::with_capacity(bitsize);

        for count in 0..chunk_count {
            // calculate zero_sum for each chunk of plaintext separately
            let mut zero_sum = BigUint::from_u8(0).unwrap();
            // end of range is different for the last chunk
            let end = if count < chunk_count - 1 {
                (count + 1) * chunk_size
            } else {
                // compute the size of the gap at the end of the last chunk
                let last_size = bitsize % chunk_size;
                let gap_size = if last_size == 0 {
                    0
                } else {
                    chunk_size - last_size
                };
                (count + 1) * chunk_size - gap_size
            };
            all_arithm_labels.append(
                &mut (count * chunk_size..end)
                    .map(|_| {
                        let zero_label = random_bigint(127);
                        let delta = random_bigint(127);
                        let one_label = zero_label.clone() + delta.clone();
                        zero_sum += zero_label.clone();
                        deltas.push(delta);
                        [zero_label, one_label]
                    })
                    .collect(),
            );
            zero_sums.push(zero_sum);
        }
        self.data().set_zero_sums(Some(zero_sums));
        self.data().set_deltas(Some(deltas));

        // encrypt each arithmetic label using a corresponding binary label as a key
        // place ciphertexts in an order based on binary label's p&p bit
        let ciphertexts: Vec<[Vec<u8>; 2]> = labels
            .iter()
            .zip(all_arithm_labels)
            .map(|(bin_pair, arithm_pair)| {
                let zero_key = Aes128::new_from_slice(&bin_pair[0].to_be_bytes()).unwrap();
                let one_key = Aes128::new_from_slice(&bin_pair[1].to_be_bytes()).unwrap();
                let mut label0 = [0u8; 16];
                let mut label1 = [0u8; 16];
                let ap0 = arithm_pair[0].to_bytes_be();
                let ap1 = arithm_pair[1].to_bytes_be();
                // need to zero-pad on the left
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
            .collect();
        self.data().set_ciphertexts(Some(ciphertexts));
    }

    // receive hashes of plaintext and reveal the encrypted arithmetic labels
    fn receive_pt_hashes(&mut self, hashes: Vec<BigUint>) -> Vec<[Vec<u8>; 2]> {
        self.data().set_plaintext_hashes(Some(hashes));
        self.data().ciphertexts().as_ref().unwrap().clone()
    }

    // receive the hash commitment to the Prover's sum of labels and reveal all
    // deltas and zero_sums.
    fn receive_labelsum_hash(&mut self, hashes: Vec<BigUint>) -> (Vec<BigUint>, Vec<BigUint>) {
        self.data().set_labelsum_hashes(Some(hashes));
        (
            self.data().deltas().as_ref().unwrap().clone(),
            self.data().zero_sums().as_ref().unwrap().clone(),
        )
    }

    fn verify_many(&mut self, proofs: Vec<Vec<u8>>) -> Result<bool, VerifierError> {
        // // Write public.json. The elements must be written in the exact order
        // // as below, that's the order snarkjs expects them to be in.

        // the last chunk will be padded with zero plaintext. We also should pad
        // the deltas of the last chunk
        let useful_bits = self.data().useful_bits().unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = useful_bits * 16 - 128;
        let chunk_count =
            (self.data().deltas().as_ref().unwrap().len() + (chunk_size - 1)) / chunk_size;
        assert!(proofs.len() == chunk_count);

        let mut deltas = self.data().deltas().as_ref().unwrap().clone();
        // pad deltas with 0 values to make their count a multiple of a chunk size
        let delta_pad_count =
            chunk_size * chunk_count - self.data().deltas().as_ref().unwrap().len();
        deltas.extend(vec![BigUint::from_u8(0).unwrap(); delta_pad_count]);
        let deltas_chunks: Vec<&[BigUint]> = deltas.chunks(chunk_size).collect();

        for count in 0..chunk_count {
            // There are as many deltas as there are bits in the chunk of the
            // plaintext (not counting the salt)
            let delta_str: Vec<String> =
                deltas_chunks[count].iter().map(|v| v.to_string()).collect();

            let plaintext_hash = self.data().plaintext_hashes().as_ref().unwrap()[count].clone();
            let labelsum_hash = self.data().labelsum_hashes().as_ref().unwrap()[count].clone();
            let zero_sum = self.data().zero_sums().as_ref().unwrap()[count].clone();

            let res = self.verify(
                proofs[count].clone(),
                delta_str,
                plaintext_hash,
                labelsum_hash,
                zero_sum,
            );
            if res.is_err() {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}

fn random_bigint(bitsize: usize) -> BigUint {
    assert!(bitsize <= 128);
    let r: [u8; 16] = thread_rng().gen();
    // take only those bits which we need
    BigUint::from_bytes_be(&boolvec_to_u8vec(&u8vec_to_boolvec(&r)[0..bitsize]))
}

#[inline]
fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
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
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
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
