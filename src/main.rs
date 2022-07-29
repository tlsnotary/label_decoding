/// implementing the "label sum" protocol
///
use num::{BigUint, FromPrimitive, ToPrimitive, Zero};
use rand::{thread_rng, Rng};

// implementation of the Prover in the "label sum" protocol (aka the User).
pub struct LsumProver {
    plaintext: Vec<u8>,
    // the prime of the field in which Poseidon hash will be computed.
    field_prime: BigUint,
    // how many bits to pack into one field element
    bits_to_pack: Option<usize>,
    // We will compute a separate Poseidon hash on each chunk of the plaintext.
    // Each chunk contains 16 field elements.
    chunks: Option<Vec<[BigUint; 16]>>,
    // each chunk's last 128 bits are used for the salt. This is important for
    // security b/c w/o the salt, hashes of plaintext with low entropy could be
    // brute-forced.
    salts: Option<Vec<BigUint>>,
}

impl LsumProver {
    pub fn new(plaintext: Vec<u8>, field_prime: BigUint) -> Self {
        if field_prime.bits() < 129 {
            // last field element must be large enough to contain the 128-bit
            // salt. In the future, if we need to support fields < 129 bits,
            // we can split the salt between multiple field elements.
            panic!("Error: expected a prime >= 129 bits");
        }
        Self {
            plaintext,
            field_prime,
            bits_to_pack: None,
            chunks: None,
            salts: None,
        }
    }

    pub fn setup(&mut self) {
        let bits_to_pack = compute_full_bits(self.field_prime.clone());
        self.bits_to_pack = Some(bits_to_pack);
        let (chunks, salts) = self.plaintext_to_chunks();
        self.chunks = Some(chunks);
        self.salts = Some(salts);
    }

    // create chunks of plaintext where each chunk consists of 16 field elements.
    // The last element's last 128 bits are reserved for the salt of the hash.
    // If there is not enough plaintext to fill the whole chunk, we fill the gap
    // with zero bits.
    fn plaintext_to_chunks(&mut self) -> (Vec<[BigUint; 16]>, Vec<BigUint>) {
        let bits_to_pack = self.bits_to_pack.unwrap();
        // the size of a chunk of plaintext not counting the salt
        let chunk_size = bits_to_pack * 16 - 128;
        // plaintext converted into bits
        let mut bits = u8vec_to_boolvec(&self.plaintext);
        // chunk count (rounded up)
        let chunk_count = (bits.len() + (chunk_size - 1)) / chunk_size;
        // extend bits with zeroes to fill the chunk
        bits.extend(vec![false; chunk_count * chunk_size - bits.len()]);
        let mut chunks: Vec<[BigUint; 16]> = Vec::with_capacity(chunk_count);
        let mut salts: Vec<BigUint> = Vec::with_capacity(chunk_count);
        // current offset within bits
        let mut offset: usize = 0;
        for i in 0..chunk_count {
            // TODO is there a cleaner way to init an array of BigUint b/c
            // [BigUint::default(); 16]; gave a Copy trait error
            let mut chunk = [
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
                BigUint::default(),
            ];
            for j in 0..15 {
                // convert bits into field element
                chunk[j] =
                    BigUint::from_bytes_be(&boolvec_to_u8vec(&bits[offset..offset + bits_to_pack]));
                offset += bits_to_pack;
            }
            // last field element's last 128 bits are for the salt
            let mut rng = thread_rng();
            let salt: [u8; 16] = rng.gen();
            let salt = u8vec_to_boolvec(&salt);

            let mut last_fe = vec![false; bits_to_pack];
            last_fe[0..bits_to_pack - 128]
                .copy_from_slice(&bits[offset..offset + (bits_to_pack - 128)]);
            offset += bits_to_pack - 128;
            last_fe[bits_to_pack - 128..].copy_from_slice(&salt);
            chunk[15] = BigUint::from_bytes_be(&boolvec_to_u8vec(&last_fe));

            let salt = BigUint::from_bytes_be(&boolvec_to_u8vec(&salt));
            salts.push(salt);
            chunks.push(chunk);
        }
        (chunks, salts)
    }
}

/// Computes how many bits of plaintext we will pack into one field element.
/// Essentially, this is field_prime bit length minus 1.
fn compute_full_bits(field_prime: BigUint) -> usize {
    (field_prime.bits() - 1) as usize
}

#[test]
fn test_compute_full_bits() {
    assert_eq!(compute_full_bits(BigUint::from_u16(13).unwrap()), 3);
    assert_eq!(compute_full_bits(BigUint::from_u16(255).unwrap()), 7);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_plaintext_to_chunks() {
        // 137-bit prime. Plaintext will be packed into 136 bits (17 bytes).
        let mut prime = vec![false; 137];
        prime[0] = true;
        let prime = boolvec_to_u8vec(&prime);
        let prime = BigUint::from_bytes_be(&prime);
        // plaintext will spawn 2 chunks
        let mut plaintext = vec![0u8; 17 * 15 + 1 + 17 * 5];
        // first chunk's field elements
        for i in 0..15 {
            // make the last byte of each field element unique
            plaintext[i * 17 + 16] = i as u8;
        }
        // first chunk's last field element's plaintext is 1 zero byte. The
        // rest of the field element will be filled with salt
        plaintext[15 * 17] = 0u8;

        // second chunk's field elements
        for i in 0..5 {
            // make the last byte of each field element unique
            plaintext[(15 * 17 + 1) + i * 17 + 16] = (i + 16) as u8;
        }

        let mut prover = LsumProver::new(plaintext, prime);
        prover.setup();

        // Check chunk1 correctness
        let chunk1: Vec<u128> = prover.chunks.clone().unwrap()[0][0..15]
            .iter()
            .map(|bigint| bigint.to_u128().unwrap())
            .collect();
        assert_eq!(chunk1, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        // the last field element must be random salt. We just check that the
        // salt has been set, i.e. it is not equal 0
        assert!(!prover.chunks.clone().unwrap()[0][15].eq(&BigUint::from_u8(0).unwrap()));

        // Check chunk2 correctness
        let chunk2: Vec<u128> = prover.chunks.clone().unwrap()[1][0..15]
            .iter()
            .map(|bigint| bigint.to_u128().unwrap())
            .collect();
        assert_eq!(chunk2, [16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // the last field element must be random salt. We just check that the
        // salt has been set, i.e. it is not equal 0
        assert!(!prover.chunks.clone().unwrap()[1][15].eq(&BigUint::from_u8(0).unwrap()));
    }
}

fn main() {
    println!("Hello, world!");
}
