//! The circuit proves y = BLAKE3(r), m̂_k = Σ_i a_{k,i}r_i + b_k, and an
//! XMSS signature on d = BLAKE3(a || b || y). The public inputs are m̂,
//! pk_seed, and the XMSS root; the commitment opening and epoch are secret.
//! GHASH limbs and circuit words are packed little-endian.

use binius_circuits::blake3::blake3_fixed;
use binius_circuits::hash_based_sig::xmss::{XmssSignatureWires, circuit_xmss_verify};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::commitment::{
    COMMITMENT_BYTES, HmCommitment, N_DIGEST_WORDS, N_FE, N_FE_WORDS, N_LINES, N_NONCE,
};
use crate::hashes::{DIGEST_WIRES, MESSAGE_WIRES, PUBLIC_PARAM_WIRES, blake3_256};
use crate::wots::{PK_SEED_BYTES, build_wots_domain_param};
use crate::xmss::XmssSignature;

pub const DOMAIN_PARAM_WIRES: usize = PUBLIC_PARAM_WIRES;

pub fn bytes32_to_words(b: &[u8; 32]) -> [Word; 4] {
    [
        Word(u64::from_le_bytes(b[0..8].try_into().unwrap())),
        Word(u64::from_le_bytes(b[8..16].try_into().unwrap())),
        Word(u64::from_le_bytes(b[16..24].try_into().unwrap())),
        Word(u64::from_le_bytes(b[24..32].try_into().unwrap())),
    ]
}

pub fn bytes16_to_words(b: &[u8; N_FE]) -> [Word; N_FE_WORDS] {
    [
        Word(u64::from_le_bytes(b[..8].try_into().unwrap())),
        Word(u64::from_le_bytes(b[8..].try_into().unwrap())),
    ]
}

fn split_lo_hi(b: &CircuitBuilder, w: Wire) -> [Wire; 2] {
    let lo = b.band(w, b.add_constant_64(0xFFFF_FFFF));
    let hi = b.shr(w, 32);
    [lo, hi]
}

fn combine_blake3_digest(b: &CircuitBuilder, out: &[Wire; 8]) -> [Wire; 4] {
    std::array::from_fn(|k| b.bor(out[2 * k], b.shl(out[2 * k + 1], 32)))
}

pub type GhashWires = [Wire; N_FE_WORDS];

pub fn hm_affine_check(
    b_circ: &CircuitBuilder,
    a: &[GhashWires; N_NONCE],
    r: &[GhashWires; N_NONCE],
    b_term: &GhashWires,
    m_hat: &GhashWires,
) {
    let mut acc = *b_term;
    for i in 0..N_NONCE {
        let (product_lo, product_hi) = b_circ.bmul(a[i][0], a[i][1], r[i][0], r[i][1]);
        acc[0] = b_circ.bxor(acc[0], product_lo);
        acc[1] = b_circ.bxor(acc[1], product_hi);
    }
    b_circ.assert_eq("hm_affine_lo", acc[0], m_hat[0]);
    b_circ.assert_eq("hm_affine_hi", acc[1], m_hat[1]);
}

pub struct Blake3RevealR {
    pub r: [GhashWires; N_NONCE],
    pub y_hat: [Wire; 8],
}

impl Blake3RevealR {
    pub fn new(b: &CircuitBuilder) -> Self {
        let r: [GhashWires; N_NONCE] =
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()));
        let mut r32: Vec<Wire> = Vec::with_capacity(N_NONCE * N_FE_WORDS * 2);
        for r_i in &r {
            for &word in r_i {
                r32.extend_from_slice(&split_lo_hi(b, word));
            }
        }
        let y_hat = blake3_fixed(b, &r32, N_NONCE * N_FE);

        Self { r, y_hat }
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, r_bytes: &[[u8; N_FE]; N_NONCE]) {
        for (i, b) in r_bytes.iter().enumerate() {
            let words = bytes16_to_words(b);
            for (j, word) in words.into_iter().enumerate() {
                w[self.r[i][j]] = word;
            }
        }
    }
}

pub const BLIND_COMMIT_INOUTS: usize = N_DIGEST_WORDS + DOMAIN_PARAM_WIRES;

pub struct BlindCommitGadget {
    pub m_hat: [Wire; N_DIGEST_WORDS],
    pub com_a: [[GhashWires; N_NONCE]; N_LINES],
    pub com_b: [GhashWires; N_LINES],
    pub domain_param: [Wire; DOMAIN_PARAM_WIRES],
    pub reveal_r: Blake3RevealR,
    com_d: [Wire; 4],
}

impl BlindCommitGadget {
    pub fn com_d(&self) -> &[Wire; 4] {
        &self.com_d
    }

    pub fn new(b: &CircuitBuilder) -> Self {
        let m_hat: [Wire; N_DIGEST_WORDS] = std::array::from_fn(|_| b.add_inout());
        let domain_param: [Wire; DOMAIN_PARAM_WIRES] = std::array::from_fn(|_| b.add_inout());

        let com_a: [[GhashWires; N_NONCE]; N_LINES] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()))
        });
        let com_b: [GhashWires; N_LINES] =
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()));

        let reveal_r = Blake3RevealR::new(b);

        for k in 0..N_LINES {
            let m_hat_k = [m_hat[2 * k], m_hat[2 * k + 1]];
            hm_affine_check(b, &com_a[k], &reveal_r.r, &com_b[k], &m_hat_k);
        }

        let mut d_msg: Vec<Wire> =
            Vec::with_capacity((N_LINES * N_NONCE + N_LINES) * N_FE_WORDS * 2 + 8);
        for line in &com_a {
            for a_i in line {
                for &word in a_i {
                    d_msg.extend_from_slice(&split_lo_hi(b, word));
                }
            }
        }
        for b_k in &com_b {
            for &word in b_k {
                d_msg.extend_from_slice(&split_lo_hi(b, word));
            }
        }
        d_msg.extend_from_slice(&reveal_r.y_hat);
        let d_digest = blake3_fixed(b, &d_msg, COMMITMENT_BYTES);
        let com_d = combine_blake3_digest(b, &d_digest);

        Self {
            m_hat,
            com_a,
            com_b,
            domain_param,
            reveal_r,
            com_d,
        }
    }

    pub fn inout_wires(&self) -> [Wire; BLIND_COMMIT_INOUTS] {
        let mut out = [self.m_hat[0]; BLIND_COMMIT_INOUTS];
        out[0..N_DIGEST_WORDS].copy_from_slice(&self.m_hat);
        out[N_DIGEST_WORDS..N_DIGEST_WORDS + DOMAIN_PARAM_WIRES]
            .copy_from_slice(&self.domain_param);
        out
    }

    pub fn populate(
        &self,
        w: &mut WitnessFiller<'_>,
        msg: &[u8],
        com: &HmCommitment,
        r: &[[u8; N_FE]; N_NONCE],
        domain_param: &[u8],
    ) {
        let m_hat_words = bytes32_to_words(&blake3_256(msg));
        for i in 0..N_DIGEST_WORDS {
            w[self.m_hat[i]] = m_hat_words[i];
        }
        for k in 0..N_LINES {
            for i in 0..N_NONCE {
                let words = bytes16_to_words(&com.a[k][i]);
                for (j, word) in words.into_iter().enumerate() {
                    w[self.com_a[k][i][j]] = word;
                }
            }
            let words = bytes16_to_words(&com.b[k]);
            for (j, word) in words.into_iter().enumerate() {
                w[self.com_b[k][j]] = word;
            }
        }
        let dp: &[u8; PK_SEED_BYTES] = domain_param
            .try_into()
            .expect("domain_param must be PK_SEED_BYTES bytes");
        for (wire, word) in self.domain_param.iter().zip(bytes16_to_words(dp)) {
            w[*wire] = word;
        }
        self.reveal_r.populate(w, r);
    }
}

pub fn build_blind_commit_public_words(
    msg: &[u8],
    pk_seed: &[u8; PK_SEED_BYTES],
) -> [Word; BLIND_COMMIT_INOUTS] {
    let m_hat_words = bytes32_to_words(&blake3_256(msg));
    let domain_param_words = bytes16_to_words(&build_wots_domain_param(pk_seed));

    let mut out = [Word::from_u64(0); BLIND_COMMIT_INOUTS];
    out[0..N_DIGEST_WORDS].copy_from_slice(&m_hat_words);
    out[N_DIGEST_WORDS..N_DIGEST_WORDS + DOMAIN_PARAM_WIRES].copy_from_slice(&domain_param_words);
    out
}

pub struct XmssVerifyGadget {
    epoch: Wire,
    signature: XmssSignatureWires,
}

impl XmssVerifyGadget {
    pub fn new(
        b: &CircuitBuilder,
        domain_param_wires: &[Wire; PUBLIC_PARAM_WIRES],
        signed_msg_wires: &[Wire; MESSAGE_WIRES],
        merkle_root_wires: &[Wire; DIGEST_WIRES],
    ) -> Self {
        let epoch = b.add_witness();
        let signature = XmssSignatureWires::new_witness(b);

        circuit_xmss_verify(
            b,
            domain_param_wires,
            merkle_root_wires,
            signed_msg_wires,
            epoch,
            &signature,
        );

        Self { epoch, signature }
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, xmss_sig: &XmssSignature) {
        w[self.epoch] = Word::from_u64(xmss_sig.epoch as u64);
        self.signature.populate(w, &xmss_sig.to_upstream());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{ghash_mul, sample_ghash};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn add_element_inout(b: &CircuitBuilder) -> GhashWires {
        std::array::from_fn(|_| b.add_inout())
    }

    fn add_element_witness(b: &CircuitBuilder) -> GhashWires {
        std::array::from_fn(|_| b.add_witness())
    }

    fn u128_words(value: u128) -> [Word; N_FE_WORDS] {
        [Word(value as u64), Word((value >> 64) as u64)]
    }

    fn random_u128(rng: &mut StdRng) -> u128 {
        u128::from_le_bytes(sample_ghash(rng))
    }

    fn fill_element(w: &mut WitnessFiller<'_>, wires: &GhashWires, value: u128) {
        for (wire, word) in wires.iter().zip(u128_words(value)) {
            w[*wire] = word;
        }
    }

    #[test]
    fn bmul_smoke_matches_native_ghash() {
        let b = CircuitBuilder::new();
        let x = add_element_inout(&b);
        let y = add_element_inout(&b);
        let z = add_element_inout(&b);
        let (product_lo, product_hi) = b.bmul(x[0], x[1], y[0], y[1]);
        b.assert_eq("bmul_lo", product_lo, z[0]);
        b.assert_eq("bmul_hi", product_hi, z[1]);

        let circuit = b.build();
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..20 {
            let xv = random_u128(&mut rng);
            let yv = random_u128(&mut rng);
            let zv = ghash_mul(xv, yv);

            let mut filler = circuit.new_witness_filler();
            fill_element(&mut filler, &x, xv);
            fill_element(&mut filler, &y, yv);
            fill_element(&mut filler, &z, zv);
            circuit
                .populate_wire_witness(&mut filler)
                .expect("populate");
            circuit
                .constraint_system()
                .verify(&filler.into_value_vec())
                .expect("constraints");
        }
    }

    #[test]
    fn hm_affine_check_in_circuit_matches_native() {
        let b = CircuitBuilder::new();
        let a: [GhashWires; N_NONCE] = std::array::from_fn(|_| add_element_inout(&b));
        let r: [GhashWires; N_NONCE] = std::array::from_fn(|_| add_element_witness(&b));
        let b_term = add_element_inout(&b);
        let m_hat = add_element_inout(&b);
        hm_affine_check(&b, &a, &r, &b_term, &m_hat);

        let circuit = b.build();
        let mut rng = StdRng::seed_from_u64(456);
        let mut a_vals = [0u128; N_NONCE];
        let mut r_vals = [0u128; N_NONCE];
        for i in 0..N_NONCE {
            a_vals[i] = random_u128(&mut rng);
            r_vals[i] = random_u128(&mut rng);
        }
        let m_val = random_u128(&mut rng);
        let mut sum = 0u128;
        for i in 0..N_NONCE {
            sum ^= ghash_mul(a_vals[i], r_vals[i]);
        }
        let b_val = m_val ^ sum;

        let mut filler = circuit.new_witness_filler();
        for i in 0..N_NONCE {
            fill_element(&mut filler, &a[i], a_vals[i]);
            fill_element(&mut filler, &r[i], r_vals[i]);
        }
        fill_element(&mut filler, &b_term, b_val);
        fill_element(&mut filler, &m_hat, m_val);

        circuit
            .populate_wire_witness(&mut filler)
            .expect("populate honest");
        circuit
            .constraint_system()
            .verify(&filler.into_value_vec())
            .expect("constraints honest");
    }

    #[test]
    fn hm_affine_check_rejects_wrong_b() {
        let b = CircuitBuilder::new();
        let a: [GhashWires; N_NONCE] = std::array::from_fn(|_| add_element_inout(&b));
        let r: [GhashWires; N_NONCE] = std::array::from_fn(|_| add_element_witness(&b));
        let b_term = add_element_inout(&b);
        let m_hat = add_element_inout(&b);
        hm_affine_check(&b, &a, &r, &b_term, &m_hat);

        let circuit = b.build();
        let mut rng = StdRng::seed_from_u64(789);
        let mut a_vals = [0u128; N_NONCE];
        let mut r_vals = [0u128; N_NONCE];
        for i in 0..N_NONCE {
            a_vals[i] = random_u128(&mut rng);
            r_vals[i] = random_u128(&mut rng);
        }
        let m_val = random_u128(&mut rng);
        let mut sum = 0u128;
        for i in 0..N_NONCE {
            sum ^= ghash_mul(a_vals[i], r_vals[i]);
        }
        let bad_b = (m_val ^ sum) ^ 1;

        let mut filler = circuit.new_witness_filler();
        for i in 0..N_NONCE {
            fill_element(&mut filler, &a[i], a_vals[i]);
            fill_element(&mut filler, &r[i], r_vals[i]);
        }
        fill_element(&mut filler, &b_term, bad_b);
        fill_element(&mut filler, &m_hat, m_val);

        let pop = circuit.populate_wire_witness(&mut filler);
        if pop.is_ok() {
            let result = circuit.constraint_system().verify(&filler.into_value_vec());
            assert!(result.is_err(), "tampered b should be rejected");
        }
    }
}
