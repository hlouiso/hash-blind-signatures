//! The circuit proves y = H_com(r), m̂_k = Σ_i a_{k,i}r_i + b_k, and an XMSS
//! signature on d = H_sig(a || b || y), with the tagged SHA-256 hashes of
//! `crate::commitment`. The public inputs are m̂, pk_seed, the XMSS root and
//! the epoch mask of the real height; the commitment opening and epoch are
//! secret. GHASH limbs are packed little-endian; pk_seed and the root are
//! packed eight big-endian bytes per word, the layout of `crate::ts_xmss`.

use std::array;

use binius_circuits::bytes::swap_bytes_32;
use binius_circuits::sha256::{State, sha256_compress};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::commitment::{
    CommitTags, GhashElement, HmCommitment, N_DIGEST_WORDS, N_FE, N_FE_WORDS, N_LINES, N_NONCE,
    N_Y, TAG_BYTES, XMSS_TAGS, tag_midstate,
};
use crate::hashes::{DIGEST_LEN, DIGEST_WIRES, LOG_LIFETIME, MESSAGE_WORDS, PUBLIC_PARAM_WIRES};
use crate::ts_xmss::hashing::{XmssHasher, packed_words};
use crate::ts_xmss::xmss::{XmssSignatureWires, circuit_xmss_verify};
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

/// A digest or public parameter as circuit words, eight big-endian bytes each.
pub fn node_words(b: &[u8; DIGEST_LEN]) -> [Word; DIGEST_WIRES] {
    packed_words(b).try_into().expect("two words")
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

/// The two big-endian 32-bit SHA-256 words of a little-endian 64-bit word.
fn be32_words(b: &CircuitBuilder, mask32: Wire, w: Wire) -> [Wire; 2] {
    let s = swap_bytes_32(b, w);
    [b.band(s, mask32), b.shr(s, 32)]
}

/// SHA-256(tag || data) for word-aligned data, from the tag's constant midstate.
fn sha256_after_tag(b: &CircuitBuilder, tag: &[u8; TAG_BYTES], data: &[Wire]) -> [Wire; 8] {
    let k = |v: u32| b.add_constant(Word(v as u64));
    let body = 4 * data.len();
    let nwords = (body + 9).div_ceil(64) * 16;
    let bit_len = ((TAG_BYTES + body) as u64) * 8;
    let mut words: Vec<Wire> = data.to_vec();
    words.push(k(0x8000_0000));
    while words.len() < nwords - 2 {
        words.push(k(0));
    }
    words.push(k((bit_len >> 32) as u32));
    words.push(k(bit_len as u32));
    let mid = tag_midstate(tag);
    let mut st = State(array::from_fn(|i| k(mid[i])));
    for blk in words.chunks_exact(16) {
        st = sha256_compress(b, st, array::from_fn(|i| blk[i]));
    }
    st.0
}

/// Proves m̂_k = Σ_i a_{k,i} r_i + b_k, y = SHA-256(nonce tag || r) and
/// d = SHA-256(digest tag || a || b || y). The public inputs are the words of m̂.
pub struct ShaCommitGadget {
    tags: &'static CommitTags,
    m_hat: [Wire; N_DIGEST_WORDS],
    com_a: [[GhashWires; N_NONCE]; N_LINES],
    com_b: [GhashWires; N_LINES],
    r: [GhashWires; N_NONCE],
    d: [Wire; 8],
}

pub const COMMIT_INOUTS: usize = N_DIGEST_WORDS;

impl ShaCommitGadget {
    pub fn new(b: &CircuitBuilder, tags: &'static CommitTags) -> Self {
        let m_hat: [Wire; N_DIGEST_WORDS] = array::from_fn(|_| b.add_inout());
        let ghash = || -> GhashWires { array::from_fn(|_| b.add_witness()) };
        let com_a: [[GhashWires; N_NONCE]; N_LINES] =
            array::from_fn(|_| array::from_fn(|_| ghash()));
        let com_b: [GhashWires; N_LINES] = array::from_fn(|_| ghash());
        let r: [GhashWires; N_NONCE] = array::from_fn(|_| ghash());

        for k in 0..N_LINES {
            hm_affine_check(
                b,
                &com_a[k],
                &r,
                &com_b[k],
                &[m_hat[2 * k], m_hat[2 * k + 1]],
            );
        }

        let mask32 = b.add_constant(Word(0xFFFF_FFFF));
        let be = |elems: &[GhashWires]| -> Vec<Wire> {
            elems
                .iter()
                .flatten()
                .flat_map(|&w| be32_words(b, mask32, w))
                .collect()
        };
        let y = sha256_after_tag(b, &tags.nonce, &be(&r));
        let mut enc = be(com_a.as_flattened());
        enc.extend(be(&com_b));
        enc.extend_from_slice(&y);
        let d = sha256_after_tag(b, &tags.digest, &enc);

        Self {
            tags,
            m_hat,
            com_a,
            com_b,
            r,
            d,
        }
    }

    /// d as eight big-endian 32-bit words, each in the low half of its wire.
    pub fn digest_words(&self) -> &[Wire; 8] {
        &self.d
    }

    pub fn inout_wires(&self) -> [Wire; COMMIT_INOUTS] {
        self.m_hat
    }

    pub fn populate(
        &self,
        w: &mut WitnessFiller<'_>,
        msg: &[u8],
        com: &HmCommitment,
        r: &[GhashElement; N_NONCE],
    ) {
        self.populate_digest(w, &self.tags.message_hash(msg), com, r);
    }

    pub fn populate_digest(
        &self,
        w: &mut WitnessFiller<'_>,
        digest: &[u8; N_Y],
        com: &HmCommitment,
        r: &[GhashElement; N_NONCE],
    ) {
        let put = |w: &mut WitnessFiller<'_>, wires: &GhashWires, e: &GhashElement| {
            let words: [Word; N_FE_WORDS] = bytes16_to_words(e);
            for (wire, word) in wires.iter().zip(words) {
                w[*wire] = word;
            }
        };
        for (wire, word) in self.m_hat.iter().zip(bytes32_to_words(digest)) {
            w[*wire] = word;
        }
        for k in 0..N_LINES {
            for i in 0..N_NONCE {
                put(w, &self.com_a[k][i], &com.a[k][i]);
            }
            put(w, &self.com_b[k], &com.b[k]);
        }
        for i in 0..N_NONCE {
            put(w, &self.r[i], &r[i]);
        }
    }
}

pub const BLIND_COMMIT_INOUTS: usize = N_DIGEST_WORDS + DOMAIN_PARAM_WIRES;

/// The stateful scheme's commitment, under [`XMSS_TAGS`], and the signer's
/// public parameter.
pub struct BlindCommitGadget {
    pub sha: ShaCommitGadget,
    pub domain_param: [Wire; DOMAIN_PARAM_WIRES],
}

impl BlindCommitGadget {
    pub fn new(b: &CircuitBuilder) -> Self {
        let sha = ShaCommitGadget::new(b, &XMSS_TAGS);
        let domain_param: [Wire; DOMAIN_PARAM_WIRES] = array::from_fn(|_| b.add_inout());
        Self { sha, domain_param }
    }

    /// d as the eight big-endian 32-bit words XMSS signs.
    pub fn com_d(&self) -> &[Wire; MESSAGE_WORDS] {
        self.sha.digest_words()
    }

    pub fn inout_wires(&self) -> [Wire; BLIND_COMMIT_INOUTS] {
        let mut out = [self.domain_param[0]; BLIND_COMMIT_INOUTS];
        out[..N_DIGEST_WORDS].copy_from_slice(&self.sha.inout_wires());
        out[N_DIGEST_WORDS..].copy_from_slice(&self.domain_param);
        out
    }

    pub fn populate(
        &self,
        w: &mut WitnessFiller<'_>,
        msg: &[u8],
        com: &HmCommitment,
        r: &[GhashElement; N_NONCE],
        domain_param: &[u8],
    ) {
        self.sha.populate(w, msg, com, r);
        let dp: &[u8; PK_SEED_BYTES] = domain_param
            .try_into()
            .expect("domain_param must be PK_SEED_BYTES bytes");
        for (wire, word) in self.domain_param.iter().zip(node_words(dp)) {
            w[*wire] = word;
        }
    }
}

pub fn build_blind_commit_public_words(
    msg: &[u8],
    pk_seed: &[u8; PK_SEED_BYTES],
) -> [Word; BLIND_COMMIT_INOUTS] {
    let m_hat_words = bytes32_to_words(&XMSS_TAGS.message_hash(msg));
    let domain_param_words = node_words(&build_wots_domain_param(pk_seed));

    let mut out = [Word::from_u64(0); BLIND_COMMIT_INOUTS];
    out[0..N_DIGEST_WORDS].copy_from_slice(&m_hat_words);
    out[N_DIGEST_WORDS..N_DIGEST_WORDS + DOMAIN_PARAM_WIRES].copy_from_slice(&domain_param_words);
    out
}

/// The bits of an epoch at or above the real height h. An epoch with any of
/// them set climbs into the seed-derived siblings instead of the real tree.
pub fn epoch_mask(height: usize) -> Word {
    assert!(
        (1..=LOG_LIFETIME).contains(&height),
        "XMSS height must be in 1..={LOG_LIFETIME}, got {height}",
    );
    Word::from_u64(!((1u64 << height) - 1))
}

/// The path climbs all `LOG_LIFETIME` levels, so the circuit itself must keep
/// the epoch below 2^h; `mask` is the public `epoch_mask(h)`.
pub fn assert_epoch_below_height(b: &CircuitBuilder, epoch: Wire, mask: Wire) {
    b.assert_zero("epoch_below_height", b.band(epoch, mask));
}

pub struct XmssVerifyGadget {
    epoch: Wire,
    signature: XmssSignatureWires,
}

impl XmssVerifyGadget {
    pub fn new(
        b: &CircuitBuilder,
        domain_param_wires: &[Wire; PUBLIC_PARAM_WIRES],
        signed_msg_words: &[Wire; MESSAGE_WORDS],
        merkle_root_wires: &[Wire; DIGEST_WIRES],
        epoch_mask_wire: Wire,
    ) -> Self {
        let epoch = b.add_witness();
        let signature = XmssSignatureWires::new_witness(b);

        assert_epoch_below_height(b, epoch, epoch_mask_wire);

        let h = XmssHasher::new(b, domain_param_wires, epoch);
        circuit_xmss_verify(
            &h,
            domain_param_wires,
            merkle_root_wires,
            signed_msg_words,
            &signature,
        );

        Self { epoch, signature }
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, xmss_sig: &XmssSignature) {
        w[self.epoch] = Word::from_u64(xmss_sig.epoch as u64);
        self.signature.populate(w, &xmss_sig.to_signature());
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
