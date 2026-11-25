//! The Halevi–Micali commitment of `crate::commitment` with SHA-256 in place
//! of BLAKE3, so the SLH-DSA blind signature uses one hash function: SHA-256
//! for SLH-DSA, for the commitment, and for Binius64's own transcript and
//! Merkle trees.
//!
//! Each of the three hashes, m̂ = H_msg(msg), y = H_com(r) and
//! d = H_sig(enc(M)), is SHA-256 of a 64-byte tag block followed by its
//! input. A tag block is ASCII padded with 0xFF, which keeps these inputs
//! apart from every other SHA-256 input in the scheme:
//! - SLH-DSA's F, H, T_l and PRF start with PK.seed || 0^48: bytes 16..64 zero;
//! - SLH-DSA's inner H_msg hash, with an empty context, has 0x00 0x00 at bytes 48..50;
//! - HMAC-SHA-256 in PRF_msg starts with K xor ipad/opad: bytes 16..64 all 0x36 or 0x5c;
//! - Binius64's Fiat–Shamir inputs start with a 32-byte SHA-256 chaining
//!   value, SHA-256("") for the first; its Merkle nodes use their own IV.
//!
//! Binius64's Merkle leaf hashes are plain SHA-256 over field elements and are
//! not separated by construction.
//!
//! A tag block is a constant first block, so the circuit starts from its
//! constant midstate and pays nothing for it.

use std::array;

use binius_circuits::bytes::swap_bytes_32;
use binius_circuits::sha256::{State, sha256_compress};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use sha2::{Digest, Sha256, block_api::compress256};

use super::native::SHA256_IV;
use crate::commitment::{
    CommitmentOpening, GhashElement, HmCommitment, N_DIGEST_WORDS, N_FE_WORDS, N_LINES, N_NONCE,
    N_Y, hm_commit_digest, sample_ghash,
};
use crate::gadgets::{GhashWires, bytes16_to_words, bytes32_to_words, hm_affine_check};

pub const TAG_BYTES: usize = 64;

const fn tag_block(label: &[u8]) -> [u8; TAG_BYTES] {
    assert!(label.len() <= 48);
    let mut t = [0xFF; TAG_BYTES];
    let mut i = 0;
    while i < label.len() {
        t[i] = label[i];
        i += 1;
    }
    t
}

pub const TAG_MESSAGE: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/message-hash");
pub const TAG_NONCE: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/commitment-y");
pub const TAG_DIGEST: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/commitment-d");

fn tagged(tag: &[u8; TAG_BYTES], data: &[u8]) -> [u8; N_Y] {
    let mut hs = Sha256::new();
    hs.update(tag);
    hs.update(data);
    hs.finalize().into()
}

fn tag_midstate(tag: &[u8; TAG_BYTES]) -> [u32; 8] {
    let mut st = SHA256_IV;
    compress256(&mut st, &[*tag]);
    st
}

/// m̂ = SHA-256(TAG_MESSAGE || msg).
pub fn message_hash(msg: &[u8]) -> [u8; N_Y] {
    tagged(&TAG_MESSAGE, msg)
}

/// y = SHA-256(TAG_NONCE || r_0 || ... || r_5).
pub fn nonce_hash(r: &[GhashElement; N_NONCE]) -> [u8; N_Y] {
    tagged(&TAG_NONCE, r.as_flattened())
}

/// d = SHA-256(TAG_DIGEST || enc(M)), the message SLH-DSA signs.
pub fn com_digest(com: &HmCommitment) -> [u8; N_Y] {
    tagged(&TAG_DIGEST, &com.to_bytes())
}

pub fn hm_commit(
    msg: &[u8],
    a: &[[GhashElement; N_NONCE]; N_LINES],
    r: &[GhashElement; N_NONCE],
) -> HmCommitment {
    hm_commit_digest(&message_hash(msg), a, r, nonce_hash(r))
}

/// Samples as `crate::commitment::sample_commitment` does, committing with SHA-256.
pub fn sample_commitment(
    rng: &mut impl rand::Rng,
    msg: &[u8],
) -> (HmCommitment, CommitmentOpening) {
    let (com, r) = sample_commitment_for_digest(rng, &message_hash(msg));
    (com, CommitmentOpening { msg: msg.to_vec(), r })
}

pub(super) fn sample_commitment_for_digest(
    rng: &mut impl rand::Rng,
    digest: &[u8; N_Y],
) -> (HmCommitment, [GhashElement; N_NONCE]) {
    let r = array::from_fn(|_| sample_ghash(rng));
    let a = array::from_fn(|_| array::from_fn(|_| sample_ghash(rng)));
    (hm_commit_digest(digest, &a, &r, nonce_hash(&r)), r)
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

/// Proves m̂_k = Σ_i a_{k,i} r_i + b_k, y = SHA-256(TAG_NONCE || r) and
/// d = SHA-256(TAG_DIGEST || a || b || y). The public inputs are the words of m̂.
pub struct ShaCommitGadget {
    m_hat: [Wire; N_DIGEST_WORDS],
    com_a: [[GhashWires; N_NONCE]; N_LINES],
    com_b: [GhashWires; N_LINES],
    r: [GhashWires; N_NONCE],
    d: [Wire; 8],
}

pub const COMMIT_INOUTS: usize = N_DIGEST_WORDS;

impl ShaCommitGadget {
    pub fn new(b: &CircuitBuilder) -> Self {
        let m_hat: [Wire; N_DIGEST_WORDS] = array::from_fn(|_| b.add_inout());
        let ghash = || -> GhashWires { array::from_fn(|_| b.add_witness()) };
        let com_a: [[GhashWires; N_NONCE]; N_LINES] =
            array::from_fn(|_| array::from_fn(|_| ghash()));
        let com_b: [GhashWires; N_LINES] = array::from_fn(|_| ghash());
        let r: [GhashWires; N_NONCE] = array::from_fn(|_| ghash());

        for k in 0..N_LINES {
            hm_affine_check(b, &com_a[k], &r, &com_b[k], &[m_hat[2 * k], m_hat[2 * k + 1]]);
        }

        let mask32 = b.add_constant(Word(0xFFFF_FFFF));
        let be = |elems: &[GhashWires]| -> Vec<Wire> {
            elems
                .iter()
                .flatten()
                .flat_map(|&w| be32_words(b, mask32, w))
                .collect()
        };
        let y = sha256_after_tag(b, &TAG_NONCE, &be(&r));
        let mut enc = be(com_a.as_flattened());
        enc.extend(be(&com_b));
        enc.extend_from_slice(&y);
        let d = sha256_after_tag(b, &TAG_DIGEST, &enc);

        Self {
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
        self.populate_digest(w, &message_hash(msg), com, r);
    }

    pub(super) fn populate_digest(
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

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn tags_are_distinct_and_outside_the_other_sha256_domains() {
        let empty: [u8; 32] = Sha256::digest([]).into();
        let tags = [TAG_MESSAGE, TAG_NONCE, TAG_DIGEST];
        for (i, t) in tags.iter().enumerate() {
            for u in &tags[i + 1..] {
                assert_ne!(t, u);
            }
            assert!(t[16..].iter().any(|&x| x != 0), "SLH-DSA F/H/T/PRF");
            assert!(t[16..].iter().any(|&x| x != 0x36), "HMAC inner pad");
            assert!(t[16..].iter().any(|&x| x != 0x5c), "HMAC outer pad");
            assert!(t[48] != 0 || t[49] != 0, "SLH-DSA H_msg, empty context");
            assert_ne!(&t[..32], &empty, "first Fiat–Shamir input");
        }
    }

    #[test]
    fn circuit_digest_matches_native() {
        let mut rng = StdRng::seed_from_u64(7);
        let msg = b"a document";
        let (com, opening) = sample_commitment(&mut rng, msg);

        let b = CircuitBuilder::new();
        let g = ShaCommitGadget::new(&b);
        let out: [Wire; 8] = array::from_fn(|_| b.add_inout());
        for i in 0..8 {
            b.assert_eq("d", g.digest_words()[i], out[i]);
        }
        let circuit = b.build();
        let d = com_digest(&com);
        let fill = |r: &[GhashElement; N_NONCE]| {
            let mut w = circuit.new_witness_filler();
            g.populate(&mut w, msg, &com, r);
            for i in 0..8 {
                let word = u32::from_be_bytes(d[4 * i..4 * i + 4].try_into().unwrap());
                w[out[i]] = Word(word as u64);
            }
            circuit.populate_wire_witness(&mut w).is_ok()
        };
        assert!(fill(&opening.r));
        let mut bad = opening.r;
        bad[0][0] ^= 1;
        assert!(!fill(&bad), "a wrong opening has no witness");
    }
}
