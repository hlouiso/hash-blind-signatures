//! The Halevi–Micali commitment of `crate::commitment` under the SLH-DSA
//! tags, so the SLH-DSA blind signature uses one hash function: SHA-256 for
//! SLH-DSA, for the commitment, and for Binius64's own transcript and Merkle
//! trees.
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

use crate::commitment::{
    CommitTags, CommitmentOpening, GhashElement, HmCommitment, N_NONCE, N_Y, TAG_BYTES, tag_block,
};

pub use crate::gadgets::{COMMIT_INOUTS, ShaCommitGadget};

pub const TAG_MESSAGE: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/message-hash");
pub const TAG_NONCE: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/commitment-y");
pub const TAG_DIGEST: [u8; TAG_BYTES] = tag_block(b"blind-slh-dsa/sha256/v1/commitment-d");

/// The stateless scheme's tags.
pub const SLH_TAGS: CommitTags = CommitTags {
    message: TAG_MESSAGE,
    nonce: TAG_NONCE,
    digest: TAG_DIGEST,
};

/// m̂ = SHA-256(TAG_MESSAGE || msg).
pub fn message_hash(msg: &[u8]) -> [u8; N_Y] {
    SLH_TAGS.message_hash(msg)
}

/// y = SHA-256(TAG_NONCE || r_0 || ... || r_5).
pub fn nonce_hash(r: &[GhashElement; N_NONCE]) -> [u8; N_Y] {
    SLH_TAGS.nonce_hash(r)
}

/// d = SHA-256(TAG_DIGEST || enc(M)), the message SLH-DSA signs.
pub fn com_digest(com: &HmCommitment) -> [u8; N_Y] {
    SLH_TAGS.com_digest(com)
}

pub fn hm_commit(
    msg: &[u8],
    a: &[[GhashElement; crate::commitment::N_NONCE]; crate::commitment::N_LINES],
    r: &[GhashElement; N_NONCE],
) -> HmCommitment {
    SLH_TAGS.hm_commit(msg, a, r)
}

/// Samples as `crate::commitment::sample_commitment` does, under the SLH-DSA tags.
pub fn sample_commitment(
    rng: &mut impl rand::Rng,
    msg: &[u8],
) -> (HmCommitment, CommitmentOpening) {
    SLH_TAGS.sample_commitment(rng, msg)
}

pub(super) fn sample_commitment_for_digest(
    rng: &mut impl rand::Rng,
    digest: &[u8; N_Y],
) -> (HmCommitment, [GhashElement; N_NONCE]) {
    SLH_TAGS.sample_commitment_for_digest(rng, digest)
}

#[cfg(test)]
mod tests {
    use std::array;

    use binius_core::word::Word;
    use binius_frontend::{CircuitBuilder, Wire};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::{Digest, Sha256};

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
        let g = ShaCommitGadget::new(&b, &SLH_TAGS);
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
