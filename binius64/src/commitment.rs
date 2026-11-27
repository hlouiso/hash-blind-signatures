//! Halevi–Micali commitment over GF(2^128) with (n, s, k) = (128, 2, 6).
//! Field elements use little-endian polynomial-basis encoding.
//!
//! Each of the three hashes, m̂ = H_msg(msg), y = H_com(r) and
//! d = H_sig(enc(M)), is SHA-256 of a 64-byte tag block followed by its
//! input. A tag block is ASCII padded with 0xFF, which keeps these inputs
//! apart from every other SHA-256 input of the scheme (see
//! [`XMSS_TAGS`] and `crate::slh::commit::SLH_TAGS`). A tag block is a
//! constant first block, so the circuit starts from its constant midstate and
//! pays nothing for it.
//!
//! The free functions here are the stateful (XMSS) scheme's, under
//! [`XMSS_TAGS`].

use binius_field::Ghash128b;
use sha2::{Digest, Sha256, block_api::compress256};

use crate::sha_stream::SHA256_IV;

pub const N_FE: usize = 16;
pub const N_FE_WORDS: usize = N_FE / 8;
pub const N_Y: usize = 32;
pub const N_NONCE: usize = 6;
pub const N_DIGEST_WORDS: usize = N_Y / 8;
pub const N_LINES: usize = N_Y / N_FE;

pub type GhashElement = [u8; N_FE];

#[inline]
fn field_from_bytes(value: &GhashElement) -> Ghash128b {
    Ghash128b::new(u128::from_le_bytes(*value))
}

#[inline]
fn field_to_bytes(value: Ghash128b) -> GhashElement {
    u128::from(value).to_le_bytes()
}

#[inline]
pub fn ghash_mul(a: u128, b: u128) -> u128 {
    u128::from(Ghash128b::new(a) * Ghash128b::new(b))
}

pub fn sample_ghash(rng: &mut impl rand::Rng) -> GhashElement {
    let mut out = [0u8; N_FE];
    rng.fill_bytes(&mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmCommitment {
    pub a: [[GhashElement; N_NONCE]; N_LINES],
    pub b: [GhashElement; N_LINES],
    pub y: [u8; N_Y],
}

pub const COMMITMENT_BYTES: usize = N_LINES * N_NONCE * N_FE + N_LINES * N_FE + N_Y;

impl HmCommitment {
    pub fn to_bytes(&self) -> [u8; COMMITMENT_BYTES] {
        let mut out = [0u8; COMMITMENT_BYTES];
        let mut offset = 0;
        for line in &self.a {
            for a_i in line {
                out[offset..offset + N_FE].copy_from_slice(a_i);
                offset += N_FE;
            }
        }
        for b_k in &self.b {
            out[offset..offset + N_FE].copy_from_slice(b_k);
            offset += N_FE;
        }
        out[offset..offset + N_Y].copy_from_slice(&self.y);
        out
    }

    pub fn from_bytes(buf: &[u8; COMMITMENT_BYTES]) -> Self {
        let mut offset = 0;
        let mut take = |n: usize| {
            let slice = &buf[offset..offset + n];
            offset += n;
            slice
        };
        let a = std::array::from_fn(|_| {
            std::array::from_fn(|_| take(N_FE).try_into().expect("N_FE bytes"))
        });
        let b = std::array::from_fn(|_| take(N_FE).try_into().expect("N_FE bytes"));
        let y = take(N_Y).try_into().expect("N_Y bytes");
        HmCommitment { a, b, y }
    }
}

pub const TAG_BYTES: usize = 64;

/// A label padded with 0xFF to a full SHA-256 block.
pub const fn tag_block(label: &[u8]) -> [u8; TAG_BYTES] {
    assert!(label.len() <= 48);
    let mut t = [0xFF; TAG_BYTES];
    let mut i = 0;
    while i < label.len() {
        t[i] = label[i];
        i += 1;
    }
    t
}

/// The tag blocks of H_msg, H_com and H_sig.
pub struct CommitTags {
    pub message: [u8; TAG_BYTES],
    pub nonce: [u8; TAG_BYTES],
    pub digest: [u8; TAG_BYTES],
}

/// The stateful scheme's tags. Byte 16 is ASCII, where every XMSS hash input
/// (`crate::ts_xmss::hashing`) has its tweak in 0..=3, and bytes 48..64 are
/// 0xFF; HMAC-SHA-256 blocks have 0x36 or 0x5c there, and Binius64's first
/// Fiat–Shamir input starts with SHA-256("").
pub const XMSS_TAGS: CommitTags = CommitTags {
    message: tag_block(b"blind-xmss/sha256/v1/message-hash"),
    nonce: tag_block(b"blind-xmss/sha256/v1/commitment-y"),
    digest: tag_block(b"blind-xmss/sha256/v1/commitment-d"),
};

/// SHA-256(tag || data).
pub fn tagged(tag: &[u8; TAG_BYTES], data: &[u8]) -> [u8; N_Y] {
    let mut hs = Sha256::new();
    hs.update(tag);
    hs.update(data);
    hs.finalize().into()
}

/// The SHA-256 state after a tag block.
pub fn tag_midstate(tag: &[u8; TAG_BYTES]) -> [u32; 8] {
    let mut st = SHA256_IV;
    compress256(&mut st, &[*tag]);
    st
}

impl CommitTags {
    /// m̂ = SHA-256(message tag || msg).
    pub fn message_hash(&self, msg: &[u8]) -> [u8; N_Y] {
        tagged(&self.message, msg)
    }

    /// y = SHA-256(nonce tag || r_0 || ... || r_5).
    pub fn nonce_hash(&self, r: &[GhashElement; N_NONCE]) -> [u8; N_Y] {
        tagged(&self.nonce, r.as_flattened())
    }

    /// d = SHA-256(digest tag || enc(M)), the message the signer signs.
    pub fn com_digest(&self, com: &HmCommitment) -> [u8; N_Y] {
        tagged(&self.digest, &com.to_bytes())
    }

    pub fn hm_commit(
        &self,
        msg: &[u8],
        a: &[[GhashElement; N_NONCE]; N_LINES],
        r: &[GhashElement; N_NONCE],
    ) -> HmCommitment {
        hm_commit_digest(&self.message_hash(msg), a, r, self.nonce_hash(r))
    }

    /// A commitment to `digest` with fresh a and r.
    pub fn sample_commitment_for_digest(
        &self,
        rng: &mut impl rand::Rng,
        digest: &[u8; N_Y],
    ) -> (HmCommitment, [GhashElement; N_NONCE]) {
        let r = std::array::from_fn(|_| sample_ghash(rng));
        let a = std::array::from_fn(|_| std::array::from_fn(|_| sample_ghash(rng)));
        (hm_commit_digest(digest, &a, &r, self.nonce_hash(&r)), r)
    }

    pub fn sample_commitment(
        &self,
        rng: &mut impl rand::Rng,
        msg: &[u8],
    ) -> (HmCommitment, CommitmentOpening) {
        let (com, r) = self.sample_commitment_for_digest(rng, &self.message_hash(msg));
        (
            com,
            CommitmentOpening {
                msg: msg.to_vec(),
                r,
            },
        )
    }

    pub fn verify_hm_opening(
        &self,
        com: &HmCommitment,
        msg: &[u8],
        r: &[GhashElement; N_NONCE],
    ) -> bool {
        if self.nonce_hash(r) != com.y {
            return false;
        }

        let m_hat = encode_digest(&self.message_hash(msg));
        for (k, m_hat_k) in m_hat.iter().enumerate() {
            let mut lhs = field_from_bytes(&com.b[k]);
            for (a_ki, r_i) in com.a[k].iter().zip(r) {
                lhs += field_from_bytes(a_ki) * field_from_bytes(r_i);
            }
            if lhs != field_from_bytes(m_hat_k) {
                return false;
            }
        }
        true
    }
}

/// m̂ = H_msg(msg) of the stateful scheme.
pub fn message_hash(msg: &[u8]) -> [u8; N_Y] {
    XMSS_TAGS.message_hash(msg)
}

/// d = H_sig(enc(M)) of the stateful scheme, the message XMSS signs.
pub fn com_digest(com: &HmCommitment) -> [u8; N_Y] {
    XMSS_TAGS.com_digest(com)
}

#[derive(Debug, Clone)]
pub struct CommitmentOpening {
    pub msg: Vec<u8>,
    pub r: [GhashElement; N_NONCE],
}

pub fn encode_digest(m_hat: &[u8; N_Y]) -> [GhashElement; N_LINES] {
    std::array::from_fn(|k| {
        m_hat[k * N_FE..(k + 1) * N_FE]
            .try_into()
            .expect("digest half has sixteen bytes")
    })
}

pub fn encode_message(msg: &[u8]) -> [GhashElement; N_LINES] {
    encode_digest(&message_hash(msg))
}

pub fn hm_commit(
    msg: &[u8],
    a: &[[GhashElement; N_NONCE]; N_LINES],
    r: &[GhashElement; N_NONCE],
) -> HmCommitment {
    XMSS_TAGS.hm_commit(msg, a, r)
}

/// The commitment to a message digest `m_hat`, with `y` the hash of `r`, for
/// whichever hash function computes both.
pub fn hm_commit_digest(
    m_hat: &[u8; N_Y],
    a: &[[GhashElement; N_NONCE]; N_LINES],
    r: &[GhashElement; N_NONCE],
    y: [u8; N_Y],
) -> HmCommitment {
    let m_hat = encode_digest(m_hat);
    let mut b = [[0u8; N_FE]; N_LINES];

    for k in 0..N_LINES {
        let mut sum = Ghash128b::new(0);
        for i in 0..N_NONCE {
            sum += field_from_bytes(&a[k][i]) * field_from_bytes(&r[i]);
        }
        b[k] = field_to_bytes(field_from_bytes(&m_hat[k]) + sum);
    }

    HmCommitment { a: *a, b, y }
}

pub fn sample_commitment(
    rng: &mut impl rand::Rng,
    msg: &[u8],
) -> (HmCommitment, CommitmentOpening) {
    XMSS_TAGS.sample_commitment(rng, msg)
}

pub fn verify_hm_opening(com: &HmCommitment, msg: &[u8], r: &[GhashElement; N_NONCE]) -> bool {
    XMSS_TAGS.verify_hm_opening(com, msg, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn seeded_keys(seed: u64) -> ([[GhashElement; N_NONCE]; N_LINES], [GhashElement; N_NONCE]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut a = [[[0u8; N_FE]; N_NONCE]; N_LINES];
        let mut r = [[0u8; N_FE]; N_NONCE];
        for r_i in &mut r {
            *r_i = sample_ghash(&mut rng);
        }
        for line in &mut a {
            for a_i in line {
                *a_i = sample_ghash(&mut rng);
            }
        }
        (a, r)
    }

    #[test]
    fn ghash_reduction_polynomial_matches_bmul_convention() {
        assert_eq!(ghash_mul(1, 0x1234), 0x1234);
        assert_eq!(ghash_mul(1u128 << 127, 2), 0x87);
    }

    #[test]
    fn digest_encoding_is_direct_and_injective() {
        let digest: [u8; N_Y] = std::array::from_fn(|i| i as u8);
        let encoded = encode_digest(&digest);
        assert_eq!(encoded[0], digest[..16]);
        assert_eq!(encoded[1], digest[16..]);
        assert_eq!([encoded[0], encoded[1]].concat(), digest);
    }

    #[test]
    fn commitment_size_is_256_bytes() {
        assert_eq!(COMMITMENT_BYTES, 256);
    }

    #[test]
    fn hm_commit_deterministic() {
        let (a, r) = seeded_keys(1);
        assert_eq!(hm_commit(b"hello", &a, &r), hm_commit(b"hello", &a, &r));
    }

    #[test]
    fn verify_hm_opening_accepts_correct() {
        let (a, r) = seeded_keys(2);
        let msg = b"test message";
        let com = hm_commit(msg, &a, &r);
        assert!(verify_hm_opening(&com, msg, &r));
    }

    #[test]
    fn verify_hm_opening_rejects_wrong_msg() {
        let (a, r) = seeded_keys(3);
        let com = hm_commit(b"correct", &a, &r);
        assert!(!verify_hm_opening(&com, b"wrong", &r));
    }

    #[test]
    fn verify_hm_opening_rejects_wrong_r() {
        let (a, r) = seeded_keys(4);
        let msg = b"hello";
        let com = hm_commit(msg, &a, &r);
        let mut r_bad = r;
        r_bad[3][0] ^= 1;
        assert!(!verify_hm_opening(&com, msg, &r_bad));
    }

    #[test]
    fn verify_hm_opening_rejects_permuted_r() {
        let (a, r) = seeded_keys(5);
        let msg = b"hello";
        let com = hm_commit(msg, &a, &r);
        let mut r_perm = r;
        r_perm.swap(0, 1);
        assert!(!verify_hm_opening(&com, msg, &r_perm));
    }

    #[test]
    fn verify_hm_opening_rejects_tampered_b() {
        let (a, r) = seeded_keys(6);
        let msg = b"hello";
        let mut com = hm_commit(msg, &a, &r);
        com.b[1][0] ^= 1;
        assert!(!verify_hm_opening(&com, msg, &r));
    }

    #[test]
    fn verify_hm_opening_rejects_tampered_a() {
        let (a, r) = seeded_keys(9);
        let msg = b"hello";
        let mut com = hm_commit(msg, &a, &r);
        com.a[1][5][0] ^= 1;
        assert!(!verify_hm_opening(&com, msg, &r));
    }

    #[test]
    fn verify_hm_opening_rejects_y_with_mhat() {
        let (a, r) = seeded_keys(8);
        let msg = b"hello";
        let mut com = hm_commit(msg, &a, &r);
        let mut data = r.as_flattened().to_vec();
        data.extend_from_slice(&message_hash(msg));
        com.y = tagged(&XMSS_TAGS.nonce, &data);
        assert!(!verify_hm_opening(&com, msg, &r));
    }

    #[test]
    fn xmss_tags_are_distinct_and_outside_the_other_sha256_domains() {
        let empty: [u8; 32] = Sha256::digest([]).into();
        let tags = [XMSS_TAGS.message, XMSS_TAGS.nonce, XMSS_TAGS.digest];
        for (i, t) in tags.iter().enumerate() {
            for u in &tags[i + 1..] {
                assert_ne!(t, u);
            }
            assert!(
                t[16] > crate::ts_xmss::hashing::TWEAK_TREE,
                "XMSS hash tweaks"
            );
            assert!(
                t[48..].iter().all(|&x| x == 0xFF),
                "XMSS tree prefix, HMAC pads"
            );
            assert_ne!(&t[..32], &empty, "first Fiat–Shamir input");
        }
    }

    #[test]
    fn com_digest_differs_across_messages() {
        let (a, r) = seeded_keys(10);
        let com1 = hm_commit(b"message one", &a, &r);
        let com2 = hm_commit(b"message two", &a, &r);
        assert_eq!(com1.y, com2.y, "y must be message-independent");
        assert_ne!(com1.b, com2.b);
        assert_ne!(com_digest(&com1), com_digest(&com2));
    }

    #[test]
    fn user_commit_opening_verified_with_verify_hm_opening() {
        use crate::User;

        let msg = b"hello world";
        let mut user = User::new(&mut StdRng::seed_from_u64(42));
        let com = user.commit(msg);
        let opening = user.opening();
        assert!(verify_hm_opening(&com, &opening.msg, &opening.r));
        assert_eq!(&opening.msg, msg);
    }
}
