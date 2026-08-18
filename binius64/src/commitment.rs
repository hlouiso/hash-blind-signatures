//! Halevi–Micali commitment over GF(2^128) with (n, s, k) = (128, 2, 6).
//! Field elements use little-endian polynomial-basis encoding.

use binius_field::BinaryField128bGhash;

use crate::hashes::blake3_256;

pub const N_FE: usize = 16;
pub const N_FE_WORDS: usize = N_FE / 8;
pub const N_Y: usize = 32;
pub const N_NONCE: usize = 6;
pub const N_DIGEST_WORDS: usize = N_Y / 8;
pub const N_LINES: usize = N_Y / N_FE;

pub type GhashElement = [u8; N_FE];

#[inline]
fn field_from_bytes(value: &GhashElement) -> BinaryField128bGhash {
    BinaryField128bGhash::new(u128::from_le_bytes(*value))
}

#[inline]
fn field_to_bytes(value: BinaryField128bGhash) -> GhashElement {
    u128::from(value).to_le_bytes()
}

#[inline]
pub fn ghash_mul(a: u128, b: u128) -> u128 {
    u128::from(BinaryField128bGhash::new(a) * BinaryField128bGhash::new(b))
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

pub fn com_digest(com: &HmCommitment) -> [u8; N_Y] {
    blake3_256(&com.to_bytes())
}

#[derive(Debug, Clone)]
pub struct CommitmentOpening {
    pub msg: Vec<u8>,
    pub r: [GhashElement; N_NONCE],
}

fn hash_r(r: &[GhashElement; N_NONCE]) -> [u8; N_Y] {
    let mut buf = [0u8; N_NONCE * N_FE];
    for (i, r_i) in r.iter().enumerate() {
        buf[i * N_FE..(i + 1) * N_FE].copy_from_slice(r_i);
    }
    blake3_256(&buf)
}

pub fn encode_digest(m_hat: &[u8; N_Y]) -> [GhashElement; N_LINES] {
    std::array::from_fn(|k| {
        m_hat[k * N_FE..(k + 1) * N_FE]
            .try_into()
            .expect("digest half has sixteen bytes")
    })
}

pub fn encode_message(msg: &[u8]) -> [GhashElement; N_LINES] {
    encode_digest(&blake3_256(msg))
}

pub fn hm_commit(
    msg: &[u8],
    a: &[[GhashElement; N_NONCE]; N_LINES],
    r: &[GhashElement; N_NONCE],
) -> HmCommitment {
    let m_hat = encode_message(msg);
    let mut b = [[0u8; N_FE]; N_LINES];

    for k in 0..N_LINES {
        let mut sum = BinaryField128bGhash::new(0);
        for i in 0..N_NONCE {
            sum += field_from_bytes(&a[k][i]) * field_from_bytes(&r[i]);
        }
        b[k] = field_to_bytes(field_from_bytes(&m_hat[k]) + sum);
    }

    HmCommitment {
        a: *a,
        b,
        y: hash_r(r),
    }
}

pub fn sample_commitment(
    rng: &mut impl rand::Rng,
    msg: &[u8],
) -> (HmCommitment, CommitmentOpening) {
    let mut a = [[[0u8; N_FE]; N_NONCE]; N_LINES];
    let mut r = [[0u8; N_FE]; N_NONCE];
    for r_i in &mut r {
        *r_i = sample_ghash(rng);
    }
    for line in &mut a {
        for a_i in line {
            *a_i = sample_ghash(rng);
        }
    }

    let com = hm_commit(msg, &a, &r);
    let opening = CommitmentOpening {
        msg: msg.to_vec(),
        r,
    };
    (com, opening)
}

pub fn verify_hm_opening(com: &HmCommitment, msg: &[u8], r: &[GhashElement; N_NONCE]) -> bool {
    if hash_r(r) != com.y {
        return false;
    }

    let m_hat = encode_message(msg);
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
        let mut hasher = blake3::Hasher::new();
        for r_i in &r {
            hasher.update(r_i);
        }
        hasher.update(&blake3_256(msg));
        com.y = *hasher.finalize().as_bytes();
        assert!(!verify_hm_opening(&com, msg, &r));
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
