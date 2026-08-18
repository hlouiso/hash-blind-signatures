//! Canonical protocol encodings. Integer fields are little-endian; XMSS
//! signatures omit recomputable public-key data, and blind signatures contain
//! only the proof transcript.

use crate::commitment::{COMMITMENT_BYTES, CommitmentOpening, HmCommitment};
use crate::hashes::{Digest, LOG_LIFETIME, Message, RANDOMNESS_LEN, Randomness};
use crate::protocol::{BlindSignature, UserState};
use crate::wots::{LEN, PK_SEED_BYTES, SK_SEED_BYTES};
use crate::xmss::{N, XmssSignature, xmss_expand};

pub const SIGNER_KEY_BYTES: usize = SK_SEED_BYTES + 8;

pub const SIGNER_PUB_BYTES: usize = N;

#[derive(Debug, Clone)]
pub struct SignerKey {
    pub sk_seed: [u8; SK_SEED_BYTES],
    pub next_leaf: u64,
}

pub fn write_signer_keys(
    keys: &[SignerKey],
    pk_seed: &[u8; PK_SEED_BYTES],
    height: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(keys.len() * SIGNER_KEY_BYTES + PK_SEED_BYTES + 1);
    for k in keys {
        out.extend_from_slice(&k.sk_seed);
    }
    out.extend_from_slice(pk_seed);
    out.push(u8::try_from(height).expect("height fits a byte"));
    for k in keys {
        out.extend_from_slice(&k.next_leaf.to_le_bytes());
    }
    debug_assert_eq!(out.len(), keys.len() * SIGNER_KEY_BYTES + PK_SEED_BYTES + 1);
    out
}

pub fn read_signer_keys(buf: &[u8]) -> Option<(Vec<SignerKey>, [u8; PK_SEED_BYTES], usize)> {
    let n = signer_count(buf.len().checked_sub(1)?, SIGNER_KEY_BYTES)?;
    let (seeds, rest) = buf.split_at(n * SK_SEED_BYTES);
    let (pk_seed, rest) = rest.split_at(PK_SEED_BYTES);
    let (height, leaves) = rest.split_first()?;
    let height = usize::from(*height);
    if !(1..=LOG_LIFETIME).contains(&height) {
        return None;
    }

    let keys = (0..n)
        .map(|i| SignerKey {
            sk_seed: seeds[i * SK_SEED_BYTES..(i + 1) * SK_SEED_BYTES]
                .try_into()
                .expect("SK_SEED_BYTES"),
            next_leaf: u64::from_le_bytes(
                leaves[i * 8..(i + 1) * 8].try_into().expect("eight bytes"),
            ),
        })
        .collect();
    Some((keys, pk_seed.try_into().expect("PK_SEED_BYTES"), height))
}

pub fn write_signer_pub(roots: &[[u8; N]], pk_seed: &[u8; PK_SEED_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(roots.len() * SIGNER_PUB_BYTES + PK_SEED_BYTES);
    for root in roots {
        out.extend_from_slice(root);
    }
    out.extend_from_slice(pk_seed);
    out
}

pub fn read_signer_pub(buf: &[u8]) -> Option<(Vec<[u8; N]>, [u8; PK_SEED_BYTES])> {
    let n = signer_count(buf.len(), SIGNER_PUB_BYTES)?;
    let (root_bytes, pk_seed) = buf.split_at(n * N);
    let roots = root_bytes
        .chunks_exact(N)
        .map(|c| c.try_into().expect("N bytes"))
        .collect();
    Some((roots, pk_seed.try_into().expect("PK_SEED_BYTES")))
}

fn signer_count(len: usize, per: usize) -> Option<usize> {
    let body = len.checked_sub(PK_SEED_BYTES)?;
    if body == 0 || body % per != 0 {
        return None;
    }
    Some(body / per)
}

pub fn write_commitment(com: &HmCommitment) -> Vec<u8> {
    com.to_bytes().to_vec()
}

pub fn read_commitment(buf: &[u8]) -> Option<HmCommitment> {
    let bytes: &[u8; COMMITMENT_BYTES] = buf.try_into().ok()?;
    Some(HmCommitment::from_bytes(bytes))
}

pub fn write_user_state(state: &UserState) -> Vec<u8> {
    let msg = &state.opening.msg;
    let mut out = Vec::with_capacity(4 + msg.len() + COMMITMENT_BYTES + 6 * 16);
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(msg);
    out.extend_from_slice(&state.com.to_bytes());
    for r_i in &state.opening.r {
        out.extend_from_slice(r_i);
    }
    out
}

pub fn read_user_state(buf: &[u8]) -> Option<UserState> {
    let r_bytes = state_nonce_bytes();
    if buf.len() < 4 + COMMITMENT_BYTES + r_bytes {
        return None;
    }
    let msg_len = u32::from_le_bytes(buf[..4].try_into().ok()?) as usize;
    if buf.len() != 4 + msg_len + COMMITMENT_BYTES + r_bytes {
        return None;
    }
    let msg = buf[4..4 + msg_len].to_vec();
    let com_bytes: &[u8; COMMITMENT_BYTES] = buf[4 + msg_len..4 + msg_len + COMMITMENT_BYTES]
        .try_into()
        .ok()?;
    let r_start = 4 + msg_len + COMMITMENT_BYTES;
    let r = std::array::from_fn(|i| {
        buf[r_start + i * 16..r_start + (i + 1) * 16]
            .try_into()
            .expect("sixteen bytes")
    });
    Some(UserState {
        opening: CommitmentOpening { msg, r },
        com: HmCommitment::from_bytes(com_bytes),
    })
}

fn state_nonce_bytes() -> usize {
    crate::commitment::N_NONCE * crate::commitment::N_FE
}

pub const XMSS_SIG_BYTES: usize = 4 + RANDOMNESS_LEN + LEN * N + LOG_LIFETIME * N;

pub fn write_xmss_sig(sig: &XmssSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(XMSS_SIG_BYTES);
    out.extend_from_slice(&sig.epoch.to_le_bytes());
    out.extend_from_slice(&sig.randomness);
    for tip in &sig.chain_tips {
        out.extend_from_slice(tip);
    }
    for node in &sig.merkle_path {
        out.extend_from_slice(node);
    }

    debug_assert_eq!(out.len(), XMSS_SIG_BYTES);
    out
}

pub fn read_xmss_sig(
    buf: &[u8],
    pk_seed: &[u8; PK_SEED_BYTES],
    message: &Message,
) -> Option<XmssSignature> {
    if buf.len() != XMSS_SIG_BYTES {
        return None;
    }
    let (epoch_bytes, rest) = buf.split_at(4);
    let epoch = u32::from_le_bytes(epoch_bytes.try_into().ok()?);
    let (randomness, rest) = rest.split_at(RANDOMNESS_LEN);
    let randomness: Randomness = randomness.try_into().ok()?;
    let (tip_bytes, path_bytes) = rest.split_at(LEN * N);

    let digest_at = |bytes: &[u8], i: usize| -> Digest {
        bytes[i * N..(i + 1) * N].try_into().expect("N bytes")
    };
    let chain_tips: [Digest; LEN] = std::array::from_fn(|i| digest_at(tip_bytes, i));
    let merkle_path: [Digest; LOG_LIFETIME] = std::array::from_fn(|i| digest_at(path_bytes, i));

    xmss_expand(
        pk_seed,
        epoch,
        &randomness,
        chain_tips,
        merkle_path,
        message,
    )
}

pub fn write_xmss_sigs(sigs: &[XmssSignature]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sigs.len() * XMSS_SIG_BYTES);
    for sig in sigs {
        out.extend_from_slice(&write_xmss_sig(sig));
    }
    out
}

pub fn read_xmss_sigs(
    buf: &[u8],
    pk_seed: &[u8; PK_SEED_BYTES],
    message: &Message,
) -> Option<Vec<XmssSignature>> {
    if buf.is_empty() || buf.len() % XMSS_SIG_BYTES != 0 {
        return None;
    }
    buf.chunks_exact(XMSS_SIG_BYTES)
        .map(|c| read_xmss_sig(c, pk_seed, message))
        .collect()
}

pub fn write_blind_sig(sig: &BlindSignature) -> Vec<u8> {
    sig.proof.clone()
}

pub fn read_blind_sig(buf: &[u8]) -> BlindSignature {
    BlindSignature {
        proof: buf.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::com_digest;
    use crate::protocol::{Signer, User};
    use rand::prelude::*;
    use rand::rngs::StdRng;

    fn signed_fixture(seed: u64) -> (Signer, XmssSignature, [u8; 32]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut user = User::new(&mut rng);
        let com = user.commit(b"a document to be blindly signed");
        let mut signer = Signer::new(&mut rng, 8);
        let sig = signer.sign(&com).expect("sign failed");
        let d = com_digest(&com);
        (signer, sig, d)
    }

    #[test]
    fn xmss_sig_wire_size_is_minimal() {
        assert_eq!(XMSS_SIG_BYTES, 1212);
        let (_, sig, _) = signed_fixture(7);
        assert_eq!(write_xmss_sig(&sig).len(), XMSS_SIG_BYTES);
    }

    #[test]
    fn xmss_sig_roundtrip_reconstructs_every_derived_field() {
        let (signer, sig, d) = signed_fixture(42);
        let bytes = write_xmss_sig(&sig);
        let got = read_xmss_sig(&bytes, &signer.pk_seed(), &d).expect("read failed");

        assert_eq!(got, sig);
        assert_eq!(
            got.root,
            signer.public_key(),
            "root must match the public key"
        );
        assert_eq!(write_xmss_sig(&got), bytes);
    }

    #[test]
    fn expanded_signature_still_proves() {
        let mut rng = StdRng::seed_from_u64(9);
        let message = b"round-tripped through the wire format";
        let mut user = User::new(&mut rng);
        let com = user.commit(message);
        let mut signer = Signer::new(&mut rng, 8);
        let sig = signer.sign(&com).expect("sign failed");

        let bytes = write_xmss_sig(&sig);
        let parsed =
            read_xmss_sig(&bytes, &signer.pk_seed(), &com_digest(&com)).expect("read failed");

        let blind = user
            .prove(&parsed)
            .expect("prove from parsed signature failed");
        let verifier = crate::Verifier::new(signer.public_key(), signer.pk_seed());
        verifier
            .verify(&read_blind_sig(&write_blind_sig(&blind)), message)
            .expect("blind signature must verify");
    }

    #[test]
    fn read_rejects_wrong_length() {
        let (signer, sig, d) = signed_fixture(1);
        let bytes = write_xmss_sig(&sig);
        let pk_seed = signer.pk_seed();

        assert!(read_xmss_sig(&bytes[..bytes.len() - 1], &pk_seed, &d).is_none());
        let mut long = bytes.clone();
        long.push(0);
        assert!(
            read_xmss_sig(&long, &pk_seed, &d).is_none(),
            "trailing bytes must be rejected"
        );
    }

    #[test]
    fn read_rejects_wrong_message_and_wrong_seed() {
        let (signer, sig, d) = signed_fixture(2);
        let bytes = write_xmss_sig(&sig);

        assert!(read_xmss_sig(&bytes, &signer.pk_seed(), &[0xAAu8; 32]).is_none());

        let mut wrong_seed = signer.pk_seed();
        wrong_seed[0] ^= 1;
        assert!(read_xmss_sig(&bytes, &wrong_seed, &d).is_none());
    }

    fn dummy_keys(n: usize) -> (Vec<SignerKey>, [u8; PK_SEED_BYTES]) {
        let keys = (0..n)
            .map(|i| SignerKey {
                sk_seed: [i as u8; SK_SEED_BYTES],
                next_leaf: 7 * i as u64,
            })
            .collect();
        (keys, [0xC3u8; PK_SEED_BYTES])
    }

    #[test]
    fn one_signer_key_and_pubkey_are_57_and_32_bytes() {
        let (keys, pk_seed) = dummy_keys(1);
        assert_eq!(write_signer_keys(&keys, &pk_seed, 32).len(), 57);
        assert_eq!(write_signer_pub(&[[9u8; N]], &pk_seed).len(), 32);
    }

    #[test]
    fn signer_key_roundtrips_at_every_signer_count() {
        for n in [1usize, 2, 10] {
            let (keys, pk_seed) = dummy_keys(n);
            let bytes = write_signer_keys(&keys, &pk_seed, 32);
            let (got, got_seed, got_h) = read_signer_keys(&bytes).expect("read failed");
            assert_eq!(got_seed, pk_seed);
            assert_eq!(got_h, 32, "the height is recovered");
            assert_eq!(got.len(), n, "signer count is recovered from the length");
            for (a, b) in got.iter().zip(&keys) {
                assert_eq!(a.sk_seed, b.sk_seed);
                assert_eq!(a.next_leaf, b.next_leaf);
            }

            let roots: Vec<[u8; N]> = (0..n).map(|i| [i as u8 + 1; N]).collect();
            let pub_bytes = write_signer_pub(&roots, &pk_seed);
            let (got_roots, got_seed) = read_signer_pub(&pub_bytes).expect("read failed");
            assert_eq!(got_roots, roots);
            assert_eq!(got_seed, pk_seed);
        }
    }

    #[test]
    fn key_files_reject_lengths_that_name_no_signer_count() {
        let (keys, pk_seed) = dummy_keys(2);
        let bytes = write_signer_keys(&keys, &pk_seed, 32);
        assert!(read_signer_keys(&bytes[..bytes.len() - 1]).is_none());
        assert!(read_signer_keys(&[]).is_none());
        assert!(read_signer_keys(&pk_seed).is_none());

        let pub_bytes = write_signer_pub(&[[1u8; N], [2u8; N]], &pk_seed);
        assert!(read_signer_pub(&pub_bytes[..pub_bytes.len() - 1]).is_none());
        assert!(read_signer_pub(&pk_seed).is_none());
    }

    #[test]
    fn commitment_and_user_state_roundtrip() {
        let mut rng = StdRng::seed_from_u64(11);
        let mut user = User::new(&mut rng);
        let com = user.commit(b"a document to be blindly signed");

        let com_bytes = write_commitment(&com);
        assert_eq!(com_bytes.len(), crate::commitment::COMMITMENT_BYTES);
        assert_eq!(read_commitment(&com_bytes).expect("read failed"), com);
        assert!(read_commitment(&com_bytes[..255]).is_none());

        let state_bytes = write_user_state(user.state());
        let got = read_user_state(&state_bytes).expect("read failed");
        assert_eq!(got.com, com);
        assert_eq!(got.opening.msg, user.opening().msg);
        assert_eq!(got.opening.r, user.opening().r);
        assert!(read_user_state(&state_bytes[..state_bytes.len() - 1]).is_none());
        let mut long = state_bytes.clone();
        long.push(0);
        assert!(read_user_state(&long).is_none());
    }

    #[test]
    fn multi_signature_wire_form_roundtrips() {
        let (signer, sig, d) = signed_fixture(21);
        let bytes = write_xmss_sigs(std::slice::from_ref(&sig));
        assert_eq!(bytes.len(), XMSS_SIG_BYTES);

        let two = write_xmss_sigs(&[sig.clone(), sig.clone()]);
        let got = read_xmss_sigs(&two, &signer.pk_seed(), &d).expect("read failed");
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|g| g.root == sig.root));

        assert!(read_xmss_sigs(&two[..two.len() - 1], &signer.pk_seed(), &d).is_none());
        assert!(read_xmss_sigs(&[], &signer.pk_seed(), &d).is_none());
    }

    #[test]
    fn tampered_chain_value_breaks_the_root() {
        let (signer, sig, d) = signed_fixture(3);
        let mut bytes = write_xmss_sig(&sig);
        bytes[4 + RANDOMNESS_LEN] ^= 1;
        let got = read_xmss_sig(&bytes, &signer.pk_seed(), &d).expect("should still parse");
        assert_ne!(got.root, signer.public_key());
    }
}
