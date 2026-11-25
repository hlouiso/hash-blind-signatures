//! File encodings of the stateless (SLH-DSA) blind signature, for the CLI.
//!
//! Every file starts with an 8-byte magic, so a reader tells a stateless
//! artefact from a stateful (XMSS) one of `crate::serialize`, which carries
//! no magic. Key and signature files then name the parameter set in one
//! byte and hold one record per signer:
//!
//! - signer key: magic || set || n × (SK.seed || SK.prf || PK.seed || PK.root)
//! - public key: magic || set || n × (PK.seed || PK.root)
//! - signatures: magic || set || n × the FIPS 205 encoding
//! - user state: magic || m_hat || enc(com) || r_0 .. r_5
//!
//! Unlike an XMSS key, an SLH-DSA key holds no state: signing never rewrites it.

use super::native::{Node, SlhKey, SlhSignature};
use super::params::{N, SLH_DSA_SHA2_128_24, SlhParams};
use super::protocol::{SlhPublicKey, SlhUserState};
use crate::commitment::{COMMITMENT_BYTES, HmCommitment, N_FE, N_NONCE, N_Y};

pub const SLH_KEY_MAGIC: [u8; 8] = *b"HBS-SLHK";
pub const SLH_PUB_MAGIC: [u8; 8] = *b"HBS-SLHP";
pub const SLH_SIGS_MAGIC: [u8; 8] = *b"HBS-SLHS";
pub const SLH_STATE_MAGIC: [u8; 8] = *b"HBS-SLHU";

/// Parameter sets a file can name, by their one-byte identifier.
const SETS: [(u8, SlhParams); 1] = [(1, SLH_DSA_SHA2_128_24)];

fn set_id(p: &SlhParams) -> u8 {
    SETS.iter()
        .find(|(_, q)| q == p)
        .map(|(id, _)| *id)
        .expect("parameter set without a file identifier")
}

fn set_by_id(id: u8) -> Option<SlhParams> {
    SETS.iter().find(|(i, _)| *i == id).map(|(_, p)| *p)
}

/// The FIPS 205 secret key: everything the signer needs to rebuild its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhSecretKey {
    pub sk_seed: Node,
    pub sk_prf: Node,
    pub pk_seed: Node,
    pub pk_root: Node,
}

impl SlhSecretKey {
    pub fn of(key: &SlhKey) -> Self {
        Self {
            sk_seed: key.sk_seed,
            sk_prf: key.sk_prf,
            pk_seed: *key.pk_seed(),
            pk_root: key.pk_root,
        }
    }

    pub fn public_key(&self) -> SlhPublicKey {
        SlhPublicKey {
            pk_seed: self.pk_seed,
            pk_root: self.pk_root,
        }
    }
}

pub fn has_magic(buf: &[u8], magic: &[u8; 8]) -> bool {
    buf.starts_with(magic)
}

fn node_at(b: &[u8], i: usize) -> Node {
    b[i * N..(i + 1) * N].try_into().expect("N bytes")
}

/// The parameter set and the records of a keyed file, each `per(p)` bytes.
fn records<'a>(
    buf: &'a [u8],
    magic: &[u8; 8],
    per: impl Fn(&SlhParams) -> usize,
) -> Option<(SlhParams, std::slice::ChunksExact<'a, u8>)> {
    let rest = buf.strip_prefix(magic)?;
    let (&id, body) = rest.split_first()?;
    let p = set_by_id(id)?;
    let per = per(&p);
    if body.is_empty() || body.len() % per != 0 {
        return None;
    }
    Some((p, body.chunks_exact(per)))
}

fn header(magic: &[u8; 8], p: &SlhParams, body: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + body);
    out.extend_from_slice(magic);
    out.push(set_id(p));
    out
}

pub fn write_slh_keys(p: &SlhParams, keys: &[SlhSecretKey]) -> Vec<u8> {
    let mut out = header(&SLH_KEY_MAGIC, p, keys.len() * 4 * N);
    for k in keys {
        for node in [&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root] {
            out.extend_from_slice(node);
        }
    }
    out
}

pub fn read_slh_keys(buf: &[u8]) -> Option<(SlhParams, Vec<SlhSecretKey>)> {
    let (p, recs) = records(buf, &SLH_KEY_MAGIC, |_| 4 * N)?;
    let keys = recs
        .map(|r| SlhSecretKey {
            sk_seed: node_at(r, 0),
            sk_prf: node_at(r, 1),
            pk_seed: node_at(r, 2),
            pk_root: node_at(r, 3),
        })
        .collect();
    Some((p, keys))
}

pub fn write_slh_pub(p: &SlhParams, pks: &[SlhPublicKey]) -> Vec<u8> {
    let mut out = header(&SLH_PUB_MAGIC, p, pks.len() * p.pk_bytes());
    for pk in pks {
        out.extend_from_slice(&pk.pk_seed);
        out.extend_from_slice(&pk.pk_root);
    }
    out
}

pub fn read_slh_pub(buf: &[u8]) -> Option<(SlhParams, Vec<SlhPublicKey>)> {
    let (p, recs) = records(buf, &SLH_PUB_MAGIC, |p| p.pk_bytes())?;
    let pks = recs
        .map(|r| SlhPublicKey {
            pk_seed: node_at(r, 0),
            pk_root: node_at(r, 1),
        })
        .collect();
    Some((p, pks))
}

pub fn write_slh_sigs(p: &SlhParams, sigs: &[SlhSignature]) -> Vec<u8> {
    let mut out = header(&SLH_SIGS_MAGIC, p, sigs.len() * p.sig_bytes());
    for s in sigs {
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), p.sig_bytes(), "signature of another parameter set");
        out.extend_from_slice(&bytes);
    }
    out
}

pub fn read_slh_sigs(buf: &[u8]) -> Option<(SlhParams, Vec<SlhSignature>)> {
    let (p, recs) = records(buf, &SLH_SIGS_MAGIC, |p| p.sig_bytes())?;
    let sigs = recs
        .map(|r| SlhSignature::from_bytes(&p, r))
        .collect::<Option<Vec<_>>>()?;
    Some((p, sigs))
}

const STATE_BYTES: usize = 8 + N_Y + COMMITMENT_BYTES + N_NONCE * N_FE;

pub fn write_slh_user_state(s: &SlhUserState) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATE_BYTES);
    out.extend_from_slice(&SLH_STATE_MAGIC);
    out.extend_from_slice(&s.digest);
    out.extend_from_slice(&s.com.to_bytes());
    for r_i in &s.r {
        out.extend_from_slice(r_i);
    }
    debug_assert_eq!(out.len(), STATE_BYTES);
    out
}

pub fn read_slh_user_state(buf: &[u8]) -> Option<SlhUserState> {
    if buf.len() != STATE_BYTES {
        return None;
    }
    let rest = buf.strip_prefix(&SLH_STATE_MAGIC)?;
    let (digest, rest) = rest.split_at(N_Y);
    let (com, r) = rest.split_at(COMMITMENT_BYTES);
    Some(SlhUserState {
        digest: digest.try_into().ok()?,
        com: HmCommitment::from_bytes(com.try_into().ok()?),
        r: std::array::from_fn(|i| r[i * N_FE..(i + 1) * N_FE].try_into().expect("N_FE bytes")),
    })
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::slh::protocol::slh_commit;

    fn node(rng: &mut impl Rng) -> Node {
        let mut n = [0u8; N];
        rng.fill_bytes(&mut n);
        n
    }

    #[test]
    fn round_trips_and_rejects_foreign_bytes() {
        let mut rng = StdRng::seed_from_u64(9);
        let p = SLH_DSA_SHA2_128_24;
        let keys: Vec<SlhSecretKey> = (0..3)
            .map(|_| SlhSecretKey {
                sk_seed: node(&mut rng),
                sk_prf: node(&mut rng),
                pk_seed: node(&mut rng),
                pk_root: node(&mut rng),
            })
            .collect();
        let kb = write_slh_keys(&p, &keys);
        assert_eq!(read_slh_keys(&kb), Some((p, keys.clone())));
        let pks: Vec<SlhPublicKey> = keys.iter().map(SlhSecretKey::public_key).collect();
        let pb = write_slh_pub(&p, &pks);
        assert_eq!(pb.len(), 9 + 3 * 32);
        assert_eq!(read_slh_pub(&pb), Some((p, pks)));

        // Wrong magic, unknown set, truncated record, empty body.
        assert!(read_slh_pub(&kb).is_none());
        let mut bad = pb.clone();
        bad[8] = 0xEE;
        assert!(read_slh_pub(&bad).is_none());
        assert!(read_slh_pub(&pb[..pb.len() - 1]).is_none());
        assert!(read_slh_pub(&pb[..9]).is_none());

        let state = slh_commit(&mut rng, b"document");
        let sb = write_slh_user_state(&state);
        assert_eq!(read_slh_user_state(&sb), Some(state));
        assert!(read_slh_user_state(&sb[..sb.len() - 1]).is_none());

        let toy = SlhSignature::from_bytes(&p, &vec![7u8; p.sig_bytes()]).unwrap();
        let sigb = write_slh_sigs(&p, &[toy.clone(), toy.clone()]);
        let (q, sigs) = read_slh_sigs(&sigb).unwrap();
        assert_eq!(q, p);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[1].to_bytes(), toy.to_bytes());
    }
}
