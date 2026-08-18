//! Stateful XMSS matching the Binius64 circuit. The circuit always verifies a
//! 32-level path; keys with real height h < 32 use seed-derived fixed siblings
//! above level h. A two-level fractal traversal materializes the top tree and
//! caches only the bottom subtree containing the current epoch.

use rand::{CryptoRng, Rng};
use rayon::prelude::*;

use binius_circuits::hash_based_sig::xmss::{
    XmssPublicKey, XmssSignature as BiXmssSignature, xmss_verify as upstream_verify,
};

use crate::hashes::{
    DIGEST_LEN, Digest, LOG_LIFETIME, Message, PublicParam, merkle_node, wots_encode,
};
use crate::wots::{
    LEN, PK_SEED_BYTES, SK_SEED_BYTES, build_wots_domain_param, compute_wots_chain_ends,
    compute_wots_public_key, compute_wots_signature, derive_wots_secret_key, wots_leaf,
};

pub const N: usize = DIGEST_LEN;

pub const XMSS_H: usize = 10;

pub const SUBTREE_H: usize = 16;

const UPPER_SIBLING_DOMAIN: &[u8] = b"blind-xmss-binius64/upper-siblings";

fn build_subtree(
    sk_seed: &[u8; SK_SEED_BYTES],
    param: &PublicParam,
    s: u32,
    subtree_h: usize,
) -> Vec<Vec<Digest>> {
    let width = 1usize << subtree_h;
    let base_epoch = (s as u64) << subtree_h;

    let leaves: Vec<Digest> = (0..width)
        .into_par_iter()
        .map(|j| {
            let epoch = (base_epoch + j as u64) as u32;
            let sk = derive_wots_secret_key(sk_seed, epoch);
            let public_key = compute_wots_public_key(param, epoch, &sk);
            wots_leaf(param, epoch, &public_key)
        })
        .collect();

    let mut levels: Vec<Vec<Digest>> = vec![leaves];
    for h in 1..=subtree_h {
        let prev = &levels[h - 1];
        let base_index = (s as u64) << (subtree_h - h);
        let level: Vec<Digest> = (0..1usize << (subtree_h - h))
            .into_par_iter()
            .map(|j| {
                let index = (base_index + j as u64) as u32;
                merkle_node(param, h, index, &prev[2 * j], &prev[2 * j + 1])
            })
            .collect();
        levels.push(level);
    }
    levels
}

fn build_top(
    param: &PublicParam,
    subtree_roots: Vec<Digest>,
    subtree_h: usize,
    top_h: usize,
) -> Vec<Vec<Digest>> {
    let mut levels: Vec<Vec<Digest>> = vec![subtree_roots];
    for r in 1..=top_h {
        let prev = &levels[r - 1];
        let level: Vec<Digest> = (0..1usize << (top_h - r))
            .into_par_iter()
            .map(|i| {
                merkle_node(
                    param,
                    subtree_h + r,
                    i as u32,
                    &prev[2 * i],
                    &prev[2 * i + 1],
                )
            })
            .collect();
        levels.push(level);
    }
    levels
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyExhaustedError {
    pub capacity: u64,
}

impl core::fmt::Display for KeyExhaustedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XMSS key exhausted: all {} leaves used", self.capacity)
    }
}

impl std::error::Error for KeyExhaustedError {}

#[derive(Debug)]
pub enum XmssSignError {
    KeyExhausted(KeyExhaustedError),
}

impl core::fmt::Display for XmssSignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyExhausted(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for XmssSignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyExhausted(e) => Some(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmssSignature {
    pub epoch: u32,
    pub public_param: PublicParam,
    pub randomness: crate::hashes::Randomness,
    pub chain_tips: [Digest; LEN],

    pub merkle_path: [Digest; LOG_LIFETIME],
    pub root: Digest,
}

impl XmssSignature {
    pub fn to_upstream(&self) -> BiXmssSignature {
        BiXmssSignature {
            randomness: self.randomness,
            chain_tips: self.chain_tips,
            merkle_path: self.merkle_path,
        }
    }

    pub fn public_key(&self) -> XmssPublicKey {
        XmssPublicKey {
            merkle_root: self.root,
            public_param: self.public_param,
        }
    }

    pub fn auth_path(&self) -> [Digest; LOG_LIFETIME] {
        self.merkle_path
    }
}

pub fn xmss_verify(root: &Digest, message: &Message, sig: &XmssSignature) -> bool {
    let public_key = XmssPublicKey {
        merkle_root: *root,
        public_param: sig.public_param,
    };
    upstream_verify(&public_key, message, &sig.to_upstream(), sig.epoch).is_ok()
}

pub fn climb(
    param: &PublicParam,
    leaf: &Digest,
    epoch: u32,
    merkle_path: &[Digest; LOG_LIFETIME],
) -> Digest {
    merkle_path
        .iter()
        .enumerate()
        .fold(*leaf, |current, (level, sibling)| {
            let (left, right) = if (epoch >> level) & 1 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            let parent_index = ((epoch as u64) >> (level + 1)) as u32;
            merkle_node(param, level + 1, parent_index, &left, &right)
        })
}

pub fn xmss_expand(
    pk_seed: &[u8; PK_SEED_BYTES],
    epoch: u32,
    randomness: &crate::hashes::Randomness,
    chain_tips: [Digest; LEN],
    merkle_path: [Digest; LOG_LIFETIME],
    message: &Message,
) -> Option<XmssSignature> {
    let param = build_wots_domain_param(pk_seed);
    let encoding = wots_encode(message, epoch, &param, randomness)?;
    let chain_ends = compute_wots_chain_ends(&param, epoch, &chain_tips, &encoding);
    let leaf = wots_leaf(&param, epoch, &chain_ends);
    let root = climb(&param, &leaf, epoch, &merkle_path);

    Some(XmssSignature {
        epoch,
        public_param: param,
        randomness: *randomness,
        chain_tips,
        merkle_path,
        root,
    })
}

pub struct XmssKeyPair {
    pub pk_seed: [u8; PK_SEED_BYTES],
    pub root: Digest,
    sk_seed: [u8; SK_SEED_BYTES],

    height: usize,

    subtree_h: usize,

    top: Vec<Vec<Digest>>,

    bottom: Option<(u32, Vec<Vec<Digest>>)>,

    upper: Vec<Digest>,
    next_leaf: u64,
}

impl XmssKeyPair {
    pub fn generate(rng: &mut impl Rng, pk_seed: &[u8; PK_SEED_BYTES]) -> Self {
        let mut sk_seed = [0u8; SK_SEED_BYTES];
        rng.fill_bytes(&mut sk_seed);
        Self::generate_from_seed(&sk_seed, pk_seed, XMSS_H)
    }

    pub fn generate_from_seed(
        sk_seed: &[u8; SK_SEED_BYTES],
        pk_seed: &[u8; PK_SEED_BYTES],
        height: usize,
    ) -> Self {
        Self::generate_from_seed_with_subtree_h(sk_seed, pk_seed, height, height.min(SUBTREE_H))
    }

    pub fn generate_from_seed_with_subtree_h(
        sk_seed: &[u8; SK_SEED_BYTES],
        pk_seed: &[u8; PK_SEED_BYTES],
        height: usize,
        subtree_h: usize,
    ) -> Self {
        assert!(
            (1..=LOG_LIFETIME).contains(&height),
            "XMSS height must be in 1..={LOG_LIFETIME}, got {height}",
        );
        assert!(
            (1..=height).contains(&subtree_h),
            "subtree height must be in 1..={height}, got {subtree_h}",
        );
        let param = build_wots_domain_param(pk_seed);
        let top_h = height - subtree_h;

        let subtree_roots: Vec<Digest> = (0..1u32 << top_h)
            .into_par_iter()
            .map(|s| build_subtree(sk_seed, &param, s, subtree_h)[subtree_h][0])
            .collect();

        let top = build_top(&param, subtree_roots, subtree_h, top_h);
        let upper = derive_upper_siblings(sk_seed, LOG_LIFETIME - height);
        let root = climb_upper(&param, &top[top_h][0], &upper, height);

        Self {
            pk_seed: *pk_seed,
            root,
            sk_seed: *sk_seed,
            height,
            subtree_h,
            top,
            bottom: None,
            upper,
            next_leaf: 0,
        }
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn capacity(&self) -> u64 {
        1u64 << self.height
    }

    pub fn sign(
        &mut self,
        rng: &mut impl CryptoRng,
        message: &Message,
    ) -> Result<XmssSignature, XmssSignError> {
        if self.next_leaf >= self.capacity() {
            return Err(XmssSignError::KeyExhausted(KeyExhaustedError {
                capacity: self.capacity(),
            }));
        }
        let epoch = self.next_leaf as u32;
        self.next_leaf += 1;

        let param = build_wots_domain_param(&self.pk_seed);
        let (randomness, encoding) =
            crate::hashes::find_randomness_for_wots_encoding(message, epoch, &param, rng);

        let sk = derive_wots_secret_key(&self.sk_seed, epoch);
        let chain_tips = compute_wots_signature(&param, epoch, &sk, &encoding);
        let merkle_path = self.merkle_path(epoch);

        let sig = XmssSignature {
            epoch,
            public_param: param,
            randomness,
            chain_tips,
            merkle_path,
            root: self.root,
        };
        debug_assert!(
            xmss_verify(&self.root, message, &sig),
            "a freshly signed message must verify at epoch {epoch}",
        );
        Ok(sig)
    }

    fn merkle_path(&mut self, epoch: u32) -> [Digest; LOG_LIFETIME] {
        let s = (epoch as u64 >> self.subtree_h) as u32;
        if self.bottom.as_ref().map(|(cached, _)| *cached) != Some(s) {
            let param = build_wots_domain_param(&self.pk_seed);
            let built = build_subtree(&self.sk_seed, &param, s, self.subtree_h);
            self.bottom = Some((s, built));
        }
        let bottom = &self.bottom.as_ref().expect("just populated").1;

        let mut path = [[0u8; N]; LOG_LIFETIME];
        let mut idx = epoch as u64;
        for (h, slot) in path.iter_mut().take(self.subtree_h).enumerate() {
            let base = (s as u64) << (self.subtree_h - h);
            *slot = bottom[h][((idx ^ 1) - base) as usize];
            idx >>= 1;
        }

        for r in 0..self.height - self.subtree_h {
            path[self.subtree_h + r] = self.top[r][(idx ^ 1) as usize];
            idx >>= 1;
        }
        path[self.height..].copy_from_slice(&self.upper);
        path
    }

    pub fn public_key(&self) -> Digest {
        self.root
    }

    pub fn next_leaf(&self) -> u64 {
        self.next_leaf
    }

    pub fn set_next_leaf(&mut self, next_leaf: u64) {
        self.next_leaf = next_leaf;
    }

    pub fn remaining(&self) -> u64 {
        self.capacity() - self.next_leaf
    }
}

fn derive_upper_siblings(sk_seed: &[u8; SK_SEED_BYTES], levels: usize) -> Vec<Digest> {
    let mut hasher = blake3::Hasher::new_keyed(sk_seed);
    hasher.update(UPPER_SIBLING_DOMAIN);
    let mut xof = hasher.finalize_xof();
    (0..levels)
        .map(|_| {
            let mut node = [0u8; N];
            xof.fill(&mut node);
            node
        })
        .collect()
}

fn climb_upper(
    param: &PublicParam,
    subtree_root: &Digest,
    upper: &[Digest],
    height: usize,
) -> Digest {
    upper
        .iter()
        .enumerate()
        .fold(*subtree_root, |current, (i, sibling)| {
            merkle_node(param, height + i + 1, 0, &current, sibling)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::MESSAGE_LEN;
    use rand::prelude::*;

    const TEST_H: usize = 8;

    fn keypair_at(seed: u64, height: usize) -> (XmssKeyPair, StdRng) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut pk_seed = [0u8; PK_SEED_BYTES];
        rng.fill_bytes(&mut pk_seed);
        let mut sk_seed = [0u8; SK_SEED_BYTES];
        rng.fill_bytes(&mut sk_seed);
        (
            XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, height),
            rng,
        )
    }

    fn keypair(seed: u64) -> (XmssKeyPair, StdRng) {
        keypair_at(seed, TEST_H)
    }

    fn message(byte: u8) -> Message {
        [byte; MESSAGE_LEN]
    }

    #[test]
    fn a_signature_verifies_under_the_published_root() {
        let (mut kp, mut rng) = keypair(42);
        let msg = message(0xAA);
        let sig = kp.sign(&mut rng, &msg).expect("sign failed");

        assert_eq!(sig.epoch, 0);
        assert_eq!(sig.root, kp.public_key());
        assert!(xmss_verify(&kp.root, &msg, &sig));
        assert!(!xmss_verify(&kp.root, &message(0xAB), &sig));
    }

    #[test]
    fn the_epoch_advances_and_the_root_holds() {
        let (mut kp, mut rng) = keypair(7);
        assert_eq!(kp.remaining(), 1 << TEST_H);

        let first = kp.sign(&mut rng, &message(0x11)).expect("sign failed");
        let second = kp.sign(&mut rng, &message(0x22)).expect("sign failed");

        assert_eq!((first.epoch, second.epoch), (0, 1));
        assert_eq!(first.root, second.root);
        assert_eq!(kp.remaining(), (1 << TEST_H) - 2);
        assert!(xmss_verify(&kp.root, &message(0x22), &second));
    }

    #[test]
    fn a_signature_does_not_move_to_a_neighbouring_epoch() {
        let (mut kp, mut rng) = keypair(3);
        let msg = message(0x5C);
        let mut sig = kp.sign(&mut rng, &msg).expect("sign failed");
        sig.epoch += 1;
        assert!(!xmss_verify(&kp.root, &msg, &sig));
    }

    #[test]
    fn every_epoch_of_the_tree_reaches_the_root() {
        let (mut kp, mut rng) = keypair(9);
        for epoch in [0u64, 1, (1 << TEST_H) - 1] {
            kp.set_next_leaf(epoch);
            let msg = message(epoch as u8);
            let sig = kp.sign(&mut rng, &msg).expect("sign failed");
            assert_eq!(u64::from(sig.epoch), epoch);
            assert!(
                xmss_verify(&kp.root, &msg, &sig),
                "epoch {epoch} must verify"
            );
        }
    }

    #[test]
    fn the_traversal_agrees_with_a_materialized_tree() {
        for (height, subtree_h) in (1usize..=8).flat_map(|h| (1..=h).map(move |sub| (h, sub))) {
            let sk_seed = [0x2Au8; SK_SEED_BYTES];
            let pk_seed = [0x3Bu8; PK_SEED_BYTES];
            let param = build_wots_domain_param(&pk_seed);

            let mut flat: Vec<Vec<Digest>> = vec![
                (0..1u32 << height)
                    .map(|epoch| {
                        let sk = derive_wots_secret_key(&sk_seed, epoch);
                        let pk = compute_wots_public_key(&param, epoch, &sk);
                        wots_leaf(&param, epoch, &pk)
                    })
                    .collect(),
            ];
            for h in 1..=height {
                let prev = &flat[h - 1];
                let level = (0..1usize << (height - h))
                    .map(|i| merkle_node(&param, h, i as u32, &prev[2 * i], &prev[2 * i + 1]))
                    .collect();
                flat.push(level);
            }

            let mut kp = XmssKeyPair::generate_from_seed_with_subtree_h(
                &sk_seed, &pk_seed, height, subtree_h,
            );
            let label = format!("h={height} sub={subtree_h}");
            assert_eq!(
                kp.top[height - subtree_h][0],
                flat[height][0],
                "{label}: root"
            );

            for epoch in 0..1u32 << height {
                let path = kp.merkle_path(epoch);
                let mut idx = epoch as usize;
                for h in 0..height {
                    assert_eq!(
                        path[h],
                        flat[h][idx ^ 1],
                        "{label}: epoch {epoch}, level {h} sibling",
                    );
                    idx >>= 1;
                }

                let leaf = flat[0][epoch as usize];
                assert_eq!(
                    climb(&param, &leaf, epoch, &path),
                    kp.root,
                    "{label}: climb"
                );
            }
        }
    }

    #[test]
    fn the_subtree_cache_survives_epochs_out_of_order() {
        let sk_seed = [0x77u8; SK_SEED_BYTES];
        let pk_seed = [0x88u8; PK_SEED_BYTES];
        let build = || XmssKeyPair::generate_from_seed_with_subtree_h(&sk_seed, &pk_seed, 8, 3);

        let mut kp = build();
        let ordered: Vec<_> = (0..1u32 << 8).map(|e| kp.merkle_path(e)).collect();

        let mut fresh = build();
        for epoch in [255u32, 0, 128, 1, 129, 64, 255, 3] {
            assert_eq!(
                fresh.merkle_path(epoch),
                ordered[epoch as usize],
                "epoch {epoch} must not depend on which subtree was cached",
            );
        }
    }

    #[test]
    fn the_key_is_a_function_of_its_seed() {
        let sk_seed = [5u8; SK_SEED_BYTES];
        let pk_seed = [6u8; PK_SEED_BYTES];
        let a = XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, TEST_H);
        let b = XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, TEST_H);
        assert_eq!(a.root, b.root);

        let mut other_seed = sk_seed;
        other_seed[0] ^= 1;
        assert_ne!(
            XmssKeyPair::generate_from_seed(&other_seed, &pk_seed, TEST_H).root,
            a.root
        );
    }

    #[test]
    fn the_key_is_exhausted_after_its_last_leaf() {
        let (mut kp, mut rng) = keypair(1);
        kp.set_next_leaf(1 << TEST_H);
        assert_eq!(kp.remaining(), 0);
        assert!(matches!(
            kp.sign(&mut rng, &message(0)),
            Err(XmssSignError::KeyExhausted(_))
        ));
    }

    #[test]
    fn expanding_the_wire_fields_recovers_the_signature() {
        let (mut kp, mut rng) = keypair(21);
        let msg = message(0x3E);
        let sig = kp.sign(&mut rng, &msg).expect("sign failed");

        let got = xmss_expand(
            &kp.pk_seed,
            sig.epoch,
            &sig.randomness,
            sig.chain_tips,
            sig.merkle_path,
            &msg,
        )
        .expect("expand failed");
        assert_eq!(got, sig);
        assert_eq!(got.root, kp.public_key());

        assert!(
            xmss_expand(
                &kp.pk_seed,
                sig.epoch,
                &sig.randomness,
                sig.chain_tips,
                sig.merkle_path,
                &message(0x3F),
            )
            .is_none()
        );
    }
}
