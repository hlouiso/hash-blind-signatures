use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::commitment::{HmCommitment, com_digest};
use crate::hashes::{Digest, PublicParam};
use crate::wots::{PK_SEED_BYTES, SK_SEED_BYTES, build_wots_domain_param};
use crate::xmss::{XmssKeyPair, XmssSignError, XmssSignature};

const NONCE_RNG_DOMAIN: &[u8] = b"blind-xmss-binius64/nonce-rng";

pub struct Signer {
    pub(crate) rng: StdRng,
    pub(crate) kp: XmssKeyPair,
    sk_seed: [u8; SK_SEED_BYTES],
}

impl Signer {
    pub fn new(rng: &mut impl Rng, height: usize) -> Self {
        let mut pk_seed = [0u8; PK_SEED_BYTES];
        rng.fill_bytes(&mut pk_seed);
        Self::with_pk_seed(rng, &pk_seed, height)
    }

    pub fn with_pk_seed(rng: &mut impl Rng, pk_seed: &[u8; PK_SEED_BYTES], height: usize) -> Self {
        let mut sk_seed = [0u8; SK_SEED_BYTES];
        rng.fill_bytes(&mut sk_seed);
        Self::from_key(&sk_seed, pk_seed, 0, height)
    }

    pub fn from_key(
        sk_seed: &[u8; SK_SEED_BYTES],
        pk_seed: &[u8; PK_SEED_BYTES],
        next_leaf: u64,
        height: usize,
    ) -> Self {
        let mut kp = XmssKeyPair::generate_from_seed(sk_seed, pk_seed, height);
        kp.set_next_leaf(next_leaf);

        let mut hasher = blake3::Hasher::new_keyed(sk_seed);
        hasher.update(NONCE_RNG_DOMAIN);
        let rng = StdRng::from_seed(*hasher.finalize().as_bytes());

        Signer {
            rng,
            kp,
            sk_seed: *sk_seed,
        }
    }

    pub fn sign(&mut self, com: &HmCommitment) -> Result<XmssSignature, XmssSignError> {
        let d = com_digest(com);
        self.kp.sign(&mut self.rng, &d)
    }

    pub fn public_key(&self) -> Digest {
        self.kp.public_key()
    }

    pub fn pk_seed(&self) -> [u8; PK_SEED_BYTES] {
        self.kp.pk_seed
    }

    pub fn sk_seed(&self) -> [u8; SK_SEED_BYTES] {
        self.sk_seed
    }

    pub fn next_leaf(&self) -> u64 {
        self.kp.next_leaf()
    }

    pub fn height(&self) -> usize {
        self.kp.height()
    }

    pub fn domain_param(&self) -> PublicParam {
        build_wots_domain_param(&self.kp.pk_seed)
    }

    pub fn remaining(&self) -> u64 {
        self.kp.remaining()
    }
}
