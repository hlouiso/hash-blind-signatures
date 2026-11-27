//! Target-sum WOTS+ compatible with the Binius64 circuit. Chain starts are
//! derived from sk_seed as the Longfellow implementation derives them
//! (`longfellow/src/xmss.cc`), so one seed gives one key in both; pk_seed is
//! the hash domain parameter.

use rand::Rng;

use crate::hashes::{
    CHAIN_LENGTH, DIGEST_LEN, Digest, PUBLIC_PARAM_LEN, PublicParam, V, iterate_hash,
    recover_public_key, wots_public_key_hash,
};
use crate::slh::native::hmac_sha256;

pub const N: usize = DIGEST_LEN;

pub use crate::hashes::CHAIN_LENGTH as CHAIN_LEN;

pub const MAX_STEPS: usize = CHAIN_LENGTH - 1;

pub const LEN: usize = V;

pub const PK_SEED_BYTES: usize = PUBLIC_PARAM_LEN;

pub const SK_SEED_BYTES: usize = 32;

/// Longfellow's label, shared so both implementations derive the same keys.
const WOTS_PRF_LABEL: &[u8] = b"blind-xmss-longfellow/wots/v1";

pub fn build_wots_domain_param(pk_seed: &[u8; PK_SEED_BYTES]) -> PublicParam {
    *pk_seed
}

pub fn generate_wots_secret_key(rng: &mut impl Rng) -> [Digest; LEN] {
    std::array::from_fn(|_| {
        let mut val = [0u8; N];
        rng.fill_bytes(&mut val);
        val
    })
}

/// The key of the chain-start PRF: HMAC-SHA-256(sk_seed, label).
pub fn derive_wots_prf_key(sk_seed: &[u8; SK_SEED_BYTES]) -> [u8; 32] {
    hmac_sha256(sk_seed, &[WOTS_PRF_LABEL])
}

/// Chain start i at `epoch`: HMAC-SHA-256(prf_key, pk_seed || epoch || i),
/// truncated, with the integers little-endian.
pub fn derive_wots_secret_key_with(
    prf_key: &[u8; 32],
    pk_seed: &[u8; PK_SEED_BYTES],
    epoch: u32,
) -> [Digest; LEN] {
    std::array::from_fn(|i| {
        let out = hmac_sha256(
            prf_key,
            &[pk_seed, &epoch.to_le_bytes(), &(i as u32).to_le_bytes()],
        );
        out[..N]
            .try_into()
            .expect("a digest is a prefix of the output")
    })
}

pub fn derive_wots_secret_key(
    sk_seed: &[u8; SK_SEED_BYTES],
    pk_seed: &[u8; PK_SEED_BYTES],
    epoch: u32,
) -> [Digest; LEN] {
    derive_wots_secret_key_with(&derive_wots_prf_key(sk_seed), pk_seed, epoch)
}

pub fn compute_wots_public_key(
    param: &PublicParam,
    epoch: u32,
    sk: &[Digest; LEN],
) -> [Digest; LEN] {
    std::array::from_fn(|i| iterate_hash(&sk[i], MAX_STEPS, param, epoch, i, 0))
}

pub fn compute_wots_signature(
    param: &PublicParam,
    epoch: u32,
    sk: &[Digest; LEN],
    encoding: &[u8; LEN],
) -> [Digest; LEN] {
    std::array::from_fn(|i| iterate_hash(&sk[i], encoding[i] as usize, param, epoch, i, 0))
}

pub fn compute_wots_chain_ends(
    param: &PublicParam,
    epoch: u32,
    chain_tips: &[Digest; LEN],
    encoding: &[u8; LEN],
) -> [Digest; LEN] {
    recover_public_key(chain_tips, encoding, epoch, param)
}

pub fn wots_leaf(param: &PublicParam, epoch: u32, chain_ends: &[Digest; LEN]) -> Digest {
    wots_public_key_hash(param, epoch, chain_ends)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::{MESSAGE_LEN, Message, find_randomness_for_wots_encoding, wots_encode};
    use rand::prelude::*;

    fn test_param() -> PublicParam {
        [0xBBu8; PK_SEED_BYTES]
    }

    fn test_message(byte: u8) -> Message {
        [byte; MESSAGE_LEN]
    }

    #[test]
    fn build_domain_param_is_the_seed() {
        let pk_seed = [0x01u8; PK_SEED_BYTES];
        assert_eq!(build_wots_domain_param(&pk_seed), pk_seed);
    }

    #[test]
    fn derived_secret_keys_are_seed_and_epoch_bound() {
        let seed = [7u8; SK_SEED_BYTES];
        let other = [8u8; SK_SEED_BYTES];
        let pk = [1u8; PK_SEED_BYTES];
        assert_eq!(
            derive_wots_secret_key(&seed, &pk, 3),
            derive_wots_secret_key(&seed, &pk, 3)
        );
        assert_ne!(
            derive_wots_secret_key(&seed, &pk, 3),
            derive_wots_secret_key(&seed, &pk, 4)
        );
        assert_ne!(
            derive_wots_secret_key(&seed, &pk, 3),
            derive_wots_secret_key(&other, &pk, 3)
        );
        assert_ne!(
            derive_wots_secret_key(&seed, &pk, 3),
            derive_wots_secret_key(&seed, &[2u8; PK_SEED_BYTES], 3)
        );
    }

    #[test]
    fn signing_then_walking_reaches_the_public_key() {
        let mut rng = StdRng::seed_from_u64(42);
        let param = test_param();
        let epoch = 7u32;
        let sk = generate_wots_secret_key(&mut rng);
        let public_key = compute_wots_public_key(&param, epoch, &sk);

        let message = test_message(0xCC);
        let (_randomness, encoding) =
            find_randomness_for_wots_encoding(&message, epoch, &param, &mut rng);
        let tips = compute_wots_signature(&param, epoch, &sk, &encoding);
        assert_eq!(
            compute_wots_chain_ends(&param, epoch, &tips, &encoding),
            public_key
        );
    }

    #[test]
    fn a_chain_at_the_last_digit_reveals_its_end() {
        let mut rng = StdRng::seed_from_u64(1);
        let param = test_param();
        let sk = generate_wots_secret_key(&mut rng);
        let encoding = [(CHAIN_LENGTH - 1) as u8; LEN];
        let tips = compute_wots_signature(&param, 0, &sk, &encoding);
        assert_eq!(compute_wots_chain_ends(&param, 0, &tips, &encoding), tips);
    }

    #[test]
    fn different_epochs_diverge() {
        let mut rng = StdRng::seed_from_u64(2024);
        let sk = generate_wots_secret_key(&mut rng);
        let param = test_param();
        assert_ne!(
            compute_wots_public_key(&param, 0, &sk),
            compute_wots_public_key(&param, 1, &sk),
        );
    }

    #[test]
    fn grinding_lands_on_the_target_sum() {
        let mut rng = StdRng::seed_from_u64(11);
        let param = test_param();
        let message = test_message(0x5A);
        let (randomness, encoding) =
            find_randomness_for_wots_encoding(&message, 5, &param, &mut rng);

        assert_eq!(
            encoding.iter().map(|&d| d as usize).sum::<usize>(),
            crate::hashes::TARGET_SUM
        );
        assert!(encoding.iter().all(|&d| (d as usize) < CHAIN_LENGTH));
        assert_eq!(
            wots_encode(&message, 5, &param, &randomness),
            Some(encoding)
        );
    }
}
