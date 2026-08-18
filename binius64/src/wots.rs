//! Target-sum WOTS+ compatible with the Binius64 circuit. Chain starts are
//! derived by a keyed XOF from sk_seed and epoch; pk_seed is the hash domain
//! parameter.

use rand::Rng;

use crate::hashes::{
    CHAIN_LENGTH, DIGEST_LEN, Digest, PUBLIC_PARAM_LEN, PublicParam, V, iterate_hash,
    recover_public_key, wots_public_key_hash,
};

pub const N: usize = DIGEST_LEN;

pub use crate::hashes::CHAIN_LENGTH as CHAIN_LEN;

pub const MAX_STEPS: usize = CHAIN_LENGTH - 1;

pub const LEN: usize = V;

pub const PK_SEED_BYTES: usize = PUBLIC_PARAM_LEN;

pub const SK_SEED_BYTES: usize = 32;

const WOTS_SK_DOMAIN: &[u8] = b"blind-xmss-binius64/wots-sk";

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

pub fn derive_wots_secret_key(sk_seed: &[u8; SK_SEED_BYTES], epoch: u32) -> [Digest; LEN] {
    let mut hasher = blake3::Hasher::new_keyed(sk_seed);
    hasher.update(WOTS_SK_DOMAIN);
    hasher.update(&epoch.to_be_bytes());
    let mut xof = hasher.finalize_xof();
    std::array::from_fn(|_| {
        let mut val = [0u8; N];
        xof.fill(&mut val);
        val
    })
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
        assert_eq!(
            derive_wots_secret_key(&seed, 3),
            derive_wots_secret_key(&seed, 3)
        );
        assert_ne!(
            derive_wots_secret_key(&seed, 3),
            derive_wots_secret_key(&seed, 4)
        );
        assert_ne!(
            derive_wots_secret_key(&seed, 3),
            derive_wots_secret_key(&other, 3)
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
