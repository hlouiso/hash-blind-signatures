pub fn blake3_256(msg: &[u8]) -> [u8; 32] {
    blake3::hash(msg).into()
}

pub const N_HASH: usize = 32;

const _: () = assert!(N_HASH == MESSAGE_LEN);

pub use binius_circuits::hash_based_sig::{
    CHAIN_LENGTH, DIGEST_LEN, DIGEST_WIRES, Digest, LOG_LIFETIME, MESSAGE_LEN, MESSAGE_WIRES,
    Message, NUM_CHAIN_HASHES, PUBLIC_PARAM_LEN, PUBLIC_PARAM_WIRES, PublicParam, RANDOMNESS_LEN,
    RANDOMNESS_WIRES, Randomness, TARGET_SUM, V, W,
    hashing::{
        TWEAK_TYPE_CHAIN, TWEAK_TYPE_ENCODING, TWEAK_TYPE_MERKLE, TWEAK_TYPE_WOTS_PK, make_tweak,
        tweak_hash,
    },
    wots::{
        chain_step, find_randomness_for_wots_encoding, iterate_hash, recover_public_key,
        wots_encode, wots_public_key_hash,
    },
    xmss::merkle_node,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_256_matches_direct() {
        let msg = b"hello commitment";
        assert_eq!(blake3_256(msg), *blake3::hash(msg).as_bytes());
    }

    #[test]
    fn parameters_are_the_reference_scheme() {
        assert_eq!(
            (DIGEST_LEN, PUBLIC_PARAM_LEN, RANDOMNESS_LEN, MESSAGE_LEN),
            (16, 16, 24, 32)
        );
        assert_eq!((V, W, CHAIN_LENGTH, TARGET_SUM), (42, 3, 8, 195));
        assert_eq!(LOG_LIFETIME, 32);
        assert_eq!(NUM_CHAIN_HASHES, V * (CHAIN_LENGTH - 1) - TARGET_SUM);
    }
}
