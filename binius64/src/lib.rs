pub mod hashes;
pub mod wots;
pub mod xmss;

pub mod commitment;

pub mod gadgets;
pub mod gadgets_multi;
pub mod salted_zk;
pub mod setup;
pub mod setup_multi;

pub mod protocol;
pub mod protocol_multi;
pub mod serialize;

pub use setup::{
    BlindZkProver, BlindZkVerifier, ProverSetup, build_prover_setup, build_prover_setup_rate,
    build_prover_verifier, build_verifier, build_verifier_setup, build_verifier_setup_rate,
};

pub use commitment::{
    COMMITMENT_BYTES, CommitmentOpening, GhashElement, HmCommitment, N_DIGEST_WORDS, N_FE,
    N_FE_WORDS, N_LINES, N_NONCE, N_Y, com_digest, ghash_mul, hm_commit, sample_ghash,
    verify_hm_opening,
};

pub use protocol::{BlindSigError, BlindSignature, Signer, User, UserState, Verifier};

pub use protocol_multi::{BlindMultiSigError, BlindMultiSignature, MultiUser, MultiVerifier};
pub use setup_multi::{
    ProverSetupMulti, build_prover_setup_multi, build_prover_setup_multi_rate,
    build_verifier_setup_multi, build_verifier_setup_multi_rate, n_inout_multi,
};

pub use protocol::verifier::UnifiedVerifyError;

pub use wots::{
    LEN, MAX_STEPS, N, PK_SEED_BYTES, SK_SEED_BYTES, compute_wots_chain_ends,
    compute_wots_public_key, compute_wots_signature, derive_wots_secret_key,
    generate_wots_secret_key, wots_leaf,
};

pub use xmss::{
    KeyExhaustedError, SUBTREE_H, XMSS_H, XmssKeyPair, XmssSignError, XmssSignature, xmss_expand,
    xmss_verify,
};

pub use serialize::{
    SIGNER_KEY_BYTES, SIGNER_PUB_BYTES, SignerKey, XMSS_SIG_BYTES, read_blind_sig, read_commitment,
    read_signer_keys, read_signer_pub, read_user_state, read_xmss_sig, read_xmss_sigs,
    write_blind_sig, write_commitment, write_signer_keys, write_signer_pub, write_user_state,
    write_xmss_sig, write_xmss_sigs,
};

pub use hashes::{
    CHAIN_LENGTH, DIGEST_LEN, Digest, LOG_LIFETIME, MESSAGE_LEN, Message, N_HASH, PUBLIC_PARAM_LEN,
    PublicParam, RANDOMNESS_LEN, Randomness, TARGET_SUM, V, W, blake3_256,
};
