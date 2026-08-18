//! The user commits, the signer XMSS-signs the commitment digest, and the user
//! proves knowledge of both the opening and signature. The proof is the blind
//! signature; the commitment and leaf index are not published.

pub mod signer;
pub mod user;
pub mod verifier;

pub use signer::Signer;
pub use user::User;
pub use user::UserState;
pub use verifier::Verifier;

pub(crate) const FS_NONCE_BYTES: usize = 32;

pub(crate) const PROOF_LABEL: &[u8] = b"blind-xmss-binius64-v6-salted-ghash";

pub struct BlindSignature {
    pub proof: Vec<u8>,
}

#[derive(Debug)]
pub enum BlindSigError {
    Proof(verifier::UnifiedVerifyError),
    Prover(anyhow::Error),
}

impl core::fmt::Display for BlindSigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proof(e) => write!(f, "proof verification failed: {e}"),
            Self::Prover(e) => write!(f, "proof generation failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{CommitmentOpening, HmCommitment, verify_hm_opening};
    use crate::wots::PK_SEED_BYTES;
    use crate::xmss::XmssKeyPair;
    use rand::prelude::*;
    use rand::rngs::StdRng;

    const TEST_H: usize = 8;

    fn make_xmss_keypair(rng: &mut StdRng) -> XmssKeyPair {
        let mut pk_seed = [0u8; PK_SEED_BYTES];
        rng.fill_bytes(&mut pk_seed);
        let mut sk_seed = [0u8; crate::wots::SK_SEED_BYTES];
        rng.fill_bytes(&mut sk_seed);
        XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, TEST_H)
    }

    fn signer_response(kp: &mut XmssKeyPair, com: &HmCommitment) -> crate::xmss::XmssSignature {
        let mut rng = StdRng::seed_from_u64(42);
        let d = crate::commitment::com_digest(com);
        kp.sign(&mut rng, &d).expect("sign failed")
    }

    #[test]
    fn blind_signature_full_roundtrip() {
        let message = b"my secret message";
        let mut user = User::new(&mut StdRng::seed_from_u64(42));
        let com = user.commit(message);

        let mut kp = make_xmss_keypair(&mut StdRng::seed_from_u64(123));
        let xmss_signature = signer_response(&mut kp, &com);
        let blind_sig = user.prove(&xmss_signature).expect("user_prove failed");

        let verifier = Verifier::new(kp.root, kp.pk_seed);
        verifier
            .verify(&blind_sig, message)
            .expect("full blind signature must verify");

        let opening = user.opening();
        assert!(verify_hm_opening(&com, &opening.msg, &opening.r));
    }

    #[test]
    fn commitment_opening_rejects_wrong_message() {
        let message = b"correct message";
        let mut user = User::new(&mut StdRng::seed_from_u64(42));
        let com = user.commit(message);

        let mut kp = make_xmss_keypair(&mut StdRng::seed_from_u64(123));
        let xmss_signature = signer_response(&mut kp, &com);
        let _blind_sig = user.prove(&xmss_signature).expect("user_prove failed");

        let r = user.opening().r;
        let wrong = CommitmentOpening {
            msg: b"wrong message".to_vec(),
            r,
        };
        assert!(!verify_hm_opening(&com, &wrong.msg, &wrong.r));
    }
}
