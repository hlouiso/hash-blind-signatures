//! Aggregate variant in which all signers certify one commitment at the same
//! leaf index and the user proves all XMSS verifications in one proof.

pub mod user;
pub mod verifier;

pub use user::MultiUser;
pub use verifier::MultiVerifier;

pub(crate) const PROOF_LABEL_MULTI: &[u8] = b"blind-xmss-binius64-multisig-v6-salted-ghash";

#[derive(Debug, Clone)]
pub struct BlindMultiSignature {
    pub proof: Vec<u8>,
}

#[derive(Debug)]
pub enum BlindMultiSigError {
    Proof(crate::protocol::verifier::UnifiedVerifyError),
    Prover(anyhow::Error),
    EpochMismatch {
        expected: u32,
        got: u32,
        signer: usize,
    },
    WrongSignerCount {
        expected: usize,
        got: usize,
    },
}

impl core::fmt::Display for BlindMultiSigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proof(e) => write!(f, "proof verification failed: {e}"),
            Self::Prover(e) => write!(f, "proof generation failed: {e}"),
            Self::EpochMismatch {
                expected,
                got,
                signer,
            } => write!(
                f,
                "signer {signer} returned epoch {got}, expected {expected}",
            ),
            Self::WrongSignerCount { expected, got } => {
                write!(f, "expected {expected} signatures, got {got}")
            }
        }
    }
}
