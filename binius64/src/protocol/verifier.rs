use std::sync::Arc;

use binius_core::word::Word;
use binius_verifier::config::StdChallenger;
use binius_verifier::transcript::VerifierTranscript;

use crate::gadgets::{build_blind_commit_public_words, bytes16_to_words};
use crate::hashes::Digest;
use crate::protocol::FS_NONCE_BYTES;
use crate::salted_zk::verify_salted;
use crate::setup::{BlindZkVerifier, build_verifier_setup};
use crate::wots::PK_SEED_BYTES;

use super::{BlindSigError, BlindSignature};

pub struct Verifier {
    pub(crate) zk_verifier: Arc<BlindZkVerifier>,
    xmss_root: Digest,
    pk_seed: [u8; PK_SEED_BYTES],
}

impl Verifier {
    pub fn new(xmss_root: Digest, pk_seed: [u8; PK_SEED_BYTES]) -> Self {
        let zk_verifier = build_verifier_setup().expect("failed to build verifier setup");
        Self::with_zk_verifier(Arc::new(zk_verifier), xmss_root, pk_seed)
    }

    pub fn with_zk_verifier(
        zk_verifier: Arc<BlindZkVerifier>,
        xmss_root: Digest,
        pk_seed: [u8; PK_SEED_BYTES],
    ) -> Self {
        Verifier {
            zk_verifier,
            xmss_root,
            pk_seed,
        }
    }

    pub fn verify(&self, sig: &BlindSignature, msg: &[u8]) -> Result<(), BlindSigError> {
        let public = self.build_public_inputs(msg);

        let challenger = StdChallenger::default();
        let mut verifier_transcript = VerifierTranscript::new(challenger, sig.proof.clone());

        let mut label = [0u8; super::PROOF_LABEL.len()];
        verifier_transcript
            .message()
            .read_bytes(&mut label)
            .map_err(|e| {
                BlindSigError::Proof(UnifiedVerifyError::Proof(
                    binius_verifier::Error::from(e).into(),
                ))
            })?;
        if label != super::PROOF_LABEL {
            return Err(BlindSigError::Proof(
                UnifiedVerifyError::InvalidDomainSeparator,
            ));
        }
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        verifier_transcript
            .message()
            .read_bytes(&mut fs_nonce)
            .map_err(|e| {
                BlindSigError::Proof(UnifiedVerifyError::Proof(
                    binius_verifier::Error::from(e).into(),
                ))
            })?;

        verify_salted(&self.zk_verifier, &public, &mut verifier_transcript)
            .map_err(|e| BlindSigError::Proof(UnifiedVerifyError::Proof(e)))
    }

    fn build_public_inputs(&self, msg: &[u8]) -> Vec<Word> {
        let prefix = build_blind_commit_public_words(msg, &self.pk_seed);
        let xmss_root_words = bytes16_to_words(&self.xmss_root);

        let mut inouts: Vec<Word> = Vec::with_capacity(prefix.len() + xmss_root_words.len());
        inouts.extend_from_slice(&prefix);
        inouts.extend_from_slice(&xmss_root_words);

        assert_eq!(inouts.len(), self.zk_verifier.constraint_system().n_inout);
        inouts
    }
}

#[derive(Debug)]
pub enum UnifiedVerifyError {
    Proof(binius_verifier::zk_config::Error),
    InvalidDomainSeparator,
}

impl core::fmt::Display for UnifiedVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proof(e) => write!(f, "proof verification failed: {e}"),
            Self::InvalidDomainSeparator => write!(f, "invalid proof domain separator"),
        }
    }
}
