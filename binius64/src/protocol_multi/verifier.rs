use std::sync::Arc;

use binius_core::word::Word;
use binius_verifier::config::StdChallenger;
use binius_verifier::transcript::VerifierTranscript;

use crate::gadgets::{build_blind_commit_public_words, epoch_mask, node_words};
use crate::hashes::Digest;
use crate::protocol::{FS_NONCE_BYTES, verifier::UnifiedVerifyError};
use crate::salted_zk::verify_salted;
use crate::setup::BlindZkVerifier;
use crate::setup_multi::{build_verifier_setup_multi, n_inout_multi};
use crate::wots::PK_SEED_BYTES;

use super::{BlindMultiSigError, BlindMultiSignature};

/// Verifies under n roots that share one pk_seed and one real height.
pub struct MultiVerifier {
    zk_verifier: Arc<BlindZkVerifier>,
    roots: Vec<Digest>,
    pk_seed: [u8; PK_SEED_BYTES],
    epoch_mask: Word,
}

impl MultiVerifier {
    pub fn new(roots: Vec<Digest>, pk_seed: [u8; PK_SEED_BYTES], height: usize) -> Self {
        let zk_verifier = build_verifier_setup_multi(roots.len())
            .expect("failed to build multi-sig verifier setup");
        Self::with_zk_verifier(Arc::new(zk_verifier), roots, pk_seed, height)
    }

    pub fn with_zk_verifier(
        zk_verifier: Arc<BlindZkVerifier>,
        roots: Vec<Digest>,
        pk_seed: [u8; PK_SEED_BYTES],
        height: usize,
    ) -> Self {
        assert!(!roots.is_empty(), "at least one XMSS signer is required");
        MultiVerifier {
            zk_verifier,
            roots,
            pk_seed,
            epoch_mask: epoch_mask(height),
        }
    }

    pub fn n_signers(&self) -> usize {
        self.roots.len()
    }

    pub fn verify(&self, sig: &BlindMultiSignature, msg: &[u8]) -> Result<(), BlindMultiSigError> {
        let public = self.build_public_inputs(msg);

        let challenger = StdChallenger::default();
        let mut verifier_transcript = VerifierTranscript::new(challenger, sig.proof.clone());

        let mut label = [0u8; super::PROOF_LABEL_MULTI.len()];
        verifier_transcript
            .message()
            .read_bytes(&mut label)
            .map_err(|e| {
                BlindMultiSigError::Proof(UnifiedVerifyError::Proof(
                    binius_verifier::Error::from(e).into(),
                ))
            })?;
        if label != super::PROOF_LABEL_MULTI {
            return Err(BlindMultiSigError::Proof(
                UnifiedVerifyError::InvalidDomainSeparator,
            ));
        }
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        verifier_transcript
            .message()
            .read_bytes(&mut fs_nonce)
            .map_err(|e| {
                BlindMultiSigError::Proof(UnifiedVerifyError::Proof(
                    binius_verifier::Error::from(e).into(),
                ))
            })?;

        verify_salted(&self.zk_verifier, &public, &mut verifier_transcript)
            .map_err(|e| BlindMultiSigError::Proof(UnifiedVerifyError::Proof(e)))?;
        verifier_transcript.finalize().map_err(|e| {
            BlindMultiSigError::Proof(UnifiedVerifyError::Proof(
                binius_verifier::Error::from(e).into(),
            ))
        })
    }

    fn build_public_inputs(&self, msg: &[u8]) -> Vec<Word> {
        let prefix = build_blind_commit_public_words(msg, &self.pk_seed);

        let mut inouts: Vec<Word> = Vec::with_capacity(n_inout_multi(self.roots.len()));
        inouts.extend_from_slice(&prefix);
        for root in &self.roots {
            inouts.extend_from_slice(&node_words(root));
        }
        inouts.push(self.epoch_mask);
        debug_assert_eq!(inouts.len(), n_inout_multi(self.roots.len()));

        assert_eq!(inouts.len(), self.zk_verifier.constraint_system().n_inout);
        inouts
    }
}
