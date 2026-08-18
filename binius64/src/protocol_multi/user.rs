use std::sync::Arc;

use binius_transcript::ProverTranscript;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng};

use crate::commitment::{CommitmentOpening, HmCommitment, sample_commitment};
use crate::gadgets::{BLIND_COMMIT_INOUTS, bytes16_to_words};
use crate::hashes::DIGEST_WIRES;
use crate::protocol::{FS_NONCE_BYTES, UserState};
use crate::setup::BlindZkProver;
use crate::setup_multi::{ProverSetupMulti, build_prover_setup_multi};
use crate::xmss::XmssSignature;

use super::{BlindMultiSigError, BlindMultiSignature};

pub struct MultiUser {
    rng: StdRng,
    setup: Arc<ProverSetupMulti>,
    zk_prover: Arc<BlindZkProver>,
    state: Option<UserState>,
}

impl MultiUser {
    pub fn new(rng: &mut (impl Rng + CryptoRng), n_signers: usize) -> Self {
        let (setup, zk_prover) =
            build_prover_setup_multi(n_signers).expect("failed to build multi-sig prover setup");
        Self::with_setup(Arc::new(setup), Arc::new(zk_prover), rng)
    }

    pub fn with_setup(
        setup: Arc<ProverSetupMulti>,
        zk_prover: Arc<BlindZkProver>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        MultiUser {
            rng: StdRng::from_seed(seed),
            setup,
            zk_prover,
            state: None,
        }
    }

    pub fn n_signers(&self) -> usize {
        self.setup.n_signers()
    }

    pub fn commit(&mut self, msg: &[u8]) -> HmCommitment {
        let (com, opening) = sample_commitment(&mut self.rng, msg);
        self.state = Some(UserState {
            opening,
            com: com.clone(),
        });
        com
    }

    pub fn prove(
        &mut self,
        signatures: &[XmssSignature],
    ) -> Result<BlindMultiSignature, BlindMultiSigError> {
        let n_signers = self.setup.n_signers();
        if signatures.len() != n_signers {
            return Err(BlindMultiSigError::WrongSignerCount {
                expected: n_signers,
                got: signatures.len(),
            });
        }
        let epoch = signatures[0].epoch;
        for (i, s) in signatures.iter().enumerate() {
            if s.epoch != epoch {
                return Err(BlindMultiSigError::EpochMismatch {
                    expected: epoch,
                    got: s.epoch,
                    signer: i,
                });
            }
        }

        let state = self
            .state
            .as_ref()
            .expect("commit must be called before prove");

        let mut filler = self.setup.circuit.new_witness_filler();

        self.setup.commit.populate(
            &mut filler,
            &state.opening.msg,
            &state.com,
            &state.opening.r,
            &signatures[0].public_param,
        );

        self.setup.xmss_multi.populate(&mut filler, signatures);

        let w = &self.setup.inout_wires;
        for (j, sig) in signatures.iter().enumerate() {
            let base = BLIND_COMMIT_INOUTS + DIGEST_WIRES * j;
            for (i, word) in bytes16_to_words(&sig.root).into_iter().enumerate() {
                filler[w[base + i]] = word;
            }
        }

        self.setup
            .circuit
            .populate_wire_witness(&mut filler)
            .map_err(|e| BlindMultiSigError::Prover(e.into()))?;
        let value_vec = filler.into_value_vec();

        let challenger = binius_verifier::config::StdChallenger::default();
        let mut prover_transcript = ProverTranscript::new(challenger);
        prover_transcript
            .message()
            .write_bytes(super::PROOF_LABEL_MULTI);
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        self.rng.fill_bytes(&mut fs_nonce);
        prover_transcript.message().write_bytes(&fs_nonce);
        self.zk_prover
            .prove(&value_vec, &mut self.rng, &mut prover_transcript)
            .map_err(|e| BlindMultiSigError::Prover(e.into()))?;
        let proof = prover_transcript.finalize();

        Ok(BlindMultiSignature { proof })
    }

    pub fn opening(&self) -> &CommitmentOpening {
        &self
            .state
            .as_ref()
            .expect("commit must be called before opening")
            .opening
    }

    pub fn state(&self) -> &UserState {
        self.state
            .as_ref()
            .expect("commit must be called before state")
    }

    pub fn restore(&mut self, state: UserState) {
        self.state = Some(state);
    }
}
