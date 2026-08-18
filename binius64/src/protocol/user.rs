use std::sync::Arc;

use binius_transcript::ProverTranscript;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng};

use crate::commitment::{CommitmentOpening, HmCommitment, sample_commitment};
use crate::gadgets::{BLIND_COMMIT_INOUTS, bytes16_to_words};
use crate::protocol::FS_NONCE_BYTES;
use crate::setup::{BlindZkProver, ProverSetup, build_prover_setup};
use crate::xmss::XmssSignature;

use super::{BlindSigError, BlindSignature};

#[derive(Debug, Clone)]
pub struct UserState {
    pub opening: CommitmentOpening,
    pub com: HmCommitment,
}

pub struct User {
    rng: StdRng,
    setup: Arc<ProverSetup>,
    zk_prover: Arc<BlindZkProver>,
    state: Option<UserState>,
}

impl User {
    pub fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let (setup, zk_prover) = build_prover_setup().expect("failed to build prover setup");
        Self::with_setup(Arc::new(setup), Arc::new(zk_prover), rng)
    }

    pub fn with_setup(
        setup: Arc<ProverSetup>,
        zk_prover: Arc<BlindZkProver>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        User {
            rng: StdRng::from_seed(seed),
            setup,
            zk_prover,
            state: None,
        }
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
        xmss_signature: &XmssSignature,
    ) -> Result<BlindSignature, BlindSigError> {
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
            &xmss_signature.public_param,
        );

        self.setup.xmss_verify.populate(&mut filler, xmss_signature);

        let w = &self.setup.inout_wires;
        let root_words = bytes16_to_words(&xmss_signature.root);
        for (i, word) in root_words.into_iter().enumerate() {
            filler[w[BLIND_COMMIT_INOUTS + i]] = word;
        }

        self.setup
            .circuit
            .populate_wire_witness(&mut filler)
            .map_err(|e| BlindSigError::Prover(e.into()))?;
        let value_vec = filler.into_value_vec();

        let challenger = binius_verifier::config::StdChallenger::default();
        let mut prover_transcript = ProverTranscript::new(challenger);
        prover_transcript.message().write_bytes(super::PROOF_LABEL);
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        self.rng.fill_bytes(&mut fs_nonce);
        prover_transcript.message().write_bytes(&fs_nonce);
        self.zk_prover
            .prove(&value_vec, &mut self.rng, &mut prover_transcript)
            .map_err(|e| BlindSigError::Prover(e.into()))?;
        let proof = prover_transcript.finalize();

        Ok(BlindSignature { proof })
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
