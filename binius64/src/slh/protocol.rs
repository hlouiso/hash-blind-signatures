//! The blind signature with SLH-DSA as the underlying scheme, on SHA-256 alone.
//!
//! The salted ZK proof and the transcript framing are those of
//! `crate::protocol`; the Halevi–Micali commitment is that of
//! `super::commit`, with SHA-256 in place of BLAKE3. The signer returns a pure
//! SLH-DSA signature (empty context) on the 32-byte commitment digest d, and
//! the user proves knowledge of it. The public inputs are m_hat for the
//! commitment gadget, then PK.seed, PK.root and the PK.seed midstate for the
//! SLH-DSA gadget.
//!
//! The blind multi-signature has n signers, each with an independent SLH-DSA
//! key. All of them sign the same commitment digest, and one proof verifies
//! the n signatures against the one secret commitment. Its public inputs are
//! m_hat, then the 16 public words of each signer in order. There is no epoch
//! to keep in lockstep: SLH-DSA picks its leaf from the signature randomness.
//! With n = 1 the circuit and the proof label are those of the single-signer
//! scheme.

use std::sync::Arc;

use binius_core::constraint_system::ConstraintSystem;
use binius_core::word::Word;
use binius_frontend::{Circuit, CircuitBuilder};
use binius_transcript::ProverTranscript;
use binius_verifier::config::StdChallenger;
use binius_verifier::transcript::VerifierTranscript;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng};

use super::commit::{COMMIT_INOUTS, ShaCommitGadget, message_hash, sample_commitment_for_digest};
use super::gadget::{SLH_INOUTS, SlhVerifyGadget, slh_public_words};
use super::native::{Node, SlhSignature};
use super::params::SlhParams;
use crate::commitment::{GhashElement, HmCommitment, N_NONCE, N_Y};
use crate::gadgets::bytes32_to_words;
use crate::protocol::FS_NONCE_BYTES;
use crate::salted_zk::verify_salted;
use crate::setup::{BlindZkProver, BlindZkVerifier, build_verifier};

pub const N_INOUT_SLH: usize = COMMIT_INOUTS + SLH_INOUTS;

/// Public words of a circuit with `n_signers` signers.
pub const fn n_inout_slh(n_signers: usize) -> usize {
    COMMIT_INOUTS + SLH_INOUTS * n_signers
}

fn proof_label(p: &SlhParams, n_signers: usize) -> Vec<u8> {
    if n_signers == 1 {
        format!("blind-{}-sha256-binius64-v2-salted-ghash", p.name).into_bytes()
    } else {
        format!("blind-{}-sha256-binius64-multisig-n{n_signers}-v1-salted-ghash", p.name)
            .into_bytes()
    }
}

/// An SLH-DSA public key, PK.seed || PK.root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhPublicKey {
    pub pk_seed: Node,
    pub pk_root: Node,
}

pub struct SlhSetup {
    pub params: SlhParams,
    pub circuit: Circuit,
    pub commit: ShaCommitGadget,
    /// One verification gadget per signer, in public-input order.
    pub slh: Vec<SlhVerifyGadget>,
}

impl SlhSetup {
    pub fn n_signers(&self) -> usize {
        self.slh.len()
    }
}

fn build_circuit(p: SlhParams, n_signers: usize) -> (SlhSetup, ConstraintSystem) {
    assert!(n_signers >= 1, "at least one signer");
    let b = CircuitBuilder::new();
    let commit = ShaCommitGadget::new(&b);
    let slh = if n_signers == 1 {
        vec![SlhVerifyGadget::new(&b, p, commit.digest_words())]
    } else {
        (0..n_signers)
            .map(|i| {
                let b = b.subcircuit(format!("signer[{i}]"));
                SlhVerifyGadget::new(&b, p, commit.digest_words())
            })
            .collect()
    };
    let circuit = b.build();
    let cs = circuit.constraint_system().clone();
    assert_eq!(cs.n_inout, n_inout_slh(n_signers));
    (
        SlhSetup {
            params: p,
            circuit,
            commit,
            slh,
        },
        cs,
    )
}

pub fn build_slh_prover_setup(p: SlhParams) -> anyhow::Result<(SlhSetup, BlindZkProver)> {
    build_slh_prover_setup_multi(p, 1)
}

pub fn build_slh_verifier(p: SlhParams) -> anyhow::Result<BlindZkVerifier> {
    build_slh_verifier_multi(p, 1)
}

pub fn build_slh_prover_setup_multi(
    p: SlhParams,
    n_signers: usize,
) -> anyhow::Result<(SlhSetup, BlindZkProver)> {
    let (setup, cs) = build_circuit(p, n_signers);
    let zk_verifier = build_verifier(cs)?;
    let zk_prover = BlindZkProver::setup(&zk_verifier)?;
    Ok((setup, zk_prover))
}

pub fn build_slh_verifier_multi(
    p: SlhParams,
    n_signers: usize,
) -> anyhow::Result<BlindZkVerifier> {
    let (_setup, cs) = build_circuit(p, n_signers);
    build_verifier(cs)
}

/// The public inputs in circuit order.
pub fn slh_public_inputs(msg: &[u8], pk_seed: &Node, pk_root: &Node) -> Vec<Word> {
    slh_public_inputs_multi(msg, &[SlhPublicKey {
        pk_seed: *pk_seed,
        pk_root: *pk_root,
    }])
}

/// The public inputs in circuit order: m_hat, then each signer's words.
pub fn slh_public_inputs_multi(msg: &[u8], pks: &[SlhPublicKey]) -> Vec<Word> {
    let mut out = Vec::with_capacity(n_inout_slh(pks.len()));
    out.extend_from_slice(&bytes32_to_words(&message_hash(msg)));
    for pk in pks {
        out.extend_from_slice(&slh_public_words(&pk.pk_seed, &pk.pk_root));
    }
    assert_eq!(out.len(), n_inout_slh(pks.len()));
    out
}

/// What the user keeps between the two rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhUserState {
    /// m_hat, the tagged SHA-256 digest of the document.
    pub digest: [u8; N_Y],
    pub com: HmCommitment,
    pub r: [GhashElement; N_NONCE],
}

pub struct SlhUser {
    rng: StdRng,
    setup: Arc<SlhSetup>,
    zk_prover: Arc<BlindZkProver>,
    state: Option<SlhUserState>,
}

impl SlhUser {
    pub fn with_setup(
        setup: Arc<SlhSetup>,
        zk_prover: Arc<BlindZkProver>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self {
            rng: StdRng::from_seed(seed),
            setup,
            zk_prover,
            state: None,
        }
    }

    pub fn commit(&mut self, msg: &[u8]) -> HmCommitment {
        let state = slh_commit(&mut self.rng, msg);
        let com = state.com.clone();
        self.state = Some(state);
        com
    }

    /// Resumes a session whose commitment was made by another process.
    pub fn restore(&mut self, state: SlhUserState) {
        self.state = Some(state);
    }

    /// The blind signature: a proof of knowledge of the opening and of `sig`.
    pub fn prove(
        &mut self,
        pk_seed: &Node,
        pk_root: &Node,
        sig: &SlhSignature,
    ) -> anyhow::Result<Vec<u8>> {
        let pk = SlhPublicKey {
            pk_seed: *pk_seed,
            pk_root: *pk_root,
        };
        self.prove_multi(&[pk], std::slice::from_ref(sig))
    }

    /// The blind multi-signature: one proof of the opening and of every
    /// `sigs[i]` under `pks[i]`.
    pub fn prove_multi(
        &mut self,
        pks: &[SlhPublicKey],
        sigs: &[SlhSignature],
    ) -> anyhow::Result<Vec<u8>> {
        let state = self.state.as_ref().ok_or_else(|| anyhow::anyhow!("commit before prove"))?;
        let s = &self.setup;
        let n = s.n_signers();
        anyhow::ensure!(
            pks.len() == n && sigs.len() == n,
            "the circuit has {n} signer(s), got {} key(s) and {} signature(s)",
            pks.len(),
            sigs.len()
        );
        for (i, sig) in sigs.iter().enumerate() {
            anyhow::ensure!(sig.has_shape(&s.params), "invalid SLH-DSA signature shape (signer {i})");
        }
        let mut filler = s.circuit.new_witness_filler();
        s.commit.populate_digest(&mut filler, &state.digest, &state.com, &state.r);
        for ((gadget, pk), sig) in s.slh.iter().zip(pks).zip(sigs) {
            gadget.populate(&mut filler, sig);
            for (wire, word) in gadget
                .inout_wires()
                .into_iter()
                .zip(slh_public_words(&pk.pk_seed, &pk.pk_root))
            {
                filler[wire] = word;
            }
        }
        s.circuit.populate_wire_witness(&mut filler)?;
        let value_vec = filler.into_value_vec();

        let mut transcript = ProverTranscript::new(StdChallenger::default());
        transcript.message().write_bytes(&proof_label(&s.params, n));
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        self.rng.fill_bytes(&mut fs_nonce);
        transcript.message().write_bytes(&fs_nonce);
        self.zk_prover
            .prove(&value_vec, &mut self.rng, &mut transcript)?;
        Ok(transcript.finalize())
    }
}

/// The user's first round without a prover setup, for a caller that proves
/// in another process.
pub fn slh_commit(rng: &mut impl Rng, msg: &[u8]) -> SlhUserState {
    let digest = message_hash(msg);
    let (com, r) = sample_commitment_for_digest(rng, &digest);
    SlhUserState { digest, com, r }
}

pub struct SlhVerifier {
    params: SlhParams,
    zk_verifier: Arc<BlindZkVerifier>,
    pks: Vec<SlhPublicKey>,
}

impl SlhVerifier {
    pub fn new(
        params: SlhParams,
        zk_verifier: Arc<BlindZkVerifier>,
        pk_seed: Node,
        pk_root: Node,
    ) -> Self {
        Self::new_multi(params, zk_verifier, vec![SlhPublicKey { pk_seed, pk_root }])
    }

    /// `zk_verifier` must come from `build_slh_verifier_multi(params, pks.len())`.
    pub fn new_multi(
        params: SlhParams,
        zk_verifier: Arc<BlindZkVerifier>,
        pks: Vec<SlhPublicKey>,
    ) -> Self {
        assert!(!pks.is_empty(), "at least one signer");
        Self {
            params,
            zk_verifier,
            pks,
        }
    }

    pub fn verify(&self, proof: &[u8], msg: &[u8]) -> anyhow::Result<()> {
        let public = slh_public_inputs_multi(msg, &self.pks);
        let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
        let label = proof_label(&self.params, self.pks.len());
        let mut got = vec![0u8; label.len()];
        transcript
            .message()
            .read_bytes(&mut got)
            .map_err(binius_verifier::Error::from)?;
        anyhow::ensure!(got == label, "wrong proof label");
        let mut fs_nonce = [0u8; FS_NONCE_BYTES];
        transcript
            .message()
            .read_bytes(&mut fs_nonce)
            .map_err(binius_verifier::Error::from)?;
        verify_salted(&self.zk_verifier, &public, &mut transcript)?;
        transcript
            .finalize()
            .map_err(binius_verifier::Error::from)?;
        Ok(())
    }
}
