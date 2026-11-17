//! Black-box checks on what the prover's transcript reveals.
//!
//! The harness replaces the Fiat-Shamir challenger by one whose challenges do
//! not depend on the transcript. With the challenges fixed, a value the prover
//! sends is either
//!
//! * randomized: it changes when only the prover's coins change, or
//! * deterministic: it is a function of the witness and the challenges.
//!
//! A deterministic value must not depend on the witness. We therefore prove the
//! same statement three times -- witness 1 with coins A, witness 1 with coins B,
//! witness 2 with coins A -- and look for 8-byte blocks that agree between the
//! first two transcripts and differ in the third. Such a block is a
//! witness-dependent value sent without any masking.
//!
//! This is a necessary condition for zero knowledge, not a proof of it.

use std::sync::{Arc, Mutex};

use binius_transcript::{ProverTranscript, fiat_shamir::Challenger};
use blind_xmss_binius64::{
    BlindZkProver, ProverSetup, Signer, XmssSignature, build_prover_setup,
    commitment::{CommitmentOpening, HmCommitment, sample_commitment},
    gadgets::{BLIND_COMMIT_INOUTS, bytes16_to_words},
};
use bytes::{Buf, BufMut};
use rand::{Rng, SeedableRng, rngs::StdRng};

const TEST_H: usize = 8;
const BLOCK: usize = 8;

/// An endless pseudo-random byte stream that depends on a seed only.
#[derive(Clone)]
struct Stream {
    xof: blake3::OutputReader,
    buf: [u8; 1024],
    pos: usize,
}

impl Stream {
    fn new(seed: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("blind-xmss-binius64 fixed challenger");
        hasher.update(&seed.to_le_bytes());
        let mut xof = hasher.finalize_xof();
        let mut buf = [0u8; 1024];
        xof.fill(&mut buf);
        Self { xof, buf, pos: 0 }
    }
}

impl Buf for Stream {
    fn remaining(&self) -> usize {
        usize::MAX
    }

    fn chunk(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let n = cnt.min(self.buf.len() - self.pos);
            self.pos += n;
            cnt -= n;
            if self.pos == self.buf.len() {
                self.xof.fill(&mut self.buf);
                self.pos = 0;
            }
        }
    }
}

/// A challenger that ignores what it observes, and hands the observed bytes
/// (the prover's message tape, without decommitments) back when dropped.
struct FixedChallenger {
    stream: Stream,
    observed: Vec<u8>,
    out: Arc<Mutex<Vec<u8>>>,
}

impl Challenger for FixedChallenger {
    fn sampler(&mut self) -> &mut impl Buf {
        &mut self.stream
    }

    fn observer(&mut self) -> &mut impl BufMut {
        &mut self.observed
    }
}

impl Drop for FixedChallenger {
    fn drop(&mut self) {
        *self.out.lock().unwrap() = std::mem::take(&mut self.observed);
    }
}

struct Session {
    com: HmCommitment,
    opening: CommitmentOpening,
    sig: XmssSignature,
}

/// Two sessions for the same message under the same key: the same public
/// statement with two different witnesses (opening, signature and leaf).
fn two_sessions() -> (Session, Session) {
    let mut rng = StdRng::seed_from_u64(0x5eed_0001);
    let mut message = vec![0u8; 1024];
    rng.fill_bytes(&mut message);
    let mut signer = Signer::new(&mut rng, TEST_H);
    let mut session = |rng: &mut StdRng| {
        let (com, opening) = sample_commitment(rng, &message);
        let sig = signer.sign(&com).expect("sign failed");
        Session { com, opening, sig }
    };
    let first = session(&mut rng);
    let second = session(&mut rng);
    assert_eq!(first.sig.root, second.sig.root);
    assert_eq!(first.sig.public_param, second.sig.public_param);
    assert_ne!(first.sig.epoch, second.sig.epoch);
    (first, second)
}

struct Tapes {
    /// Everything the challenger observed: the prover's messages.
    messages: Vec<u8>,
    /// The serialized proof: messages and decommitments.
    proof: Vec<u8>,
}

fn prove(
    setup: &ProverSetup,
    prover: &BlindZkProver,
    session: &Session,
    challenge_seed: u64,
    coin_seed: u64,
) -> Tapes {
    let mut filler = setup.circuit.new_witness_filler();
    setup.commit.populate(
        &mut filler,
        &session.opening.msg,
        &session.com,
        &session.opening.r,
        &session.sig.public_param,
    );
    setup.xmss_verify.populate(&mut filler, &session.sig);
    for (i, word) in bytes16_to_words(&session.sig.root).into_iter().enumerate() {
        filler[setup.inout_wires[BLIND_COMMIT_INOUTS + i]] = word;
    }
    setup
        .circuit
        .populate_wire_witness(&mut filler)
        .expect("witness population failed");
    let value_vec = filler.into_value_vec();

    let out = Arc::new(Mutex::new(Vec::new()));
    let challenger = FixedChallenger {
        stream: Stream::new(challenge_seed),
        observed: Vec::new(),
        out: Arc::clone(&out),
    };
    let mut transcript = ProverTranscript::new(challenger);
    prover
        .prove(&value_vec, StdRng::seed_from_u64(coin_seed), &mut transcript)
        .expect("proof generation failed");
    let proof = transcript.finalize();
    let messages = std::mem::take(&mut *out.lock().unwrap());
    Tapes { messages, proof }
}

/// Offsets of the blocks that are equal in `a` and `b` but differ in `c`.
fn unmasked_blocks(a: &[u8], b: &[u8], c: &[u8]) -> Vec<usize> {
    assert_eq!(a.len(), b.len(), "same statement, same challenges: same layout");
    assert_eq!(a.len(), c.len(), "same statement, same challenges: same layout");
    (0..a.len() / BLOCK)
        .map(|i| i * BLOCK)
        .filter(|&o| a[o..o + BLOCK] == b[o..o + BLOCK] && a[o..o + BLOCK] != c[o..o + BLOCK])
        .collect()
}

struct Report {
    message_blocks: Vec<usize>,
    proof_blocks: Vec<usize>,
    proof_len: usize,
}

fn examine(setup: &ProverSetup, prover: &BlindZkProver, challenge_seed: u64) -> Report {
    let (w1, w2) = two_sessions();
    let t11 = prove(setup, prover, &w1, challenge_seed, 11);
    let t12 = prove(setup, prover, &w1, challenge_seed, 12);
    let t21 = prove(setup, prover, &w2, challenge_seed, 11);
    // The harness itself must be sound: with other coins the transcript changes.
    assert_ne!(t11.proof, t12.proof);
    Report {
        message_blocks: unmasked_blocks(&t11.messages, &t12.messages, &t21.messages),
        proof_blocks: unmasked_blocks(&t11.proof, &t12.proof, &t21.proof),
        proof_len: t11.proof.len(),
    }
}

/// Regression check for the target of the inner oracle relation.
///
/// Every message of the prover must be randomized or witness-independent. An
/// inner opening target sent in the clear is neither: it shows up here as one
/// field element (two blocks).
#[test]
fn prover_messages_are_masked_or_public() {
    let (setup, prover) = build_prover_setup().expect("setup failed");
    for challenge_seed in 0..3 {
        let report = examine(&setup, &prover, challenge_seed);
        assert!(
            report.message_blocks.is_empty(),
            "challenge seed {challenge_seed}: witness-dependent message bytes sent without \
             masking at observed-tape offsets {:?}",
            report.message_blocks
        );
    }
}

/// Known gap, kept as an executable record: opened codeword symbols.
///
/// The query phase opens symbols of the committed codewords. A symbol at a low
/// position of the additive-NTT codeword depends on few message coordinates,
/// and the pad coordinates need not be among them; such a symbol is then a
/// fixed function of the witness. The sweep counts the challenge seeds for
/// which the proof contains such a symbol. Run with
/// `cargo test --release -- --ignored --nocapture opened_symbols`.
#[test]
#[ignore = "known gap: pad independence of the encoder is not established"]
fn opened_symbols_are_masked_or_public() {
    let (setup, prover) = build_prover_setup().expect("setup failed");
    let seeds: u64 = std::env::var("ZK_SWEEP_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let mut hits = Vec::new();
    for challenge_seed in 0..seeds {
        let report = examine(&setup, &prover, challenge_seed);
        if !report.proof_blocks.is_empty() {
            println!(
                "challenge seed {challenge_seed}: {} unmasked witness-dependent block(s) in a \
                 proof of {} bytes, first offsets {:?}",
                report.proof_blocks.len(),
                report.proof_len,
                &report.proof_blocks[..report.proof_blocks.len().min(8)]
            );
            hits.push(challenge_seed);
        }
    }
    println!("{} of {seeds} challenge seeds expose an unmasked witness-dependent value", hits.len());
    assert!(hits.is_empty(), "seeds with unmasked witness-dependent values: {hits:?}");
}
