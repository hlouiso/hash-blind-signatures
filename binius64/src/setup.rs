//! Single-signer circuit setup. Public inputs are m_hat || pk_seed || root;
//! the commitment opening, XMSS signature, and epoch are witnesses.
//! Binius64 fixes the BaseFold component at 96-bit security.

use binius_core::constraint_system::{ConstraintSystem, InoutSegment};
use binius_frontend::{CircuitBuilder, Wire};
use binius_hash::StdHashSuite;
use binius_verifier::{
    protocols::shift::LOG_SHIFT_COUNT,
    reduction::{LOG_OPERANDS, log_constraint_point},
    zk_config::ZKVerifier,
};

use crate::gadgets::{BLIND_COMMIT_INOUTS, BlindCommitGadget, XmssVerifyGadget};
use crate::hashes::DIGEST_WIRES;
use crate::salted_zk::SaltedZkProver;

pub const LOG_INV_RATE: usize = 2;

pub const N_INOUT: usize = BLIND_COMMIT_INOUTS + DIGEST_WIRES;

pub type BlindZkVerifier = ZKVerifier<StdHashSuite>;

pub type BlindZkProver = SaltedZkProver;

/// The pinned upstream verifier indexes its sparse wiring matrix with a u64.
#[derive(Debug)]
pub struct WiringCapacityError {
    pub required_bits: usize,
}

impl std::fmt::Display for WiringCapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Binius64 wiring address needs {} bits; upstream supports at most 63",
            self.required_bits,
        )
    }
}

impl std::error::Error for WiringCapacityError {}

pub(crate) fn build_verifier_rate(
    cs: ConstraintSystem,
    log_inv_rate: usize,
) -> anyhow::Result<BlindZkVerifier> {
    cs.validate()?;
    // Check the upstream WiringInfo::new precondition before it can panic.
    let required_bits = LOG_OPERANDS
        + 2 * LOG_SHIFT_COUNT
        + cs.log_segment_words(InoutSegment::Public)
        + log_constraint_point(&cs);
    if required_bits >= u64::BITS as usize {
        return Err(WiringCapacityError { required_bits }.into());
    }
    BlindZkVerifier::setup(cs, log_inv_rate).map_err(Into::into)
}

pub fn build_prover_verifier(
    cs: ConstraintSystem,
) -> anyhow::Result<(BlindZkVerifier, BlindZkProver)> {
    let zk_verifier = build_verifier(cs)?;
    let zk_prover = BlindZkProver::setup(&zk_verifier)?;

    Ok((zk_verifier, zk_prover))
}

pub fn build_verifier(cs: ConstraintSystem) -> anyhow::Result<BlindZkVerifier> {
    build_verifier_rate(cs, LOG_INV_RATE)
}

pub struct ProverSetup {
    pub circuit: binius_frontend::Circuit,
    pub commit: BlindCommitGadget,
    pub xmss_verify: XmssVerifyGadget,

    pub inout_wires: [binius_frontend::Wire; N_INOUT],
}

pub fn build_prover_setup() -> anyhow::Result<(ProverSetup, BlindZkProver)> {
    build_prover_setup_rate(LOG_INV_RATE)
}

pub fn build_prover_setup_rate(
    log_inv_rate: usize,
) -> anyhow::Result<(ProverSetup, BlindZkProver)> {
    let (circuit, cs, prover_fields) = build_circuit();

    let zk_verifier = build_verifier_rate(cs, log_inv_rate)?;
    let zk_prover = BlindZkProver::setup(&zk_verifier)?;
    Ok((
        ProverSetup {
            circuit,
            commit: prover_fields.commit,
            xmss_verify: prover_fields.xmss_verify,
            inout_wires: prover_fields.inout_wires,
        },
        zk_prover,
    ))
}

pub fn build_verifier_setup() -> anyhow::Result<BlindZkVerifier> {
    build_verifier_setup_rate(LOG_INV_RATE)
}

pub fn build_verifier_setup_rate(log_inv_rate: usize) -> anyhow::Result<BlindZkVerifier> {
    let (_circuit, cs, _fields) = build_circuit();
    build_verifier_rate(cs, log_inv_rate)
}

struct CircuitFields {
    commit: BlindCommitGadget,
    xmss_verify: XmssVerifyGadget,
    inout_wires: [binius_frontend::Wire; N_INOUT],
}

fn build_circuit() -> (binius_frontend::Circuit, ConstraintSystem, CircuitFields) {
    let b = CircuitBuilder::new();

    let commit = BlindCommitGadget::new(&b);

    let xmss_root_wires: [Wire; DIGEST_WIRES] = std::array::from_fn(|_| b.add_inout());

    let xmss_verify =
        XmssVerifyGadget::new(&b, &commit.domain_param, commit.com_d(), &xmss_root_wires);

    let prefix = commit.inout_wires();
    let inout_wires: [Wire; N_INOUT] = std::array::from_fn(|i| {
        if i < BLIND_COMMIT_INOUTS {
            prefix[i]
        } else {
            xmss_root_wires[i - BLIND_COMMIT_INOUTS]
        }
    });

    let circuit = b.build();
    let cs = circuit.constraint_system().clone();

    let fields = CircuitFields {
        commit,
        xmss_verify,
        inout_wires,
    };

    (circuit, cs, fields)
}
