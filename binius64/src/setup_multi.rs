//! Multi-signer setup with public inputs m_hat || pk_seed || roots. The
//! commitment and the single epoch shared by all XMSS signatures are secret.

use binius_core::constraint_system::ConstraintSystem;
use binius_frontend::{CircuitBuilder, Wire};

use crate::gadgets::{BLIND_COMMIT_INOUTS, BlindCommitGadget};
use crate::gadgets_multi::XmssMultisigVerifyGadget;
use crate::hashes::DIGEST_WIRES;
use crate::setup::{BlindZkProver, BlindZkVerifier, LOG_INV_RATE};

pub const fn n_inout_multi(n_signers: usize) -> usize {
    BLIND_COMMIT_INOUTS + DIGEST_WIRES * n_signers
}

pub struct ProverSetupMulti {
    pub circuit: binius_frontend::Circuit,
    pub commit: BlindCommitGadget,
    pub xmss_multi: XmssMultisigVerifyGadget,

    pub inout_wires: Vec<Wire>,
}

impl ProverSetupMulti {
    pub fn n_signers(&self) -> usize {
        self.xmss_multi.n_signers()
    }
}

pub fn build_prover_setup_multi(
    n_signers: usize,
) -> anyhow::Result<(ProverSetupMulti, BlindZkProver)> {
    build_prover_setup_multi_rate(n_signers, LOG_INV_RATE)
}

pub fn build_prover_setup_multi_rate(
    n_signers: usize,
    log_inv_rate: usize,
) -> anyhow::Result<(ProverSetupMulti, BlindZkProver)> {
    let (circuit, cs, fields) = build_circuit_multi(n_signers);

    let zk_verifier = BlindZkVerifier::setup(cs, log_inv_rate)?;
    let zk_prover = BlindZkProver::setup(&zk_verifier)?;
    Ok((
        ProverSetupMulti {
            circuit,
            commit: fields.commit,
            xmss_multi: fields.xmss_multi,
            inout_wires: fields.inout_wires,
        },
        zk_prover,
    ))
}

pub fn build_verifier_setup_multi(n_signers: usize) -> anyhow::Result<BlindZkVerifier> {
    build_verifier_setup_multi_rate(n_signers, LOG_INV_RATE)
}

pub fn build_verifier_setup_multi_rate(
    n_signers: usize,
    log_inv_rate: usize,
) -> anyhow::Result<BlindZkVerifier> {
    let (_circuit, cs, _fields) = build_circuit_multi(n_signers);
    BlindZkVerifier::setup(cs, log_inv_rate).map_err(Into::into)
}

struct CircuitFields {
    commit: BlindCommitGadget,
    xmss_multi: XmssMultisigVerifyGadget,
    inout_wires: Vec<Wire>,
}

fn build_circuit_multi(
    n_signers: usize,
) -> (binius_frontend::Circuit, ConstraintSystem, CircuitFields) {
    let b = CircuitBuilder::new();

    let commit = BlindCommitGadget::new(&b);

    let epoch_wire = b.add_witness();
    let roots: Vec<[Wire; DIGEST_WIRES]> = (0..n_signers)
        .map(|_| std::array::from_fn(|_| b.add_inout()))
        .collect();

    let xmss_multi =
        XmssMultisigVerifyGadget::new(&b, &commit.domain_param, commit.com_d(), epoch_wire, &roots);

    let prefix = commit.inout_wires();
    let mut inout_wires: Vec<Wire> = Vec::with_capacity(n_inout_multi(n_signers));
    inout_wires.extend_from_slice(&prefix);
    for root in &roots {
        inout_wires.extend_from_slice(root);
    }
    debug_assert_eq!(inout_wires.len(), n_inout_multi(n_signers));

    let circuit = b.build();
    let cs = circuit.constraint_system().clone();

    let fields = CircuitFields {
        commit,
        xmss_multi,
        inout_wires,
    };

    (circuit, cs, fields)
}
