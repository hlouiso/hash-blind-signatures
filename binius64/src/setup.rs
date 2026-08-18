//! Single-signer circuit setup. Public inputs are m_hat || pk_seed || root;
//! the commitment opening, XMSS signature, and epoch are witnesses.
//! Binius64 fixes the BaseFold component at 96-bit security.

use binius_core::constraint_system::ConstraintSystem;
use binius_frontend::{CircuitBuilder, Wire};
use binius_hash::StdHashSuite;
use binius_verifier::zk_config::ZKVerifier;

use crate::gadgets::{BLIND_COMMIT_INOUTS, BlindCommitGadget, XmssVerifyGadget};
use crate::hashes::DIGEST_WIRES;
use crate::salted_zk::SaltedZkProver;

pub const LOG_INV_RATE: usize = 2;

pub const N_INOUT: usize = BLIND_COMMIT_INOUTS + DIGEST_WIRES;

pub type BlindZkVerifier = ZKVerifier<StdHashSuite>;

pub type BlindZkProver = SaltedZkProver;

pub fn build_prover_verifier(
    cs: ConstraintSystem,
) -> anyhow::Result<(BlindZkVerifier, BlindZkProver)> {
    let zk_verifier = BlindZkVerifier::setup(cs, LOG_INV_RATE)?;
    let zk_prover = BlindZkProver::setup(&zk_verifier)?;

    Ok((zk_verifier, zk_prover))
}

pub fn build_verifier(cs: ConstraintSystem) -> anyhow::Result<BlindZkVerifier> {
    BlindZkVerifier::setup(cs, LOG_INV_RATE).map_err(Into::into)
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

    let zk_verifier = BlindZkVerifier::setup(cs, log_inv_rate)?;
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
    BlindZkVerifier::setup(cs, log_inv_rate).map_err(Into::into)
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
