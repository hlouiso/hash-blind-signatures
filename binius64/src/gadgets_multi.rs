//! Multi-signer XMSS verification over one secret digest and one secret epoch.

use binius_circuits::hash_based_sig::xmss::{XmssSignatureWires, circuit_xmss_verify};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::hashes::{DIGEST_WIRES, MESSAGE_WIRES, PUBLIC_PARAM_WIRES};
use crate::xmss::XmssSignature;

pub struct XmssMultisigVerifyGadget {
    per_signer: Vec<XmssSignatureWires>,
    epoch: Wire,
}

impl XmssMultisigVerifyGadget {
    pub fn new(
        b: &CircuitBuilder,
        domain_param_wires: &[Wire; PUBLIC_PARAM_WIRES],
        signed_msg_wires: &[Wire; MESSAGE_WIRES],
        epoch_wire: Wire,
        roots: &[[Wire; DIGEST_WIRES]],
    ) -> Self {
        let per_signer = roots
            .iter()
            .enumerate()
            .map(|(i, root)| {
                let b = b.subcircuit(format!("signer[{i}]"));
                let signature = XmssSignatureWires::new_witness(&b);
                circuit_xmss_verify(
                    &b,
                    domain_param_wires,
                    root,
                    signed_msg_wires,
                    epoch_wire,
                    &signature,
                );
                signature
            })
            .collect();

        Self {
            per_signer,
            epoch: epoch_wire,
        }
    }

    pub fn n_signers(&self) -> usize {
        self.per_signer.len()
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, signatures: &[XmssSignature]) {
        assert_eq!(
            signatures.len(),
            self.per_signer.len(),
            "signatures length {} != gadget n_signers {}",
            signatures.len(),
            self.per_signer.len(),
        );

        let epoch = signatures[0].epoch;
        for s in signatures {
            assert_eq!(
                s.epoch, epoch,
                "all signers must use the same epoch (got {} and {})",
                epoch, s.epoch,
            );
        }
        w[self.epoch] = Word::from_u64(epoch as u64);

        for (wires, sig) in self.per_signer.iter().zip(signatures) {
            wires.populate(w, &sig.to_upstream());
        }
    }
}
