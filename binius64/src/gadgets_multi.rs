//! Multi-signer XMSS verification over one secret digest and one secret epoch.
//! The signers share pk_seed, so one hasher, with its epoch bytes and tree
//! midstate, serves all of them.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::gadgets::assert_epoch_below_height;
use crate::hashes::{DIGEST_WIRES, MESSAGE_WORDS, PUBLIC_PARAM_WIRES};
use crate::ts_xmss::hashing::XmssHasher;
use crate::ts_xmss::xmss::{XmssSignatureWires, circuit_xmss_verify};
use crate::xmss::XmssSignature;

pub struct XmssMultisigVerifyGadget {
    per_signer: Vec<XmssSignatureWires>,
    epoch: Wire,
}

impl XmssMultisigVerifyGadget {
    pub fn new(
        b: &CircuitBuilder,
        domain_param_wires: &[Wire; PUBLIC_PARAM_WIRES],
        signed_msg_words: &[Wire; MESSAGE_WORDS],
        epoch_wire: Wire,
        epoch_mask_wire: Wire,
        roots: &[[Wire; DIGEST_WIRES]],
    ) -> Self {
        assert!(!roots.is_empty(), "at least one XMSS signer is required");
        assert_epoch_below_height(b, epoch_wire, epoch_mask_wire);

        let h = XmssHasher::new(b, domain_param_wires, epoch_wire);
        let per_signer = roots
            .iter()
            .map(|root| {
                let signature = XmssSignatureWires::new_witness(b);
                circuit_xmss_verify(&h, domain_param_wires, root, signed_msg_words, &signature);
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
            wires.populate(w, &sig.to_signature());
        }
    }
}
