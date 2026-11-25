//! SLH-DSA as the underlying signature: the circuit against the native
//! verifier.

use std::sync::Arc;

use blind_xmss_binius64::slh::SlhParams;
use blind_xmss_binius64::slh::commit::com_digest;
use blind_xmss_binius64::slh::native::{Node, SlhKey, slh_verify};
use blind_xmss_binius64::slh::protocol::{
    SlhUser, SlhVerifier, build_slh_prover_setup, build_slh_verifier,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn node(rng: &mut impl Rng) -> Node {
    let mut n = [0u8; 16];
    rng.fill_bytes(&mut n);
    n
}

/// One layer and w = 4, the shape of SLH-DSA-SHA2-128-24.
const TOY_W4: SlhParams = SlhParams {
    name: "toy-w4-d1",
    h: 6,
    d: 1,
    hp: 6,
    a: 5,
    k: 6,
    lg_w: 2,
    m: 5,
};

/// Several layers and w = 16, to cover the hypertree and the longer chains.
const TOY_W16: SlhParams = SlhParams {
    name: "toy-w16-d3",
    h: 6,
    d: 3,
    hp: 2,
    a: 4,
    k: 5,
    lg_w: 4,
    m: 5,
};

fn round_trip(p: SlhParams, seed: u64) {
    assert_eq!(p.md_bytes() + p.tree_bytes() + p.leaf_bytes(), p.m);
    let mut rng = StdRng::seed_from_u64(seed);
    let key = SlhKey::keygen_internal(p, &node(&mut rng), &node(&mut rng), &node(&mut rng));
    let (pk_seed, pk_root) = (*key.pk_seed(), key.pk_root);

    let (setup, zk_prover) = build_slh_prover_setup(p).unwrap();
    let verifier = SlhVerifier::new(
        p,
        Arc::new(build_slh_verifier(p).unwrap()),
        pk_seed,
        pk_root,
    );
    let mut user = SlhUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);

    let doc = b"an SLH-DSA blind signature test document";
    for round in 0..3 {
        let com = user.commit(doc);
        let sig = key.sign(&com_digest(&com), Some(&node(&mut rng)));
        assert!(slh_verify(p, &pk_seed, &pk_root, &com_digest(&com), &sig));

        let proof = user.prove(&pk_seed, &pk_root, &sig).unwrap();
        verifier.verify(&proof, doc).unwrap();
        assert!(verifier.verify(&proof, b"another document").is_err());

        if round == 0 {
            let mut malformed = sig.clone();
            let sibling = malformed.fors[0].auth.pop().unwrap();
            assert!(user.prove(&pk_seed, &pk_root, &malformed).is_err());
            // Equal serialized length still requires the correct component lengths.
            malformed.ht[0].auth.push(sibling);
            assert!(user.prove(&pk_seed, &pk_root, &malformed).is_err());
        }

        // Tampering with any part of the signature leaves no witness.
        let mut bad = sig.clone();
        match round {
            0 => bad.ht[p.d - 1].wots[p.len() - 1][0] ^= 1,
            1 => bad.fors[p.k - 1].auth[p.a - 1][15] ^= 0x80,
            _ => bad.r[3] ^= 4,
        }
        assert!(user.prove(&pk_seed, &pk_root, &bad).is_err(), "round {round}");
        bad = sig.clone();
        bad.ht[0].auth[p.hp - 1][7] ^= 2;
        assert!(user.prove(&pk_seed, &pk_root, &bad).is_err());
        bad = sig.clone();
        bad.fors[0].sk[0] ^= 1;
        assert!(user.prove(&pk_seed, &pk_root, &bad).is_err());

        // A signature on another commitment does not verify on this one.
        let other = key.sign(&[0u8; 32], None);
        assert!(user.prove(&pk_seed, &pk_root, &other).is_err());
        // Nor does this one under another key.
        let mut other_root = pk_root;
        other_root[0] ^= 1;
        assert!(user.prove(&pk_seed, &other_root, &sig).is_err());
    }
}

#[test]
fn circuit_accepts_exactly_valid_signatures_w4_single_layer() {
    round_trip(TOY_W4, 41);
}

#[test]
fn circuit_accepts_exactly_valid_signatures_w16_hypertree() {
    round_trip(TOY_W16, 43);
}

/// n independent keys sign one commitment; one proof covers all of them.
#[test]
fn multisig_accepts_exactly_the_signer_set() {
    use blind_xmss_binius64::slh::protocol::{
        SlhPublicKey, build_slh_prover_setup_multi, build_slh_verifier_multi,
    };
    let p = TOY_W4;
    let n = 3;
    let mut rng = StdRng::seed_from_u64(47);
    let keys: Vec<SlhKey> = (0..n + 1)
        .map(|_| SlhKey::keygen_internal(p, &node(&mut rng), &node(&mut rng), &node(&mut rng)))
        .collect();
    let pk = |k: &SlhKey| SlhPublicKey {
        pk_seed: *k.pk_seed(),
        pk_root: k.pk_root,
    };
    let pks: Vec<SlhPublicKey> = keys[..n].iter().map(pk).collect();

    let (setup, zk_prover) = build_slh_prover_setup_multi(p, n).unwrap();
    assert_eq!(setup.n_signers(), n);
    let zk_verifier = Arc::new(build_slh_verifier_multi(p, n).unwrap());
    let verifier = SlhVerifier::new_multi(p, zk_verifier.clone(), pks.clone());
    let mut user = SlhUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);

    let doc = b"an SLH-DSA blind multi-signature test document";
    let com = user.commit(doc);
    let d = com_digest(&com);
    let sigs: Vec<_> = keys[..n].iter().map(|k| k.sign(&d, Some(&node(&mut rng)))).collect();

    let proof = user.prove_multi(&pks, &sigs).unwrap();
    verifier.verify(&proof, doc).unwrap();
    assert!(verifier.verify(&proof, b"another document").is_err());

    // The verifier's key list is part of the statement, order included.
    let mut swapped = pks.clone();
    swapped.swap(0, 1);
    assert!(SlhVerifier::new_multi(p, zk_verifier.clone(), swapped).verify(&proof, doc).is_err());
    let mut other = pks.clone();
    other[2] = pk(&keys[n]);
    assert!(SlhVerifier::new_multi(p, zk_verifier.clone(), other.clone()).verify(&proof, doc).is_err());

    // The prover needs a valid signature from every listed key.
    assert!(user.prove_multi(&pks, &sigs[..n - 1]).is_err(), "a signature short");
    let mut wrong = sigs.clone();
    wrong.swap(0, 1);
    assert!(user.prove_multi(&pks, &wrong).is_err(), "signatures in the wrong slots");
    let mut wrong = sigs.clone();
    wrong[2] = keys[n].sign(&d, None);
    assert!(user.prove_multi(&pks, &wrong).is_err(), "an outsider's signature");
    assert!(user.prove_multi(&other, &wrong).is_ok(), "the outsider in the key list");
    let mut wrong = sigs.clone();
    wrong[1] = keys[1].sign(&[0u8; 32], None);
    assert!(user.prove_multi(&pks, &wrong).is_err(), "a signature on another message");

    // Proofs do not cross signer counts or the single-signer scheme.
    let (single, single_prover) = build_slh_prover_setup(p).unwrap();
    let mut single_user = SlhUser::with_setup(Arc::new(single), Arc::new(single_prover), &mut rng);
    let com1 = single_user.commit(doc);
    let sig1 = keys[0].sign(&com_digest(&com1), None);
    let proof1 = single_user.prove(&pks[0].pk_seed, &pks[0].pk_root, &sig1).unwrap();
    assert!(verifier.verify(&proof1, doc).is_err());
    let single_verifier =
        SlhVerifier::new(p, Arc::new(build_slh_verifier(p).unwrap()), pks[0].pk_seed, pks[0].pk_root);
    single_verifier.verify(&proof1, doc).unwrap();
    assert!(single_verifier.verify(&proof, doc).is_err());
}
