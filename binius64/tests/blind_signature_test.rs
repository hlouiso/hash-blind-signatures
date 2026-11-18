use blind_xmss_binius64::{
    DIGEST_LEN, Digest, MESSAGE_LEN, Message, PK_SEED_BYTES, Signer, User, Verifier, XmssKeyPair,
    XmssSignature, xmss_verify,
};
use rand::Rng;

const TEST_H: usize = 8;

#[test]
fn blind_signature_roundtrip() {
    let mut rng = rand::rng();
    let message: Vec<u8> = {
        let mut msg = vec![0u8; 5 * 1024];
        rng.fill_bytes(&mut msg);
        msg
    };

    let mut user = User::new(&mut rng);
    let com = user.commit(&message);

    let mut signer = Signer::new(&mut rng, TEST_H);
    let signature = signer.sign(&com).expect("sign failed");

    let mut blind_sig = user.prove(&signature).expect("proof generation failed");

    let verifier = Verifier::new(signer.public_key(), signer.pk_seed(), TEST_H);
    verifier
        .verify(&blind_sig, &message)
        .expect("Blind signature verification failed");

    for suffix in [&[0u8][..], b"trailing proof data".as_slice()] {
        let original_len = blind_sig.proof.len();
        blind_sig.proof.extend_from_slice(suffix);
        verifier
            .verify(&blind_sig, &message)
            .expect_err("signature with trailing bytes must be rejected");
        blind_sig.proof.truncate(original_len);
    }

    let previous_label = b"blind-xmss-binius64-v9-salted-ghash";
    blind_sig.proof[..previous_label.len()].copy_from_slice(previous_label);
    assert!(matches!(
        verifier.verify(&blind_sig, &message),
        Err(blind_xmss_binius64::BlindSigError::Proof(
            blind_xmss_binius64::protocol::verifier::UnifiedVerifyError::InvalidDomainSeparator
        ))
    ));
}

fn make_valid_xmss_sig() -> (XmssKeyPair, XmssSignature, Message) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1234);
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);
    let mut sk_seed = [0u8; 32];
    rng.fill_bytes(&mut sk_seed);
    let mut kp = XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, TEST_H);
    let msg = [0xABu8; MESSAGE_LEN];
    let sig = kp.sign(&mut rng, &msg).expect("sign failed");
    (kp, sig, msg)
}

#[test]
fn native_and_circuit_xmss_agree() {
    let mut rng = rand::rng();
    let message: Vec<u8> = {
        let mut m = vec![0u8; 32];
        rng.fill_bytes(&mut m);
        m
    };

    let mut user = User::new(&mut rng);
    let com = user.commit(&message);

    let mut signer = Signer::new(&mut rng, TEST_H);
    let xmss_sig = signer.sign(&com).expect("sign failed");

    let signed_msg = blind_xmss_binius64::com_digest(&com);
    assert!(
        xmss_verify(&signer.public_key(), &signed_msg, &xmss_sig),
        "native verifier must accept a valid XMSS signature"
    );

    let blind_sig = user.prove(&xmss_sig).expect("prove failed");
    let verifier = Verifier::new(signer.public_key(), signer.pk_seed(), TEST_H);
    verifier
        .verify(&blind_sig, &message)
        .expect("ZK verifier must accept a valid blind signature");

    Verifier::new(signer.public_key(), signer.pk_seed(), TEST_H - 1)
        .verify(&blind_sig, &message)
        .expect_err("ZK verifier must bind the signer's height");
}

#[test]
fn epoch_above_the_real_tree_has_no_proof() {
    // Epoch 2^(h-1) climbs to the same root whatever height is claimed, so
    // under h-1 only the circuit's range check on the epoch stops it.
    let mut rng = rand::rng();
    let message = b"top half of the tree".to_vec();

    let mut user = User::new(&mut rng);
    let com = user.commit(&message);

    let fresh = Signer::new(&mut rng, TEST_H);
    let mut signer = Signer::from_key(
        &fresh.sk_seed(),
        &fresh.pk_seed(),
        1 << (TEST_H - 1),
        TEST_H,
    );
    let mut xmss_sig = signer.sign(&com).expect("sign failed");

    let blind_sig = user.prove(&xmss_sig).expect("prove failed");
    Verifier::new(signer.public_key(), signer.pk_seed(), TEST_H)
        .verify(&blind_sig, &message)
        .expect("epoch 2^(h-1) is a leaf of a height-h tree");

    xmss_sig.height = TEST_H - 1;
    let err = user
        .prove(&xmss_sig)
        .err()
        .expect("the circuit must reject an epoch at or above 2^h");
    assert!(
        format!("{err:?}").contains("epoch_below_height"),
        "rejected by the range check, not elsewhere: {err:?}"
    );
}

#[test]
fn tampered_sig_hash_rejected() {
    let (kp, mut sig, msg) = make_valid_xmss_sig();

    assert!(xmss_verify(&kp.root, &msg, &sig));

    sig.chain_tips[0][0] ^= 0xFF;

    assert!(
        !xmss_verify(&kp.root, &msg, &sig),
        "a tampered chain tip must be rejected by the native verifier"
    );
}

#[test]
fn tampered_auth_path_rejected() {
    let (kp, mut sig, msg) = make_valid_xmss_sig();

    assert!(xmss_verify(&kp.root, &msg, &sig));

    sig.merkle_path[0][0] ^= 0xFF;

    assert!(
        !xmss_verify(&kp.root, &msg, &sig),
        "a tampered authentication path must be rejected by the native verifier"
    );
}

#[test]
fn wrong_xmss_root_rejected() {
    let mut rng = rand::rng();
    let message: Vec<u8> = {
        let mut m = vec![0u8; 32];
        rng.fill_bytes(&mut m);
        m
    };

    let mut user = User::new(&mut rng);
    let com = user.commit(&message);

    let mut signer = Signer::new(&mut rng, TEST_H);
    let xmss_sig = signer.sign(&com).expect("sign failed");
    let blind_sig = user.prove(&xmss_sig).expect("prove failed");

    let signed_msg = blind_xmss_binius64::com_digest(&com);
    let wrong_root: Digest = [0xFFu8; DIGEST_LEN];
    assert!(
        !xmss_verify(&wrong_root, &signed_msg, &xmss_sig),
        "native verifier must reject a signature under the wrong root"
    );

    let bad_verifier = Verifier::new(wrong_root, signer.pk_seed(), TEST_H);
    bad_verifier
        .verify(&blind_sig, &message)
        .expect_err("ZK verifier with wrong root must reject a valid proof");
}
