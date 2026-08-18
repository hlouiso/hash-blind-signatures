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

    let verifier = Verifier::new(signer.public_key(), signer.pk_seed());
    verifier
        .verify(&blind_sig, &message)
        .expect("Blind signature verification failed");

    blind_sig.proof[0] ^= 1;
    verifier
        .verify(&blind_sig, &message)
        .expect_err("a modified proof domain separator must be rejected");
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
    let verifier = Verifier::new(signer.public_key(), signer.pk_seed());
    verifier
        .verify(&blind_sig, &message)
        .expect("ZK verifier must accept a valid blind signature");
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

    let bad_verifier = Verifier::new(wrong_root, signer.pk_seed());
    bad_verifier
        .verify(&blind_sig, &message)
        .expect_err("ZK verifier with wrong root must reject a valid proof");
}
