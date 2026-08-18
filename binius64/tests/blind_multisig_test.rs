use blind_xmss_binius64::{BlindMultiSigError, MultiUser, MultiVerifier, PK_SEED_BYTES, Signer};
use rand::Rng;
use rayon::prelude::*;

const N_SIGNERS: usize = 3;

const TEST_H: usize = 8;

fn run_signing<R: Rng>(
    rng: &mut R,
    pk_seed: &[u8; PK_SEED_BYTES],
    com: &blind_xmss_binius64::HmCommitment,
    n_signers: usize,
) -> (Vec<Signer>, Vec<blind_xmss_binius64::XmssSignature>) {
    let mut signers: Vec<Signer> = (0..n_signers)
        .map(|_| Signer::with_pk_seed(rng, pk_seed, TEST_H))
        .collect();
    let signatures: Vec<_> = signers
        .par_iter_mut()
        .map(|s| s.sign(com).expect("sign failed"))
        .collect();
    (signers, signatures)
}

fn collect_roots(signers: &[Signer]) -> Vec<blind_xmss_binius64::Digest> {
    signers.iter().map(|s| s.public_key()).collect()
}

#[test]
fn blind_multisig_full_roundtrip() {
    let mut rng = rand::rng();
    let message: Vec<u8> = {
        let mut msg = vec![0u8; 1024];
        rng.fill_bytes(&mut msg);
        msg
    };

    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    let mut user = MultiUser::new(&mut rng, N_SIGNERS);
    let com = user.commit(&message);

    let (signers, signatures) = run_signing(&mut rng, &pk_seed, &com, N_SIGNERS);
    let mut blind_sig = user
        .prove(&signatures)
        .expect("multi-sig proof generation failed");

    let verifier = MultiVerifier::new(collect_roots(&signers), pk_seed);
    verifier
        .verify(&blind_sig, &message)
        .expect("honest blind multi-signature must verify");

    blind_sig.proof[0] ^= 1;
    verifier
        .verify(&blind_sig, &message)
        .expect_err("a modified multi-proof domain separator must be rejected");
}

#[test]
fn blind_multisig_varying_n() {
    for &n in &[1usize, 2, 5] {
        let mut rng = rand::rng();
        let mut pk_seed = [0u8; PK_SEED_BYTES];
        rng.fill_bytes(&mut pk_seed);

        let mut user = MultiUser::new(&mut rng, n);
        assert_eq!(user.n_signers(), n);
        let com = user.commit(b"varying-n");
        let (signers, signatures) = run_signing(&mut rng, &pk_seed, &com, n);
        let blind_sig = user.prove(&signatures).expect("prove failed");

        let verifier = MultiVerifier::new(collect_roots(&signers), pk_seed);
        verifier
            .verify(&blind_sig, b"varying-n")
            .unwrap_or_else(|e| panic!("n={n}: verify failed: {e}"));
    }
}

#[test]
fn rejects_wrong_signer_count() {
    let mut rng = rand::rng();
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    let mut user = MultiUser::new(&mut rng, N_SIGNERS);
    let com = user.commit(b"a message");
    let (_signers, mut signatures) = run_signing(&mut rng, &pk_seed, &com, N_SIGNERS);

    signatures.pop();
    match user.prove(&signatures) {
        Err(BlindMultiSigError::WrongSignerCount { expected, got }) => {
            assert_eq!(expected, N_SIGNERS);
            assert_eq!(got, N_SIGNERS - 1);
        }
        other => panic!("expected WrongSignerCount, got {other:?}"),
    }
}

#[test]
fn rejects_epoch_mismatch() {
    let mut rng = rand::rng();
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    let mut user = MultiUser::new(&mut rng, N_SIGNERS);
    let com = user.commit(b"a message");
    let (mut signers, _initial) = run_signing(&mut rng, &pk_seed, &com, N_SIGNERS);

    let _ = signers[0].sign(&com).expect("second sign failed");

    let signatures: Vec<_> = signers
        .par_iter_mut()
        .map(|s| s.sign(&com).expect("sign failed"))
        .collect();

    assert_ne!(signatures[0].epoch, signatures[1].epoch);

    match user.prove(&signatures) {
        Err(BlindMultiSigError::EpochMismatch { signer, .. }) => {
            assert!(signer > 0, "first mismatch should be signer 1+, got 0");
        }
        Ok(_) => panic!("expected epoch mismatch but proof succeeded"),
        Err(e) => panic!("expected EpochMismatch, got {e:?}"),
    }
}

#[test]
fn rejects_swapped_signatures() {
    let mut rng = rand::rng();
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    let mut user = MultiUser::new(&mut rng, N_SIGNERS);
    let com = user.commit(b"swap test");
    let (signers, mut signatures) = run_signing(&mut rng, &pk_seed, &com, N_SIGNERS);

    let roots = collect_roots(&signers);

    signatures.swap(0, 1);

    match user.prove(&signatures) {
        Ok(blind_sig) => {
            let verifier = MultiVerifier::new(roots, pk_seed);
            verifier
                .verify(&blind_sig, b"swap test")
                .expect_err("swapped signatures must be rejected by the verifier");
        }
        Err(BlindMultiSigError::Prover(_)) => {}
        Err(e) => panic!("unexpected error from prove(): {e:?}"),
    }
}

#[test]
fn rejects_wrong_root() {
    let mut rng = rand::rng();
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);

    let mut user = MultiUser::new(&mut rng, N_SIGNERS);
    let message = b"wrong-root";
    let com = user.commit(message);
    let (signers, signatures) = run_signing(&mut rng, &pk_seed, &com, N_SIGNERS);
    let blind_sig = user.prove(&signatures).expect("prove failed");

    let mut roots = collect_roots(&signers);
    *roots.last_mut().unwrap() = [0xAAu8; blind_xmss_binius64::DIGEST_LEN];

    let bad_verifier = MultiVerifier::new(roots, pk_seed);
    bad_verifier
        .verify(&blind_sig, message)
        .expect_err("verifier with one wrong root must reject");
}
