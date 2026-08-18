use std::sync::Arc;
use std::time::Instant;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

use blind_xmss_binius64::{
    HmCommitment, MultiUser, MultiVerifier, PK_SEED_BYTES, SK_SEED_BYTES, Signer, SignerKey, User,
    Verifier, XMSS_H, XmssSignature, build_prover_setup, build_prover_setup_multi,
    build_verifier_setup, build_verifier_setup_multi, write_blind_sig, write_commitment,
    write_signer_keys, write_signer_pub, write_xmss_sig,
};

const MSG_BYTES: usize = 10 * 1024;
const SEED: u64 = 0xDEAD_BEEF_C0FF_EE01;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn make_document(rng: &mut StdRng) -> Vec<u8> {
    let mut doc = vec![0u8; MSG_BYTES];
    rng.fill_bytes(&mut doc);
    doc
}

fn xmss_h() -> usize {
    env_usize("BENCH_XMSS_H", 10)
}

fn mean_secs(iters: usize, mut f: impl FnMut()) -> f64 {
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    t.elapsed().as_secs_f64() / iters as f64
}

fn print_size(label: &str, bytes: usize) {
    if bytes < 1024 {
        println!("    {label:<38} {bytes:>10} B");
    } else if bytes < 1024 * 1024 {
        println!("    {label:<38} {:>9.2} KB", bytes as f64 / 1024.0);
    } else {
        println!(
            "    {label:<38} {:>9.2} MB",
            bytes as f64 / (1024.0 * 1024.0)
        );
    }
}

fn signer_keys(rng: &mut StdRng, n: usize) -> (Vec<SignerKey>, [u8; PK_SEED_BYTES]) {
    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);
    let keys = (0..n)
        .map(|_| {
            let mut sk_seed = [0u8; SK_SEED_BYTES];
            rng.fill_bytes(&mut sk_seed);
            SignerKey {
                sk_seed,
                next_leaf: 0,
            }
        })
        .collect();
    (keys, pk_seed)
}

fn sign_all(
    keys: &[SignerKey],
    pk_seed: &[u8; PK_SEED_BYTES],
    com: &HmCommitment,
) -> Vec<XmssSignature> {
    keys.par_iter()
        .map(|k| {
            let mut signer = Signer::from_key(&k.sk_seed, pk_seed, k.next_leaf, xmss_h());
            signer.sign(com).expect("sign failed")
        })
        .collect()
}

fn bench_single(iters: usize) -> (f64, f64, usize) {
    let mut rng = StdRng::seed_from_u64(SEED);
    let doc = make_document(&mut rng);

    let t0 = Instant::now();
    let (setup, zk_prover) = build_prover_setup().expect("prover setup");
    let zk_verifier = build_verifier_setup().expect("verifier setup");
    let setup_s = t0.elapsed().as_secs_f64();

    let (keys, pk_seed) = signer_keys(&mut rng, 1);
    let mut user = User::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);

    let commit_s = mean_secs(iters, || {
        user.commit(&doc);
    });
    let com = user.commit(&doc);

    let sign_s = mean_secs(iters, || {
        let mut signer = Signer::from_key(&keys[0].sk_seed, &pk_seed, 0, xmss_h());
        signer.sign(&com).expect("sign failed");
    });

    let xmss_sig = sign_all(&keys, &pk_seed, &com).remove(0);
    let root = xmss_sig.root;
    let verifier = Verifier::with_zk_verifier(Arc::new(zk_verifier), root, pk_seed);

    let sig = user.prove(&xmss_sig).expect("prove failed");
    verifier
        .verify(&sig, &doc)
        .expect("the honest proof must verify");

    let prove_s = mean_secs(iters, || {
        user.prove(&xmss_sig).expect("prove failed");
    });
    let verify_s = mean_secs(iters, || {
        verifier.verify(&sig, &doc).expect("verify failed");
    });

    let proof_bytes = write_blind_sig(&sig).len();

    println!("  one-time setup: circuit {setup_s:.2} s (prover + verifier keys, excluded below)\n");

    println!("  Average execution times (s)");
    println!(
        "    {:<38} {commit_s:>10.4}",
        "Commitment computation (user)"
    );
    println!(
        "    {:<38} {sign_s:>10.4}",
        "Key generation + signature (signer)"
    );
    println!("    {:<38} {prove_s:>10.4}", "Proof generation (user)");
    println!(
        "    {:<38} {verify_s:>10.4}\n",
        "Proof verification (verifier)"
    );

    println!("  Sizes of the main objects");
    print_size(
        "Public key of S (pk)",
        write_signer_pub(&[root], &pk_seed).len(),
    );
    print_size(
        "Secret key of S (sk)",
        write_signer_keys(&keys, &pk_seed, xmss_h()).len(),
    );
    print_size("Commitment M", write_commitment(&com).len());
    print_size("Signature of S", write_xmss_sig(&xmss_sig).len());
    print_size("Final signature (NIZK proof)", proof_bytes);
    println!();

    (prove_s, verify_s, proof_bytes)
}

fn bench_multi(n: usize, iters: usize) -> (f64, f64, usize) {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x55);
    let doc = make_document(&mut rng);

    let (setup, zk_prover) = build_prover_setup_multi(n).expect("multi prover setup");
    let zk_verifier = build_verifier_setup_multi(n).expect("multi verifier setup");

    let mut user = MultiUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
    let com = user.commit(&doc);

    let (keys, pk_seed) = signer_keys(&mut rng, n);
    let sigs = sign_all(&keys, &pk_seed, &com);
    let roots: Vec<blind_xmss_binius64::Digest> = sigs.iter().map(|s| s.root).collect();
    let verifier = MultiVerifier::with_zk_verifier(Arc::new(zk_verifier), roots, pk_seed);

    let sig = user.prove(&sigs).expect("prove failed");
    verifier
        .verify(&sig, &doc)
        .expect("the honest proof must verify");

    let prove_s = mean_secs(iters, || {
        user.prove(&sigs).expect("prove failed");
    });
    let verify_s = mean_secs(iters, || {
        verifier.verify(&sig, &doc).expect("verify failed");
    });

    (prove_s, verify_s, sig.proof.len())
}

fn main() {
    let iters = env_usize("BENCH_ITERS", 10);
    let multi_iters = env_usize("BENCH_MULTI_ITERS", 3);
    let max_signers = env_usize("BENCH_MAX_SIGNERS", 64);

    println!(
        "blind-xmss-binius64 benchmark  ·  {iters} iterations \
         ({multi_iters} per multi-signature row)"
    );
    println!(
        "  message {MSG_BYTES} B  ·  BLAKE3, GF(2^128)  ·  XMSS h={} (path {} in circuit)  \
         ·  WOTS+ v={} w={} target={}\n",
        xmss_h(),
        blind_xmss_binius64::LOG_LIFETIME,
        blind_xmss_binius64::V,
        blind_xmss_binius64::W,
        blind_xmss_binius64::TARGET_SUM,
    );

    let (prove_1, verify_1, size_1) = bench_single(iters);

    println!("  Blind multi-signature as the number of signers n grows");
    println!(
        "    {:>5} {:>18} {:>22} {:>24}",
        "n", "Blind multisig size", "Proof generation (s)", "Proof verification (s)"
    );
    let mut n = 1usize;
    loop {
        let (prove_s, verify_s, size) = if n == 1 {
            (prove_1, verify_1, size_1)
        } else {
            bench_multi(n, multi_iters)
        };
        println!(
            "    {n:>5} {:>15.2} KB {prove_s:>22.3} {verify_s:>24.3}",
            size as f64 / 1024.0
        );
        if n >= max_signers {
            break;
        }
        n *= 2;
    }
}
