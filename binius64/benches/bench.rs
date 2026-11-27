//! Benchmarks of the blind signature, stateful (XMSS) by default or stateless
//! (SLH-DSA-SHA2) with `--stateless`, like `blindsig keygen`.
//!
//! Both use a 10,240-byte document. Proof generation is the user's final
//! round with witness generation included, verification is the
//! blind-signature verifier, each the mean of BENCH_ITERS runs (default 10).
//!
//! Upstream Binius64 at 487127b4 indexes its wiring matrix with 63 bits, so
//! a circuit above about 2^20 AND constraints is reported as unsupported and
//! ends the run or sweep.
//!
//! Stateful: the single-signer figures, then the blind multi-signature as n
//! doubles up to BENCH_MAX_SIGNERS (default 64, the first n past the
//! capacity), BENCH_MULTI_ITERS runs per row (default 3). Keys have the
//! fixed height 24, so each takes about a minute to generate; that is done
//! once per signer, excluded from the timings, and the sweep reuses the keys
//! as n grows. Signing is timed as `blindsig sign` does it, from the stored
//! top levels.
//!
//!   RUSTFLAGS="-C target-cpu=native" RAYON_NUM_THREADS=8 BENCH_MULTI_ITERS=10 \
//!     cargo bench --bench bench
//!
//! Stateless: SLH-DSA-SHA2-128-24, SIGN_ITERS signatures for the signer's
//! timing (default 3). With `multi`, it runs the stateless blind
//! multi-signature instead: n independent SLH-DSA keys sign one commitment
//! and one proof verifies all n signatures, for n = BENCH_MIN_SIGNERS,
//! 2 BENCH_MIN_SIGNERS, ... up to BENCH_MAX_SIGNERS (defaults 1 and 8, the
//! first n past the capacity), BENCH_MULTI_ITERS runs per row (default 3).
//! Key generation and signing are excluded from the proof timings.
//!
//!   RUSTFLAGS="-C target-cpu=native" RAYON_NUM_THREADS=8 \
//!     cargo bench --bench bench -- --stateless [multi]

use std::sync::Arc;
use std::time::Instant;

use binius_frontend::CircuitStat;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

use blind_xmss_binius64::setup::{LOG_INV_RATE, WiringCapacityError};
use blind_xmss_binius64::xmss::cache_split_height;
use blind_xmss_binius64::slh::commit::com_digest;
use blind_xmss_binius64::slh::native::{Node, SlhCtx, SlhKey, SlhSignature, pure_message};
use blind_xmss_binius64::slh::protocol::{
    SlhPublicKey, SlhUser, SlhVerifier, build_slh_prover_setup, build_slh_prover_setup_multi,
    build_slh_verifier, build_slh_verifier_multi,
};
use blind_xmss_binius64::slh::{SLH_DSA_SHA2_128_24, SlhParams};
use blind_xmss_binius64::{
    HmCommitment, LOG_LIFETIME, MultiUser, MultiVerifier, PK_SEED_BYTES, SK_SEED_BYTES, Signer,
    SignerKey, User,
    Verifier, XmssSignature, build_prover_setup, build_prover_setup_multi, build_verifier_setup,
    build_verifier_setup_multi, write_blind_sig, write_commitment,
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
        println!("    {label:<38} {:>8.2} KiB", bytes as f64 / 1024.0);
    } else {
        println!(
            "    {label:<38} {:>8.2} MiB",
            bytes as f64 / (1024.0 * 1024.0)
        );
    }
}

/// The signers' keys at the fixed height, generated once and grown as the
/// multi-signature sweep needs more. They share one pk_seed, and each keeps
/// only its top levels, as signer_cache.bin does.
struct SignerPool {
    rng: StdRng,
    pk_seed: [u8; PK_SEED_BYTES],
    keys: Vec<Signer>,
    next_epoch: u64,
}

impl SignerPool {
    fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut pk_seed = [0u8; PK_SEED_BYTES];
        rng.fill_bytes(&mut pk_seed);
        Self {
            rng,
            pk_seed,
            keys: Vec::new(),
            next_epoch: 0,
        }
    }

    /// Generates keys until there are `n`; returns the seconds per key.
    fn grow(&mut self, n: usize) -> Option<f64> {
        let mut last = None;
        while self.keys.len() < n {
            let mut sk_seed = [0u8; SK_SEED_BYTES];
            self.rng.fill_bytes(&mut sk_seed);
            let t = Instant::now();
            let split = cache_split_height(LOG_LIFETIME);
            let key = Signer::from_key_split(&sk_seed, &self.pk_seed, 0, LOG_LIFETIME, split);
            let secs = t.elapsed().as_secs_f64();
            eprintln!(
                "  keygen: signer {} at h = {LOG_LIFETIME} in {secs:.1} s (excluded)",
                self.keys.len()
            );
            self.keys.push(key);
            last = Some(secs);
        }
        last
    }

    /// The first `n` signers at one fresh, shared epoch, each resumed from its
    /// top levels as `blindsig sign` does from signer_cache.bin.
    fn session(&mut self, n: usize) -> Vec<Signer> {
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.keys[..n]
            .par_iter()
            .map(|k| {
                Signer::from_top_levels(
                    &k.sk_seed(),
                    &self.pk_seed,
                    epoch,
                    LOG_LIFETIME,
                    k.subtree_height(),
                    k.top_levels().to_vec(),
                )
                .expect("the key's own top levels")
            })
            .collect()
    }

    fn roots(&self, n: usize) -> Vec<blind_xmss_binius64::Digest> {
        self.keys[..n].iter().map(Signer::public_key).collect()
    }
}

fn sign_all(signers: &mut [Signer], com: &HmCommitment) -> Vec<XmssSignature> {
    signers
        .par_iter_mut()
        .map(|s| s.sign(com).expect("sign failed"))
        .collect()
}

fn bench_single(iters: usize, pool: &mut SignerPool) -> (f64, f64, usize) {
    let mut rng = StdRng::seed_from_u64(SEED);
    let doc = make_document(&mut rng);

    let t0 = Instant::now();
    let (setup, zk_prover) = build_prover_setup().expect("prover setup");
    let zk_verifier = build_verifier_setup().expect("verifier setup");
    let setup_s = t0.elapsed().as_secs_f64();
    let stat = CircuitStat::collect(&setup.circuit);
    println!(
        "  {} AND constraints, {} committed words, BaseFold rate 1/{}",
        stat.n_and_constraints,
        stat.committed_allocated,
        1usize << LOG_INV_RATE
    );

    let keygen_s = pool.grow(1);
    let pk_seed = pool.pk_seed;
    let root = pool.roots(1)[0];
    let mut user = User::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);

    let commit_s = mean_secs(iters, || {
        user.commit(&doc);
    });
    let com = user.commit(&doc);

    let xmss_sig = sign_all(&mut pool.session(1), &com).remove(0);
    let sign_s = mean_secs(iters, || {
        sign_all(&mut pool.session(1), &com);
    });
    let verifier =
        Verifier::with_zk_verifier(Arc::new(zk_verifier), root, pk_seed, LOG_LIFETIME);

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

    println!("  one-time setup: circuit {setup_s:.2} s (prover + verifier keys, excluded below)");
    if let Some(k) = keygen_s {
        println!("  one-time keygen: {k:.2} s for the 2^{LOG_LIFETIME} leaves (excluded below)");
    }
    println!();

    println!("  Average execution times (s)");
    println!(
        "    {:<38} {commit_s:>10.4}",
        "Commitment computation (user)"
    );
    println!(
        "    {:<38} {sign_s:>10.4}",
        "Signature from cached top levels"
    );
    println!("    {:<38} {prove_s:>10.4}", "Proof generation (user)");
    println!(
        "    {:<38} {verify_s:>10.4}\n",
        "Proof verification (verifier)"
    );

    let key = SignerKey {
        sk_seed: pool.keys[0].sk_seed(),
        next_leaf: pool.next_epoch,
    };
    println!("  Sizes of the main objects");
    print_size(
        "Public key of S (pk)",
        write_signer_pub(&[root], &pk_seed, LOG_LIFETIME).len(),
    );
    print_size(
        "Secret key of S (sk)",
        write_signer_keys(&[key], &pk_seed, LOG_LIFETIME).len(),
    );
    print_size("Commitment M", write_commitment(&com).len());
    print_size("Signature of S", write_xmss_sig(&xmss_sig).len());
    print_size("Final signature (NIZK proof)", proof_bytes);
    println!();

    (prove_s, verify_s, proof_bytes)
}

fn bench_multi(
    n: usize,
    iters: usize,
    pool: &mut SignerPool,
) -> anyhow::Result<(f64, f64, usize)> {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x55);
    let doc = make_document(&mut rng);

    let (setup, zk_prover) = build_prover_setup_multi(n)?;
    let zk_verifier = build_verifier_setup_multi(n)?;

    let mut user = MultiUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
    let com = user.commit(&doc);

    pool.grow(n);
    let sigs = sign_all(&mut pool.session(n), &com);
    let verifier = MultiVerifier::with_zk_verifier(
        Arc::new(zk_verifier),
        pool.roots(n),
        pool.pk_seed,
        LOG_LIFETIME,
    );

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

    Ok((prove_s, verify_s, sig.proof.len()))
}

fn run_stateful() {
    let iters = env_usize("BENCH_ITERS", 10);
    let multi_iters = env_usize("BENCH_MULTI_ITERS", 3);
    let max_signers = env_usize("BENCH_MAX_SIGNERS", 64);

    println!(
        "blind-xmss-binius64 benchmark  ·  {iters} iterations \
         ({multi_iters} per multi-signature row)"
    );
    println!(
        "  message {MSG_BYTES} B  ·  SHA-256, GF(2^128)  ·  XMSS h={LOG_LIFETIME}  \
         ·  WOTS+ v={} w={} target={}\n",
        blind_xmss_binius64::V,
        blind_xmss_binius64::CHAIN_LENGTH,
        blind_xmss_binius64::TARGET_SUM,
    );

    let mut pool = SignerPool::new(SEED ^ 0x5157);
    let (prove_1, verify_1, size_1) = bench_single(iters, &mut pool);

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
            match bench_multi(n, multi_iters, &mut pool) {
                Ok(result) => result,
                Err(err) if err.is::<WiringCapacityError>() => {
                    println!("    {n:>5} unsupported: {err}");
                    break;
                }
                Err(err) => panic!("multi-signer benchmark failed: {err:#}"),
            }
        };
        println!(
            "    {n:>5} {:>14.2} KiB {prove_s:>22.3} {verify_s:>24.3}",
            size as f64 / 1024.0
        );
        if n >= max_signers {
            break;
        }
        n *= 2;
    }
}

// Stateless: SLH-DSA-SHA2 as the underlying signature.

fn node(rng: &mut impl Rng) -> Node {
    let mut n = [0u8; 16];
    rng.fill_bytes(&mut n);
    n
}

fn bench_slh(p: SlhParams, iters: usize, sign_iters: usize) {
    println!("== {}  (signature {} B)", p.name, p.sig_bytes());
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut doc = vec![0u8; MSG_BYTES];
    rng.fill_bytes(&mut doc);

    let t = Instant::now();
    let key = SlhKey::keygen_internal(p, &node(&mut rng), &node(&mut rng), &node(&mut rng));
    let keygen_s = t.elapsed().as_secs_f64();
    let (pk_seed, pk_root) = (*key.pk_seed(), key.pk_root);

    let t = Instant::now();
    let (setup, zk_prover) = build_slh_prover_setup(p).expect("prover setup");
    let zk_verifier = build_slh_verifier(p).expect("verifier setup");
    let setup_s = t.elapsed().as_secs_f64();
    let stat = CircuitStat::collect(&setup.circuit);

    let mut user = SlhUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
    let verifier = SlhVerifier::new(p, Arc::new(zk_verifier), pk_seed, pk_root);
    let com = user.commit(&doc);
    let d = com_digest(&com);

    let ctx = SlhCtx::new(p, &pk_seed);
    let mut sig = None;
    let mut calls = 0u64;
    let sign_s = mean_secs(sign_iters, || {
        let s = key.sign(&d, Some(&node(&mut rng)));
        let (ok, stats) = ctx.verify_internal(&pk_root, &pure_message(&d, &[]), &s);
        assert!(ok, "native verification");
        calls += stats.hash_calls();
        sig = Some(s);
    });
    let sig = sig.unwrap();
    let native_verify_s = mean_secs(iters, || {
        assert!(ctx.verify_internal(&pk_root, &pure_message(&d, &[]), &sig).0);
    });

    let proof = user.prove(&pk_seed, &pk_root, &sig).expect("prove");
    verifier.verify(&proof, &doc).expect("the honest proof must verify");
    assert!(verifier.verify(&proof, b"another document").is_err());

    let prove_s = mean_secs(iters, || {
        user.prove(&pk_seed, &pk_root, &sig).expect("prove");
    });
    let verify_s = mean_secs(iters, || {
        verifier.verify(&proof, &doc).expect("verify");
    });

    println!(
        "  circuit: AND {}  BMUL {}  ZERO {}  committed trace 2^{} words  (setup {setup_s:.2} s, excluded)",
        stat.n_and_constraints,
        stat.n_bmul_constraints,
        stat.n_zero_constraints,
        stat.committed_allocated.trailing_zeros(),
    );
    println!(
        "  signer:  keygen {keygen_s:.2} s   sign {sign_s:.3} s (mean of {sign_iters})   native verify {:.3} ms, {:.0} hash calls",
        native_verify_s * 1e3,
        calls as f64 / sign_iters as f64,
    );
    println!("  Proof generation (user)    {prove_s:>8.4} s");
    println!("  Proof verification         {verify_s:>8.4} s");
    println!(
        "  Blind signature            {:>8.2} KB  ({} bytes)\n",
        proof.len() as f64 / 1000.0,
        proof.len()
    );
}

fn bench_slh_multi(p: SlhParams, min_n: usize, max_n: usize, iters: usize) {
    println!(
        "== {} blind multi-signature  (stateless: n independent keys, one commitment, one proof)",
        p.name
    );
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x55);
    let mut doc = vec![0u8; MSG_BYTES];
    rng.fill_bytes(&mut doc);

    let seeds: Vec<[Node; 3]> = (0..max_n)
        .map(|_| [node(&mut rng), node(&mut rng), node(&mut rng)])
        .collect();
    let t = Instant::now();
    let keys: Vec<SlhKey> = seeds
        .par_iter()
        .map(|[sk_seed, sk_prf, pk_seed]| SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed))
        .collect();
    println!(
        "  keygen: {max_n} key{} in {:.2} s (excluded)",
        if max_n == 1 { "" } else { "s" },
        t.elapsed().as_secs_f64()
    );
    println!("  {iters} iterations per row; setup and signing excluded from the proof timings\n");
    println!(
        "  {:>4} {:>9} {:>7} {:>11} {:>11} {:>9} {:>10} {:>10} {:>9} {:>9}",
        "n", "AND", "trace", "size (B)", "size (KB)", "KiB", "prove (s)", "verify (s)", "setup (s)", "sign (s)"
    );

    let mut n = min_n;
    while n <= max_n {
        let t = Instant::now();
        let built = build_slh_prover_setup_multi(p, n)
            .and_then(|(setup, zk_prover)| Ok((setup, zk_prover, build_slh_verifier_multi(p, n)?)));
        let (setup, zk_prover, zk_verifier) = match built {
            Ok(x) => x,
            Err(err) if err.is::<WiringCapacityError>() => {
                println!("  {n:>4} unsupported: {err}");
                break;
            }
            Err(err) => panic!("multi-signer setup failed at n = {n}: {err:#}"),
        };
        let setup_s = t.elapsed().as_secs_f64();
        let stat = CircuitStat::collect(&setup.circuit);

        let mut user = SlhUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
        let com = user.commit(&doc);
        let d = com_digest(&com);
        let addrnd: Vec<Node> = (0..n).map(|_| node(&mut rng)).collect();
        let t = Instant::now();
        let sigs: Vec<SlhSignature> = keys[..n]
            .par_iter()
            .zip(&addrnd)
            .map(|(k, r)| k.sign(&d, Some(r)))
            .collect();
        let sign_s = t.elapsed().as_secs_f64();
        let pks: Vec<SlhPublicKey> = keys[..n]
            .iter()
            .map(|k| SlhPublicKey {
                pk_seed: *k.pk_seed(),
                pk_root: k.pk_root,
            })
            .collect();
        let verifier = SlhVerifier::new_multi(p, Arc::new(zk_verifier), pks.clone());

        let proof = user.prove_multi(&pks, &sigs).expect("prove");
        verifier.verify(&proof, &doc).expect("the honest proof must verify");
        assert!(verifier.verify(&proof, b"another document").is_err());

        let prove_s = mean_secs(iters, || {
            user.prove_multi(&pks, &sigs).expect("prove");
        });
        let verify_s = mean_secs(iters, || {
            verifier.verify(&proof, &doc).expect("verify");
        });

        println!(
            "  {n:>4} {:>9} {:>7} {:>11} {:>11.2} {:>9.2} {prove_s:>10.4} {verify_s:>10.4} {setup_s:>9.2} {sign_s:>9.2}",
            stat.n_and_constraints,
            format!("2^{}", stat.committed_allocated.trailing_zeros()),
            proof.len(),
            proof.len() as f64 / 1000.0,
            proof.len() as f64 / 1024.0,
        );
        n *= 2;
    }
    println!();
}

fn run_stateless(multi: bool) {
    let p = SLH_DSA_SHA2_128_24;
    let threads = rayon::current_num_threads();
    if multi {
        let min_n = env_usize("BENCH_MIN_SIGNERS", 1);
        let max_n = env_usize("BENCH_MAX_SIGNERS", 8).max(min_n);
        let multi_iters = env_usize("BENCH_MULTI_ITERS", 3);
        println!(
            "Blind multi-signature over SLH-DSA, Binius64 at 487127b4, {threads} threads, \
             n = {min_n}..{max_n} (doubling)\n"
        );
        bench_slh_multi(p, min_n, max_n, multi_iters);
        return;
    }
    let iters = env_usize("BENCH_ITERS", 10);
    let sign_iters = env_usize("SIGN_ITERS", 3);
    println!(
        "Blind signature over SLH-DSA, Binius64 at 487127b4, {threads} threads, {iters} iterations\n"
    );
    bench_slh(p, iters, sign_iters);
}

const USAGE: &str = "usage: cargo bench --bench bench -- [--stateful | --stateless [multi]]";

fn main() {
    let mut stateless = false;
    let mut multi = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            // `cargo bench` passes --bench to every harness = false target.
            "--bench" => {}
            "--stateful" => stateless = false,
            "--stateless" => stateless = true,
            "multi" => multi = true,
            _ => {
                eprintln!("bench: unknown argument `{arg}`\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    if !stateless && multi {
        eprintln!("bench: `multi` needs --stateless\n{USAGE}");
        std::process::exit(2);
    }
    if stateless {
        run_stateless(multi);
    } else {
        run_stateful();
    }
}
