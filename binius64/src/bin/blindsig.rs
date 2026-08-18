use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

use blind_xmss_binius64::{
    LOG_LIFETIME, MultiUser, MultiVerifier, PK_SEED_BYTES, SK_SEED_BYTES, Signer, SignerKey, User,
    Verifier, XMSS_H, XmssSignature, build_prover_setup, build_prover_setup_multi,
    build_verifier_setup, build_verifier_setup_multi, com_digest, read_blind_sig, read_commitment,
    read_signer_keys, read_signer_pub, read_user_state, read_xmss_sigs, write_blind_sig,
    write_commitment, write_signer_keys, write_signer_pub, write_user_state, write_xmss_sigs,
};

struct Options {
    dir: PathBuf,
    signers: usize,
    height: usize,
    msg_file: Option<PathBuf>,
}

impl Options {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    fn msg(&self) -> Result<Vec<u8>> {
        let path = self.msg_file.as_ref().expect("checked by the parser");
        read_file(path)
    }
}

const USAGE: &str = "\
usage: blindsig <command> [options]

commands:
  keygen                signer:   generate XMSS key pair(s)
  commit <msg_file>     user:     commit to a message (round 1)
  sign                  signer:   sign the commitment (round 1 reply)
  prove                 user:     build the blind signature (round 2)
  verify <msg_file>     verifier: check the blind signature

options:
  -d, --dir <path>      directory holding the artefacts (default \".\")
  -n, --signers <n>     number of signers (keygen only, default 1); n > 1
                        selects the blind multi-signature
      --height <h>      real XMSS tree height (keygen only, default 10, max 32).
                        Keygen sweeps every one of the 2^h leaves and the signer
                        repeats that sweep on every invocation, so raising this
                        costs time on both; the circuit climbs 32 levels either
                        way.
  -h, --help
";

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("cannot write {}", path.display()))
}

fn os_rng() -> StdRng {
    StdRng::from_rng(&mut rand::rng())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn kb(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    }
}

fn cmd_keygen(opt: &Options) -> Result<()> {
    let n = opt.signers;
    let mut rng = os_rng();

    let mut pk_seed = [0u8; PK_SEED_BYTES];
    rng.fill_bytes(&mut pk_seed);
    let sk_seeds: Vec<[u8; SK_SEED_BYTES]> = (0..n)
        .map(|_| {
            let mut s = [0u8; SK_SEED_BYTES];
            rng.fill_bytes(&mut s);
            s
        })
        .collect();

    let t0 = Instant::now();
    let roots: Vec<blind_xmss_binius64::Digest> = sk_seeds
        .par_iter()
        .map(|sk| Signer::from_key(sk, &pk_seed, 0, opt.height).public_key())
        .collect();
    let keygen_s = t0.elapsed().as_secs_f64();

    let keys: Vec<SignerKey> = sk_seeds
        .iter()
        .map(|&sk_seed| SignerKey {
            sk_seed,
            next_leaf: 0,
        })
        .collect();
    let key_bytes = write_signer_keys(&keys, &pk_seed, opt.height);
    let pub_bytes = write_signer_pub(&roots, &pk_seed);
    write_file(&opt.path("signer_key.bin"), &key_bytes)?;
    write_file(&opt.path("signer_pub.bin"), &pub_bytes)?;

    println!(
        "keygen  ·  {n} signer{}  ·  XMSS h={} ({} one-time signatures each)  {:.0} ms",
        if n == 1 { "" } else { "s" },
        opt.height,
        1u64 << opt.height,
        keygen_s * 1e3
    );
    for (i, root) in roots.iter().enumerate() {
        println!("  root[{i}]  : {}", hex(root));
    }
    println!("  pk_seed  : {}", hex(&pk_seed));
    println!("  → signer_key.bin ({}, secret)", kb(key_bytes.len()));
    println!("  → signer_pub.bin ({})", kb(pub_bytes.len()));
    Ok(())
}

fn cmd_commit(opt: &Options) -> Result<()> {
    let msg = opt.msg()?;

    let mut rng = os_rng();
    let t0 = Instant::now();
    let (com, opening) = blind_xmss_binius64::commitment::sample_commitment(&mut rng, &msg);
    let commit_ms = t0.elapsed().as_secs_f64() * 1e3;

    let state = blind_xmss_binius64::UserState {
        opening,
        com: com.clone(),
    };
    let com_bytes = write_commitment(&com);
    let state_bytes = write_user_state(&state);
    write_file(&opt.path("commitment.bin"), &com_bytes)?;
    write_file(&opt.path("user_state.bin"), &state_bytes)?;

    println!("commit  ·  message {} B  {commit_ms:.1} ms", msg.len());
    println!(
        "  → commitment.bin ({}, send to the signer(s))",
        kb(com_bytes.len())
    );
    println!("  → user_state.bin ({}, secret)", kb(state_bytes.len()));
    Ok(())
}

fn cmd_sign(opt: &Options) -> Result<()> {
    let (keys, pk_seed, height) = read_signer_keys(&read_file(&opt.path("signer_key.bin"))?)
        .context("malformed signer_key.bin")?;
    let com = read_commitment(&read_file(&opt.path("commitment.bin"))?)
        .context("malformed commitment.bin")?;

    let epoch = keys[0].next_leaf;
    if let Some(i) = keys.iter().position(|k| k.next_leaf != epoch) {
        bail!(
            "signers are out of lockstep: signer 0 is at leaf {epoch}, signer {i} at leaf {}",
            keys[i].next_leaf
        );
    }
    if epoch >= 1u64 << height {
        bail!("key exhausted: all {} leaves used", 1u64 << height);
    }

    let t0 = Instant::now();
    let sigs: Vec<XmssSignature> = keys
        .par_iter()
        .map(|k| {
            let mut signer = Signer::from_key(&k.sk_seed, &pk_seed, k.next_leaf, height);
            signer.sign(&com)
        })
        .collect::<std::result::Result<_, _>>()
        .context("signing failed")?;
    let sign_s = t0.elapsed().as_secs_f64();

    let advanced: Vec<SignerKey> = keys
        .iter()
        .map(|k| SignerKey {
            sk_seed: k.sk_seed,
            next_leaf: k.next_leaf + 1,
        })
        .collect();
    let sig_bytes = write_xmss_sigs(&sigs);
    write_file(&opt.path("xmss_sig.bin"), &sig_bytes)?;
    write_file(
        &opt.path("signer_key.bin"),
        &write_signer_keys(&advanced, &pk_seed, height),
    )?;

    println!(
        "sign  ·  {} signature{} at leaf {epoch} of {}  {:.0} ms",
        keys.len(),
        if keys.len() == 1 { "" } else { "s" },
        1u64 << height,
        sign_s * 1e3
    );
    println!(
        "  → xmss_sig.bin ({}, send to the user)",
        kb(sig_bytes.len())
    );
    println!(
        "  signer_key.bin updated: next_leaf = {} ({} left)",
        epoch + 1,
        (1u64 << height) - (epoch + 1)
    );
    Ok(())
}

fn cmd_prove(opt: &Options) -> Result<()> {
    let state = read_user_state(&read_file(&opt.path("user_state.bin"))?)
        .context("malformed user_state.bin")?;
    let (roots, pk_seed) = read_signer_pub(&read_file(&opt.path("signer_pub.bin"))?)
        .context("malformed signer_pub.bin")?;

    let d = com_digest(&state.com);
    let sig_bytes = read_file(&opt.path("xmss_sig.bin"))?;
    let sigs = read_xmss_sigs(&sig_bytes, &pk_seed, &d)
        .context("xmss_sig.bin is not a signature on this commitment under signer_pub.bin")?;

    if sigs.len() != roots.len() {
        bail!(
            "xmss_sig.bin holds {} signature(s) but signer_pub.bin names {} signer(s)",
            sigs.len(),
            roots.len()
        );
    }

    for (i, (sig, root)) in sigs.iter().zip(&roots).enumerate() {
        if &sig.root != root {
            bail!("signature {i} does not verify under signer_pub.bin (recomputed root differs)");
        }
    }

    let n = roots.len();
    println!("prove  ·  {n} signer{}", if n == 1 { "" } else { "s" });

    let mut rng = os_rng();
    let t0 = Instant::now();
    let (proof, prove_s) = if n == 1 {
        let (setup, zk_prover) = build_prover_setup().context("prover setup")?;
        println!(
            "  circuit  : built in {:.0} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
        let mut user = User::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
        user.restore(state);
        let t1 = Instant::now();
        let sig = user.prove(&sigs[0]).map_err(|e| anyhow::anyhow!("{e}"))?;
        (write_blind_sig(&sig), t1.elapsed().as_secs_f64())
    } else {
        let (setup, zk_prover) = build_prover_setup_multi(n).context("multi prover setup")?;
        println!(
            "  circuit  : built in {:.0} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
        let mut user = MultiUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
        user.restore(state);
        let t1 = Instant::now();
        let sig = user.prove(&sigs).map_err(|e| anyhow::anyhow!("{e}"))?;
        (sig.proof, t1.elapsed().as_secs_f64())
    };

    write_file(&opt.path("blind_sig.bin"), &proof)?;
    println!(
        "  → blind_sig.bin ({})  {:.0} ms",
        kb(proof.len()),
        prove_s * 1e3
    );
    Ok(())
}

fn cmd_verify(opt: &Options) -> Result<()> {
    let msg = opt.msg()?;
    let (roots, pk_seed) = read_signer_pub(&read_file(&opt.path("signer_pub.bin"))?)
        .context("malformed signer_pub.bin")?;
    let proof = read_file(&opt.path("blind_sig.bin"))?;

    let n = roots.len();
    println!("verify  ·  {n} signer{}", if n == 1 { "" } else { "s" });

    let t0 = Instant::now();
    let (ok, verify_s) = if n == 1 {
        let zk_verifier = build_verifier_setup().context("verifier setup")?;
        println!(
            "  circuit  : built in {:.0} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
        let verifier = Verifier::with_zk_verifier(Arc::new(zk_verifier), roots[0], pk_seed);
        let t1 = Instant::now();
        let ok = verifier.verify(&read_blind_sig(&proof), &msg).is_ok();
        (ok, t1.elapsed().as_secs_f64())
    } else {
        let zk_verifier = build_verifier_setup_multi(n).context("multi verifier setup")?;
        println!(
            "  circuit  : built in {:.0} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
        let verifier = MultiVerifier::with_zk_verifier(Arc::new(zk_verifier), roots, pk_seed);
        let sig = blind_xmss_binius64::BlindMultiSignature {
            proof: proof.clone(),
        };
        let t1 = Instant::now();
        let ok = verifier.verify(&sig, &msg).is_ok();
        (ok, t1.elapsed().as_secs_f64())
    };

    println!(
        "  [{}]  {}  {:.0} ms",
        if ok { "PASS" } else { "FAIL" },
        kb(proof.len()),
        verify_s * 1e3
    );
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print!("{USAGE}");
        std::process::exit(1);
    }
    let cmd = args[0].clone();
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(());
    }

    let mut opt = Options {
        dir: PathBuf::from("."),
        signers: 1,
        height: XMSS_H,
        msg_file: None,
    };
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "-d" | "--dir" => {
                i += 1;
                let v = args.get(i).context("--dir needs a value")?;
                opt.dir = PathBuf::from(v);
            }
            "-n" | "--signers" => {
                i += 1;
                let v = args.get(i).context("--signers needs a value")?;
                opt.signers = v.parse().context("--signers takes a positive integer")?;
                if opt.signers == 0 {
                    bail!("--signers must be at least 1");
                }
            }
            "--height" => {
                i += 1;
                let v = args.get(i).context("--height needs a value")?;
                opt.height = v.parse().context("--height takes an integer")?;
                if !(1..=LOG_LIFETIME).contains(&opt.height) {
                    bail!("--height must be in 1..={LOG_LIFETIME}");
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            _ if arg.starts_with('-') => bail!("unknown option: {arg}"),
            _ if opt.msg_file.is_none() => opt.msg_file = Some(PathBuf::from(&arg)),
            _ => bail!("too many positional arguments"),
        }
        i += 1;
    }

    let needs_msg = matches!(cmd.as_str(), "commit" | "verify");
    if needs_msg && opt.msg_file.is_none() {
        bail!("{cmd} needs a <msg_file>");
    }
    if !needs_msg && opt.msg_file.is_some() {
        bail!("{cmd} takes no positional arguments");
    }

    match cmd.as_str() {
        "keygen" => cmd_keygen(&opt),
        "commit" => cmd_commit(&opt),
        "sign" => cmd_sign(&opt),
        "prove" => cmd_prove(&opt),
        "verify" => cmd_verify(&opt),
        other => {
            eprintln!("unknown command: {other}\n");
            print!("{USAGE}");
            std::process::exit(1);
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
