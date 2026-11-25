use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;

use blind_xmss_binius64::slh::native::{HashFamily, Node, SlhKey, SlhSignature, slh_verify};
use blind_xmss_binius64::slh::{SLH_DSA_SHA2_128_24, SlhParams};
use blind_xmss_binius64::xmss::cache_split_height;
use blind_xmss_binius64::slh::protocol::{
    SlhUser, SlhVerifier, build_slh_prover_setup_multi, build_slh_verifier_multi, slh_commit,
};
use blind_xmss_binius64::slh::serialize::{
    SLH_KEY_MAGIC, SLH_PUB_MAGIC, SLH_STATE_MAGIC, SlhSecretKey, has_magic, read_slh_keys,
    read_slh_pub, read_slh_sigs, read_slh_user_state, write_slh_keys, write_slh_pub,
    write_slh_sigs, write_slh_user_state,
};
use blind_xmss_binius64::{
    Digest, LOG_LIFETIME, MultiUser, MultiVerifier, PK_SEED_BYTES, SK_SEED_BYTES, Signer,
    SignerKey, User,
    Verifier, XMSS_H, XmssSignature, build_prover_setup, build_prover_setup_multi,
    build_verifier_setup, build_verifier_setup_multi, com_digest, read_blind_sig, read_commitment,
    read_signer_keys, read_signer_pub, read_user_state, read_xmss_sigs, write_blind_sig,
    write_commitment, write_signer_keys, write_signer_pub, write_user_state, write_xmss_sigs,
};

/// The underlying signature scheme, chosen at keygen and recorded in the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    /// XMSS: each signature consumes a leaf, so the secret key is rewritten.
    Stateful,
    /// SLH-DSA-SHA2-128-24: the secret key never changes.
    Stateless,
}

impl Scheme {
    fn name(self) -> &'static str {
        match self {
            Scheme::Stateful => "stateful (XMSS)",
            Scheme::Stateless => "stateless (SLH-DSA-SHA2-128-24)",
        }
    }
}

struct Options {
    dir: PathBuf,
    signers: usize,
    height: usize,
    height_set: bool,
    scheme: Option<Scheme>,
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
  keygen                signer:   generate the key pair(s)
  commit <msg_file>     user:     commit to a message (round 1)
  sign                  signer:   sign the commitment (round 1 reply)
  prove                 user:     build the blind signature (round 2)
  verify <msg_file>     verifier: check the blind signature

options:
  -d, --dir <path>      directory holding the artefacts (default \".\")
      --stateful        keygen only, the default: XMSS underneath. Each
                        signature consumes a leaf, and sign rewrites
                        signer_key.bin.
      --stateless       keygen only: SLH-DSA-SHA2-128-24 underneath. sign
                        never rewrites signer_key.bin. The other commands
                        follow the scheme recorded in the key files.
                        In both schemes keygen also writes signer_cache.bin,
                        the upper levels of the signer's tree, so that sign
                        rebuilds one small subtree instead of the whole key;
                        without it, sign rebuilds the key and rewrites it.
  -n, --signers <n>     number of signers (keygen only, default 1); n > 1
                        selects the blind multi-signature
      --height <h>      real XMSS tree height (stateful keygen only, default
                        10, max 32). Keygen sweeps every one of the 2^h
                        leaves and the signer repeats that sweep on every
                        invocation, so raising this costs time on both; the
                        circuit climbs 32 levels either way.
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
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn node(rng: &mut impl Rng) -> Node {
    let mut n = [0u8; 16];
    rng.fill_bytes(&mut n);
    n
}

/// signer_cache.bin: the upper levels of each signer's tree, so that `sign`
/// rebuilds one small subtree rather than the whole key. It is
/// `magic || entries`, one entry per signer in key order, and every entry
/// ends in a tag H(domain || sk_seed || entry) that ties it to its key.
/// An XMSS entry is `height || split || levels split..=height`, an SLH-DSA
/// entry `first || levels first..=h'`. A missing or invalid cache only costs
/// time: `sign` rebuilds the trees and writes a fresh one.
const XMSS_CACHE_MAGIC: [u8; 8] = *b"HBS-XMSC";
const SLH_CACHE_MAGIC: [u8; 8] = *b"HBS-SLHC";
const CACHE_TAG_DOMAIN: &[u8] = b"blindsig-binius64/signer-cache/v1";
const CACHE_TAG_BYTES: usize = 32;

fn cache_tag(secret: &[u8], body: &[u8]) -> [u8; CACHE_TAG_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(CACHE_TAG_DOMAIN);
    h.update(&[secret.len() as u8]);
    h.update(secret);
    h.update(body);
    *h.finalize().as_bytes()
}

fn push_entry(out: &mut Vec<u8>, secret: &[u8], header: &[u8], levels: &[Vec<[u8; 16]>]) {
    let start = out.len();
    out.extend_from_slice(header);
    for node in levels.iter().flatten() {
        out.extend_from_slice(node);
    }
    let tag = cache_tag(secret, &out[start..]);
    out.extend_from_slice(&tag);
}

/// Splits one entry off `buf`: its header, its `count`-node levels of
/// `widths`, checked against the tag under `secret`.
fn take_entry<'a>(
    buf: &mut &'a [u8],
    secret: &[u8],
    header_len: usize,
    widths: impl Fn(&[u8]) -> Option<Vec<usize>>,
) -> Option<(&'a [u8], Vec<Vec<[u8; 16]>>)> {
    let header = buf.get(..header_len)?;
    let widths = widths(header)?;
    let body_len = header_len + 16 * widths.iter().sum::<usize>();
    let entry = buf.get(..body_len + CACHE_TAG_BYTES)?;
    if entry[body_len..] != cache_tag(secret, &entry[..body_len]) {
        return None;
    }
    let mut nodes = entry[header_len..body_len].chunks_exact(16).map(|c| c.try_into().unwrap());
    let levels = widths.iter().map(|&w| nodes.by_ref().take(w).collect()).collect();
    *buf = &buf[body_len + CACHE_TAG_BYTES..];
    Some((header, levels))
}

fn level_widths(first: usize, top: usize) -> Vec<usize> {
    (first..=top).map(|z| 1usize << (top - z)).collect()
}

fn write_xmss_cache(keys: &[SignerKey], height: usize, signers: &[Signer]) -> Vec<u8> {
    let mut out = XMSS_CACHE_MAGIC.to_vec();
    for (k, s) in keys.iter().zip(signers) {
        let header = [height as u8, s.subtree_height() as u8];
        push_entry(&mut out, &k.sk_seed, &header, s.top_levels());
    }
    out
}

/// Each signer's split height and top levels, if the whole cache is valid.
fn read_xmss_cache(
    buf: &[u8],
    keys: &[SignerKey],
    height: usize,
) -> Option<Vec<(usize, Vec<Vec<Digest>>)>> {
    let mut rest = buf.strip_prefix(&XMSS_CACHE_MAGIC)?;
    let entries = keys
        .iter()
        .map(|k| {
            let (header, levels) = take_entry(&mut rest, &k.sk_seed, 2, |h| {
                let (h_, split) = (usize::from(h[0]), usize::from(h[1]));
                (h_ == height && (1..=height).contains(&split))
                    .then(|| level_widths(split, height))
            })?;
            Some((usize::from(header[1]), levels))
        })
        .collect::<Option<Vec<_>>>()?;
    rest.is_empty().then_some(entries)
}

fn write_slh_cache(keys: &[SlhSecretKey], slh: &[SlhKey]) -> Vec<u8> {
    let mut out = SLH_CACHE_MAGIC.to_vec();
    for (k, key) in keys.iter().zip(slh) {
        let (first, levels) = key.top_cache();
        push_entry(&mut out, &k.sk_seed, &[first as u8], levels);
    }
    out
}

fn read_slh_cache(
    buf: &[u8],
    p: &SlhParams,
    keys: &[SlhSecretKey],
) -> Option<Vec<(usize, Vec<Vec<Node>>)>> {
    let mut rest = buf.strip_prefix(&SLH_CACHE_MAGIC)?;
    let entries = keys
        .iter()
        .map(|k| {
            let (header, levels) = take_entry(&mut rest, &k.sk_seed, 1, |h| {
                let first = usize::from(h[0]);
                (first <= p.hp).then(|| level_widths(first, p.hp))
            })?;
            Some((usize::from(header[0]), levels))
        })
        .collect::<Option<Vec<_>>>()?;
    rest.is_empty().then_some(entries)
}

fn read_cache_file(opt: &Options) -> Option<Vec<u8>> {
    std::fs::read(opt.path("signer_cache.bin")).ok()
}

/// The signer's public key, which tells every other party the scheme.
fn read_pub_file(opt: &Options, who: &str) -> Result<(Scheme, Vec<u8>)> {
    let path = opt.path("signer_pub.bin");
    let bytes = read_file(&path).with_context(|| {
        format!("{who} needs signer_pub.bin, which records the signer's scheme; run keygen first")
    })?;
    let scheme = if has_magic(&bytes, &SLH_PUB_MAGIC) {
        Scheme::Stateless
    } else {
        Scheme::Stateful
    };
    Ok((scheme, bytes))
}

/// The user's state, checked against the scheme of signer_pub.bin.
fn read_state_file(opt: &Options, scheme: Scheme) -> Result<Vec<u8>> {
    let bytes = read_file(&opt.path("user_state.bin"))?;
    let made_for = if has_magic(&bytes, &SLH_STATE_MAGIC) {
        Scheme::Stateless
    } else {
        Scheme::Stateful
    };
    ensure!(
        made_for == scheme,
        "user_state.bin was committed for the {} scheme but signer_pub.bin is {}; \
         run commit again",
        made_for.name(),
        scheme.name()
    );
    Ok(bytes)
}

fn cmd_keygen(opt: &Options) -> Result<()> {
    match opt.scheme.unwrap_or(Scheme::Stateful) {
        Scheme::Stateful => keygen_stateful(opt),
        Scheme::Stateless => keygen_stateless(opt),
    }
}

fn keygen_stateful(opt: &Options) -> Result<()> {
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

    let split = cache_split_height(opt.height);
    let t0 = Instant::now();
    let signers: Vec<Signer> = sk_seeds
        .par_iter()
        .map(|sk| Signer::from_key_split(sk, &pk_seed, 0, opt.height, split))
        .collect();
    let keygen_s = t0.elapsed().as_secs_f64();
    let roots: Vec<Digest> = signers.iter().map(Signer::public_key).collect();

    let keys: Vec<SignerKey> = sk_seeds
        .iter()
        .map(|&sk_seed| SignerKey {
            sk_seed,
            next_leaf: 0,
        })
        .collect();
    let key_bytes = write_signer_keys(&keys, &pk_seed, opt.height);
    let pub_bytes = write_signer_pub(&roots, &pk_seed, opt.height);
    let cache_bytes = write_xmss_cache(&keys, opt.height, &signers);
    write_file(&opt.path("signer_key.bin"), &key_bytes)?;
    write_file(&opt.path("signer_pub.bin"), &pub_bytes)?;
    write_file(&opt.path("signer_cache.bin"), &cache_bytes)?;

    println!(
        "keygen  ·  stateful  ·  {n} signer{}  ·  XMSS h={} ({} one-time signatures each)  {:.0} ms",
        plural(n),
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
    println!(
        "  → signer_cache.bin ({}, the tree above height {split}, for sign)",
        kb(cache_bytes.len())
    );
    Ok(())
}

fn keygen_stateless(opt: &Options) -> Result<()> {
    let n = opt.signers;
    let p = SLH_DSA_SHA2_128_24;
    let mut rng = os_rng();
    let seeds: Vec<[Node; 3]> = (0..n)
        .map(|_| [node(&mut rng), node(&mut rng), node(&mut rng)])
        .collect();

    let t0 = Instant::now();
    let slh: Vec<SlhKey> = seeds
        .par_iter()
        .map(|[sk_seed, sk_prf, pk_seed]| SlhKey::keygen_internal(p, sk_seed, sk_prf, pk_seed))
        .collect();
    let keygen_s = t0.elapsed().as_secs_f64();
    let keys: Vec<SlhSecretKey> = slh.iter().map(SlhSecretKey::of).collect();

    let pks: Vec<_> = keys.iter().map(SlhSecretKey::public_key).collect();
    let key_bytes = write_slh_keys(&p, &keys);
    let pub_bytes = write_slh_pub(&p, &pks);
    let cache_bytes = write_slh_cache(&keys, &slh);
    write_file(&opt.path("signer_key.bin"), &key_bytes)?;
    write_file(&opt.path("signer_pub.bin"), &pub_bytes)?;
    write_file(&opt.path("signer_cache.bin"), &cache_bytes)?;

    println!(
        "keygen  ·  stateless  ·  {n} signer{}  ·  {} (at most 2^24 signatures per key)  {:.0} ms",
        plural(n),
        p.name,
        keygen_s * 1e3
    );
    for (i, pk) in pks.iter().enumerate() {
        println!("  pk[{i}]    : seed {}  root {}", hex(&pk.pk_seed), hex(&pk.pk_root));
    }
    println!("  → signer_key.bin ({}, secret)", kb(key_bytes.len()));
    println!("  → signer_pub.bin ({})", kb(pub_bytes.len()));
    println!(
        "  → signer_cache.bin ({}, the top tree above height {}, for sign)",
        kb(cache_bytes.len()),
        slh[0].top_cache().0
    );
    Ok(())
}

fn cmd_commit(opt: &Options) -> Result<()> {
    let msg = opt.msg()?;
    let (scheme, _) = read_pub_file(opt, "commit")?;

    let mut rng = os_rng();
    let t0 = Instant::now();
    let (com_bytes, state_bytes) = match scheme {
        Scheme::Stateful => {
            let (com, opening) =
                blind_xmss_binius64::commitment::sample_commitment(&mut rng, &msg);
            let state = blind_xmss_binius64::UserState {
                opening,
                com: com.clone(),
            };
            (write_commitment(&com), write_user_state(&state))
        }
        Scheme::Stateless => {
            let state = slh_commit(&mut rng, &msg);
            (write_commitment(&state.com), write_slh_user_state(&state))
        }
    };
    let commit_ms = t0.elapsed().as_secs_f64() * 1e3;

    write_file(&opt.path("commitment.bin"), &com_bytes)?;
    write_file(&opt.path("user_state.bin"), &state_bytes)?;

    println!(
        "commit  ·  {}  ·  message {} B  {commit_ms:.1} ms",
        scheme.name(),
        msg.len()
    );
    println!(
        "  → commitment.bin ({}, send to the signer(s))",
        kb(com_bytes.len())
    );
    println!("  → user_state.bin ({}, secret)", kb(state_bytes.len()));
    Ok(())
}

fn cmd_sign(opt: &Options) -> Result<()> {
    let key_bytes = read_file(&opt.path("signer_key.bin"))?;
    if has_magic(&key_bytes, &SLH_KEY_MAGIC) {
        sign_stateless(opt, &key_bytes)
    } else {
        sign_stateful(opt, &key_bytes)
    }
}

fn sign_stateful(opt: &Options, key_bytes: &[u8]) -> Result<()> {
    let (keys, pk_seed, height) =
        read_signer_keys(key_bytes).context("malformed signer_key.bin")?;
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
    let cached: Option<Vec<Signer>> = read_cache_file(opt)
        .and_then(|b| read_xmss_cache(&b, &keys, height))
        .and_then(|entries| {
            keys.par_iter()
                .zip(entries)
                .map(|(k, (split, top))| {
                    Signer::from_top_levels(&k.sk_seed, &pk_seed, k.next_leaf, height, split, top)
                })
                .collect()
        });
    let from_cache = cached.is_some();
    let mut signers = cached.unwrap_or_else(|| {
        let split = cache_split_height(height);
        keys.par_iter()
            .map(|k| Signer::from_key_split(&k.sk_seed, &pk_seed, k.next_leaf, height, split))
            .collect()
    });
    let sigs: Vec<XmssSignature> = signers
        .par_iter_mut()
        .map(|s| s.sign(&com))
        .collect::<std::result::Result<_, _>>()
        .context("signing failed (deleting signer_cache.bin makes sign rebuild it)")?;
    let sign_s = t0.elapsed().as_secs_f64();
    if !from_cache {
        write_file(&opt.path("signer_cache.bin"), &write_xmss_cache(&keys, height, &signers))?;
    }

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
        "sign  ·  stateful  ·  {} signature{} at leaf {epoch} of {}  {:.0} ms",
        keys.len(),
        plural(keys.len()),
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
    println!(
        "  tree: {}",
        if from_cache {
            "from signer_cache.bin"
        } else {
            "rebuilt (no valid signer_cache.bin), cache written"
        }
    );
    Ok(())
}

fn sign_stateless(opt: &Options, key_bytes: &[u8]) -> Result<()> {
    let (p, keys) = read_slh_keys(key_bytes).context("malformed signer_key.bin")?;
    let com = read_commitment(&read_file(&opt.path("commitment.bin"))?)
        .context("malformed commitment.bin")?;
    let d = blind_xmss_binius64::slh::commit::com_digest(&com);
    let mut rng = os_rng();
    let addrnd: Vec<Node> = keys.iter().map(|_| node(&mut rng)).collect();

    let t0 = Instant::now();
    let cached: Option<Vec<SlhKey>> = read_cache_file(opt)
        .and_then(|b| read_slh_cache(&b, &p, &keys))
        .and_then(|entries| {
            keys.par_iter()
                .zip(entries)
                .map(|(k, (first, levels))| {
                    SlhKey::from_top_cache(
                        p,
                        HashFamily::Sha2,
                        &k.sk_seed,
                        &k.sk_prf,
                        &k.pk_seed,
                        &k.pk_root,
                        first,
                        levels,
                    )
                })
                .collect()
        });
    let from_cache = cached.is_some();
    let slh: Vec<SlhKey> = match cached {
        Some(slh) => slh,
        None => keys
            .par_iter()
            .enumerate()
            .map(|(i, k)| {
                let key = SlhKey::keygen_internal(p, &k.sk_seed, &k.sk_prf, &k.pk_seed);
                ensure!(
                    key.pk_root == k.pk_root,
                    "signer_key.bin is corrupt: key {i} no longer yields its PK.root"
                );
                Ok(key)
            })
            .collect::<Result<_>>()?,
    };
    let sigs: Vec<SlhSignature> = slh
        .par_iter()
        .zip(&addrnd)
        .map(|(key, opt_rand)| key.sign(&d, Some(opt_rand)))
        .collect();
    let sign_s = t0.elapsed().as_secs_f64();
    for (i, (sig, k)) in sigs.iter().zip(&keys).enumerate() {
        ensure!(
            slh_verify(p, &k.pk_seed, &k.pk_root, &d, sig),
            "signature {i} does not verify (deleting signer_cache.bin makes sign rebuild it)"
        );
    }
    if !from_cache {
        write_file(&opt.path("signer_cache.bin"), &write_slh_cache(&keys, &slh))?;
    }

    let sig_bytes = write_slh_sigs(&p, &sigs);
    write_file(&opt.path("slh_sig.bin"), &sig_bytes)?;

    println!(
        "sign  ·  stateless  ·  {} {} signature{}  {:.0} ms",
        keys.len(),
        p.name,
        plural(keys.len()),
        sign_s * 1e3
    );
    println!(
        "  → slh_sig.bin ({}, send to the user)",
        kb(sig_bytes.len())
    );
    println!(
        "  signer_key.bin unchanged; top tree {}",
        if from_cache {
            "from signer_cache.bin"
        } else {
            "rebuilt (no valid signer_cache.bin), cache written"
        }
    );
    Ok(())
}

fn cmd_prove(opt: &Options) -> Result<()> {
    let (scheme, pub_bytes) = read_pub_file(opt, "prove")?;
    let state_bytes = read_state_file(opt, scheme)?;
    match scheme {
        Scheme::Stateful => prove_stateful(opt, &pub_bytes, &state_bytes),
        Scheme::Stateless => prove_stateless(opt, &pub_bytes, &state_bytes),
    }
}

fn prove_stateful(opt: &Options, pub_bytes: &[u8], state_bytes: &[u8]) -> Result<()> {
    let state = read_user_state(state_bytes).context("malformed user_state.bin")?;
    let (roots, pk_seed, height) =
        read_signer_pub(pub_bytes).context("malformed signer_pub.bin")?;

    let d = com_digest(&state.com);
    let sig_bytes = read_file(&opt.path("xmss_sig.bin"))?;
    let sigs = read_xmss_sigs(&sig_bytes, &pk_seed, height, &d)
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
    println!("prove  ·  stateful  ·  {n} signer{}", plural(n));

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

fn prove_stateless(opt: &Options, pub_bytes: &[u8], state_bytes: &[u8]) -> Result<()> {
    let state = read_slh_user_state(state_bytes).context("malformed user_state.bin")?;
    let (p, pks) = read_slh_pub(pub_bytes).context("malformed signer_pub.bin")?;
    let (q, sigs) = read_slh_sigs(&read_file(&opt.path("slh_sig.bin"))?)
        .context("malformed slh_sig.bin")?;
    ensure!(q == p, "slh_sig.bin is {} but signer_pub.bin is {}", q.name, p.name);
    ensure!(
        sigs.len() == pks.len(),
        "slh_sig.bin holds {} signature(s) but signer_pub.bin names {} signer(s)",
        sigs.len(),
        pks.len()
    );
    let d = blind_xmss_binius64::slh::commit::com_digest(&state.com);
    for (i, (sig, pk)) in sigs.iter().zip(&pks).enumerate() {
        ensure!(
            slh_verify(p, &pk.pk_seed, &pk.pk_root, &d, sig),
            "signature {i} in slh_sig.bin is not a signature on this commitment under \
             signer_pub.bin"
        );
    }

    let n = pks.len();
    println!("prove  ·  stateless ({})  ·  {n} signer{}", p.name, plural(n));
    let mut rng = os_rng();
    let t0 = Instant::now();
    let (setup, zk_prover) = build_slh_prover_setup_multi(p, n).context("prover setup")?;
    println!(
        "  circuit  : built in {:.0} ms",
        t0.elapsed().as_secs_f64() * 1e3
    );
    let mut user = SlhUser::with_setup(Arc::new(setup), Arc::new(zk_prover), &mut rng);
    user.restore(state);
    let t1 = Instant::now();
    let proof = user.prove_multi(&pks, &sigs)?;
    let prove_s = t1.elapsed().as_secs_f64();

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
    let (scheme, pub_bytes) = read_pub_file(opt, "verify")?;
    let proof = read_file(&opt.path("blind_sig.bin"))?;

    let t0 = Instant::now();
    let (ok, verify_s) = match scheme {
        Scheme::Stateful => {
            let (roots, pk_seed, height) =
                read_signer_pub(&pub_bytes).context("malformed signer_pub.bin")?;
            let n = roots.len();
            println!("verify  ·  stateful  ·  {n} signer{}", plural(n));
            if n == 1 {
                let zk_verifier = build_verifier_setup().context("verifier setup")?;
                println!(
                    "  circuit  : built in {:.0} ms",
                    t0.elapsed().as_secs_f64() * 1e3
                );
                let verifier =
                    Verifier::with_zk_verifier(Arc::new(zk_verifier), roots[0], pk_seed, height);
                let t1 = Instant::now();
                let ok = verifier.verify(&read_blind_sig(&proof), &msg).is_ok();
                (ok, t1.elapsed().as_secs_f64())
            } else {
                let zk_verifier = build_verifier_setup_multi(n).context("multi verifier setup")?;
                println!(
                    "  circuit  : built in {:.0} ms",
                    t0.elapsed().as_secs_f64() * 1e3
                );
                let verifier =
                    MultiVerifier::with_zk_verifier(Arc::new(zk_verifier), roots, pk_seed, height);
                let sig = blind_xmss_binius64::BlindMultiSignature {
                    proof: proof.clone(),
                };
                let t1 = Instant::now();
                let ok = verifier.verify(&sig, &msg).is_ok();
                (ok, t1.elapsed().as_secs_f64())
            }
        }
        Scheme::Stateless => {
            let (p, pks) = read_slh_pub(&pub_bytes).context("malformed signer_pub.bin")?;
            let n = pks.len();
            println!("verify  ·  stateless ({})  ·  {n} signer{}", p.name, plural(n));
            let zk_verifier = build_slh_verifier_multi(p, n).context("verifier setup")?;
            println!(
                "  circuit  : built in {:.0} ms",
                t0.elapsed().as_secs_f64() * 1e3
            );
            let verifier = SlhVerifier::new_multi(p, Arc::new(zk_verifier), pks);
            let t1 = Instant::now();
            let ok = verifier.verify(&proof, &msg).is_ok();
            (ok, t1.elapsed().as_secs_f64())
        }
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
        height_set: false,
        scheme: None,
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
                opt.height_set = true;
            }
            "--stateful" | "--stateless" => {
                let s = if arg == "--stateful" {
                    Scheme::Stateful
                } else {
                    Scheme::Stateless
                };
                if opt.scheme.is_some_and(|t| t != s) {
                    bail!("--stateful and --stateless are mutually exclusive");
                }
                opt.scheme = Some(s);
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
    if opt.scheme.is_some() && cmd != "keygen" {
        bail!("--stateful and --stateless are keygen options; {cmd} follows the key files");
    }
    if opt.scheme == Some(Scheme::Stateless) && opt.height_set {
        bail!("--height sets the XMSS tree height and does not apply to --stateless");
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
