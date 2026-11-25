//! Writes the SLH-DSA and SHA-256 commitment test vectors that the Longfellow
//! and VOLEitH ports load, to `../test-vectors/slh/` (or the directory given
//! as the first argument).
//!
//!   RAYON_NUM_THREADS=8 cargo run --offline --release --example slh_kat
//!
//! Every SLH-DSA vector is a pure signature with an empty context (FIPS 205
//! Algorithm 22): the signed string is M' = 0x00 || 0x00 || msg. A null
//! `addrnd` is the deterministic variant, where opt_rand = PK.seed. The 128-24
//! sets have no external reference implementation, so these vectors check
//! the ports against this crate, not against the standard.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use blind_xmss_binius64::commitment::{GhashElement, N_LINES, N_NONCE};
use blind_xmss_binius64::slh::commit::{
    TAG_DIGEST, TAG_MESSAGE, TAG_NONCE, com_digest, hm_commit, message_hash,
};
use blind_xmss_binius64::slh::native::{
    HashFamily, Node, SlhCtx, SlhKey, SlhSignature, pk_seed_midstate, pure_message,
    slh_verify_with,
};
use blind_xmss_binius64::slh::{SLH_DSA_SHA2_128_24, SlhParams};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const KEYS_PER_SET: usize = 2;

fn node(rng: &mut impl Rng) -> Node {
    let mut n = [0u8; 16];
    rng.fill_bytes(&mut n);
    n
}

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

fn hx(b: &[u8]) -> String {
    q(&hex::encode(b))
}

fn slh_file(p: SlhParams, family: HashFamily, seed: u64) -> String {
    let name = family.set_name(&p);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut vectors = Vec::new();
    for key_no in 0..KEYS_PER_SET {
        let (sk_seed, sk_prf, pk_seed) = (node(&mut rng), node(&mut rng), node(&mut rng));
        let t = Instant::now();
        let key = SlhKey::keygen_internal_with(p, family, &sk_seed, &sk_prf, &pk_seed);
        eprintln!("  {name} key {key_no}: keygen {:.2} s", t.elapsed().as_secs_f64());
        let ctx = SlhCtx::with_family(p, family, &pk_seed);
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);
        let addrnd = node(&mut rng);
        for opt in [None, Some(&addrnd)] {
            let t = Instant::now();
            let sig = key.sign(&msg, opt);
            let sign_s = t.elapsed().as_secs_f64();
            let bytes = sig.to_bytes();
            assert_eq!(bytes.len(), p.sig_bytes());
            assert_eq!(SlhSignature::from_bytes(&p, &bytes).as_ref(), Some(&sig));
            assert!(slh_verify_with(p, family, &pk_seed, &key.pk_root, &msg, &sig));
            let m_prime = pure_message(&msg, &[]);
            let (ok, stats) = ctx.verify_internal(&key.pk_root, &m_prime, &sig);
            assert!(ok);
            let digest = ctx.h_msg(&sig.r, &key.pk_root, &m_prime);
            eprintln!(
                "    sign ({}) {sign_s:.2} s, {} hash calls to verify",
                if opt.is_some() { "hedged" } else { "deterministic" },
                stats.hash_calls()
            );
            let mut v = String::from("    {\n");
            let mut field = |k: &str, val: String| writeln!(v, "      \"{k}\": {val},").unwrap();
            field("sk_seed", hx(&sk_seed));
            field("sk_prf", hx(&sk_prf));
            field("pk_seed", hx(&pk_seed));
            field("pk_root", hx(&key.pk_root));
            field("msg", hx(&msg));
            field("addrnd", opt.map_or("null".into(), |r| hx(r)));
            field("verify_hash_calls", stats.hash_calls().to_string());
            field("digest", hx(&digest));
            if family == HashFamily::Sha2 {
                let mid: Vec<u8> = pk_seed_midstate(&pk_seed)
                    .iter()
                    .flat_map(|w| w.to_be_bytes())
                    .collect();
                field("pk_seed_midstate", hx(&mid));
            }
            write!(v, "      \"signature\": {}\n    }}", hx(&bytes)).unwrap();
            vectors.push(v);
        }
    }
    let mut out = String::from("{\n");
    let mut field = |k: &str, val: String| writeln!(out, "  \"{k}\": {val},").unwrap();
    field("parameter_set", q(&name));
    field("family", q(if family == HashFamily::Sha2 { "SHA2" } else { "SHAKE" }));
    for (k, v) in [
        ("n", 16),
        ("h", p.h),
        ("d", p.d),
        ("hp", p.hp),
        ("a", p.a),
        ("k", p.k),
        ("lg_w", p.lg_w),
        ("m", p.m),
        ("signature_bytes", p.sig_bytes()),
    ] {
        field(k, v.to_string());
    }
    field(
        "interface",
        q("pure slh_sign with an empty context: M' = 0x00 || 0x00 || msg; addrnd null = deterministic (opt_rand = PK.seed); digest = H_msg(R, PK.seed, PK.root, M')"),
    );
    field("generator", q("binius64/examples/slh_kat.rs"));
    write!(out, "  \"vectors\": [\n{}\n  ]\n}}\n", vectors.join(",\n")).unwrap();
    out
}

fn commit_file() -> String {
    let mut rng = StdRng::seed_from_u64(0xC0_33_17);
    let msgs: [Vec<u8>; 2] = [b"a document".to_vec(), (0..300).map(|i| (i * 7 + 1) as u8).collect()];
    let mut vectors = Vec::new();
    for msg in &msgs {
        let mut ghash = || -> GhashElement {
            let mut e = [0u8; 16];
            rng.fill_bytes(&mut e);
            e
        };
        let r: [GhashElement; N_NONCE] = std::array::from_fn(|_| ghash());
        let a: [[GhashElement; N_NONCE]; N_LINES] =
            std::array::from_fn(|_| std::array::from_fn(|_| ghash()));
        let com = hm_commit(msg, &a, &r);
        let mut v = String::from("    {\n");
        let mut field = |k: &str, val: String| writeln!(v, "      \"{k}\": {val},").unwrap();
        field("msg", hx(msg));
        field("a", hx(a.as_flattened().as_flattened()));
        field("r", hx(r.as_flattened()));
        field("m_hat", hx(&message_hash(msg)));
        field("b", hx(com.b.as_flattened()));
        field("y", hx(&com.y));
        field("commitment", hx(&com.to_bytes()));
        write!(v, "      \"d\": {}\n    }}", hx(&com_digest(&com))).unwrap();
        vectors.push(v);
    }
    let mut out = String::from("{\n");
    let mut field = |k: &str, val: String| writeln!(out, "  \"{k}\": {val},").unwrap();
    field(
        "scheme",
        q("Halevi-Micali commitment over GF(2^128), (n, s, k) = (128, 2, 6), SHA-256 with 64-byte tag blocks (binius64/src/slh/commit.rs)"),
    );
    field(
        "definitions",
        q("m_hat = SHA-256(TAG_MESSAGE || msg); b_k = m_hat[16k..16k+16] + sum_i a[k][i] r[i] (little-endian polynomial basis, x^128 + x^7 + x^2 + x + 1); y = SHA-256(TAG_NONCE || r); commitment = a || b || y; d = SHA-256(TAG_DIGEST || commitment)"),
    );
    field("tag_message", hx(&TAG_MESSAGE));
    field("tag_nonce", hx(&TAG_NONCE));
    field("tag_digest", hx(&TAG_DIGEST));
    field("generator", q("binius64/examples/slh_kat.rs"));
    write!(out, "  \"vectors\": [\n{}\n  ]\n}}\n", vectors.join(",\n")).unwrap();
    out
}

fn main() {
    let dir = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/slh")
    });
    std::fs::create_dir_all(&dir).expect("create the output directory");
    let only: Vec<String> = std::env::args().skip(2).collect();
    let sets = [
        ("sha2-128-24", SLH_DSA_SHA2_128_24, HashFamily::Sha2, 0x5348_3232_0001),
        ("shake-128-24", SLH_DSA_SHA2_128_24, HashFamily::Shake, 0x5348_4b45_0001),
    ];
    eprintln!("{} rayon threads", rayon::current_num_threads());
    for (file, p, family, seed) in sets {
        if !only.is_empty() && !only.iter().any(|o| o == file) {
            continue;
        }
        let path = dir.join(format!("{file}.json"));
        std::fs::write(&path, slh_file(p, family, seed)).expect("write vectors");
        eprintln!("wrote {}", path.display());
    }
    if only.is_empty() || only.iter().any(|o| o == "commit") {
        let path = dir.join("commit-sha256.json");
        std::fs::write(&path, commit_file()).expect("write vectors");
        eprintln!("wrote {}", path.display());
    }
}
