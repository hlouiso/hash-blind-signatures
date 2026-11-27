//! Writes the SHA-256 target-sum XMSS test vectors that the Longfellow port
//! loads, to `../test-vectors/xmss/` (or the directory given as the first
//! argument).
//!
//!   cargo run --offline --release --example xmss_kat
//!
//! Both implementations define the same instance (`src/ts_xmss`,
//! `longfellow/src/sha.h`) and derive keys from a seed the same way, so the
//! vectors check every hash, the key derivation and verification across them.
//! They also share the tagged SHA-256 commitment (`src/commitment.rs`,
//! `longfellow/src/commitment.h`), which the `commitment` vectors check.

use std::fmt::Write as _;
use std::path::PathBuf;

use blind_xmss_binius64::commitment::{
    GhashElement, N_LINES, N_NONCE, XMSS_TAGS, com_digest, hm_commit,
    message_hash as hm_message_hash,
};
use blind_xmss_binius64::hashes::{LOG_LIFETIME, MESSAGE_LEN, V};
use blind_xmss_binius64::ts_xmss::hashing::{
    chain_hash, leaf_hash, message_hash, tree_hash, tree_midstate,
};
use blind_xmss_binius64::wots::{PK_SEED_BYTES, SK_SEED_BYTES};
use blind_xmss_binius64::xmss::{XmssKeyPair, xmss_verify};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn bytes<const N: usize>(rng: &mut impl Rng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

fn hx(b: &[u8]) -> String {
    q(&hex::encode(b))
}

fn list(items: &[String], indent: &str) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let inner = items.join(&format!(",\n{indent}  "));
    format!("[\n{indent}  {inner}\n{indent}]")
}

fn object(fields: &[(&str, String)], indent: &str) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{indent}  \"{k}\": {v}"))
        .collect();
    format!("{{\n{}\n{indent}}}", body.join(",\n"))
}

fn hash_vectors(rng: &mut StdRng) -> String {
    let mut out = Vec::new();
    for _ in 0..3 {
        let pp: [u8; 16] = bytes(rng);
        let epoch = rng.next_u32() >> (32 - LOG_LIFETIME);
        let x: [u8; 16] = bytes(rng);
        let (chain, position) = (
            (rng.next_u32() % V as u32) as u8,
            (rng.next_u32() % 7 + 1) as u8,
        );
        let ends: [[u8; 16]; V] = std::array::from_fn(|_| bytes(rng));
        let (left, right): ([u8; 16], [u8; 16]) = (bytes(rng), bytes(rng));
        let level = (rng.next_u32() % LOG_LIFETIME as u32) as u8;
        let index = epoch >> (level + 1);
        let nonce: [u8; 24] = bytes(rng);
        let msg: [u8; MESSAGE_LEN] = bytes(rng);
        let mid: Vec<u8> = tree_midstate(&pp)
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        let ends_hex: Vec<String> = ends.iter().map(|e| hx(e)).collect();
        out.push(object(
            &[
                ("pk_seed", hx(&pp)),
                ("epoch", epoch.to_string()),
                ("chain_input", hx(&x)),
                ("chain_index", chain.to_string()),
                ("chain_position", position.to_string()),
                (
                    "chain_hash",
                    hx(&chain_hash(&pp, epoch, &x, chain, position)),
                ),
                ("leaf_inputs", list(&ends_hex, "      ")),
                ("leaf_hash", hx(&leaf_hash(&pp, epoch, &ends))),
                ("tree_level", level.to_string()),
                ("tree_index", index.to_string()),
                ("tree_left", hx(&left)),
                ("tree_right", hx(&right)),
                ("tree_midstate", hx(&mid)),
                (
                    "tree_hash",
                    hx(&tree_hash(&pp, level, index, &left, &right)),
                ),
                ("nonce", hx(&nonce)),
                ("message", hx(&msg)),
                ("message_hash", hx(&message_hash(&pp, epoch, &nonce, &msg))),
            ],
            "    ",
        ));
    }
    list(&out, "  ")
}

fn key_vectors(rng: &mut StdRng) -> String {
    let mut out = Vec::new();
    for height in [1usize, 5, 10] {
        let sk_seed: [u8; SK_SEED_BYTES] = bytes(rng);
        let pk_seed: [u8; PK_SEED_BYTES] = bytes(rng);
        let mut kp = XmssKeyPair::generate_from_seed(&sk_seed, &pk_seed, height);
        let mut sigs = Vec::new();
        for leaf in [0u64, (1u64 << height) - 1] {
            kp.set_next_leaf(leaf);
            let msg: [u8; MESSAGE_LEN] = bytes(rng);
            let sig = kp.sign(rng, &msg).expect("sign");
            assert!(xmss_verify(&kp.root, &msg, &sig));
            let tips: Vec<String> = sig.chain_tips.iter().map(|t| hx(t)).collect();
            let path: Vec<String> = sig.merkle_path.iter().map(|n| hx(n)).collect();
            sigs.push(object(
                &[
                    ("leaf_index", sig.epoch.to_string()),
                    ("message", hx(&msg)),
                    ("nonce", hx(&sig.randomness)),
                    ("sig_hashes", list(&tips, "          ")),
                    ("auth_path", list(&path, "          ")),
                ],
                "        ",
            ));
            if height == 1 {
                break;
            }
        }
        out.push(object(
            &[
                ("sk_seed", hx(&sk_seed)),
                ("pk_seed", hx(&pk_seed)),
                ("height", height.to_string()),
                ("root", hx(&kp.root)),
                ("signatures", list(&sigs, "      ")),
            ],
            "    ",
        ));
    }
    list(&out, "  ")
}

fn commitment_vectors() -> String {
    // A separate stream, so the hash and key vectors stay as they were.
    let mut rng = StdRng::seed_from_u64(0x584d_5353_c033);
    let msgs: [Vec<u8>; 3] = [
        Vec::new(),
        b"a document".to_vec(),
        (0..300).map(|i| (i * 7 + 1) as u8).collect(),
    ];
    let mut out = Vec::new();
    for msg in &msgs {
        let r: [GhashElement; N_NONCE] = std::array::from_fn(|_| bytes(&mut rng));
        let a: [[GhashElement; N_NONCE]; N_LINES] =
            std::array::from_fn(|_| std::array::from_fn(|_| bytes(&mut rng)));
        let com = hm_commit(msg, &a, &r);
        out.push(object(
            &[
                ("msg", hx(msg)),
                ("a", hx(a.as_flattened().as_flattened())),
                ("r", hx(r.as_flattened())),
                ("m_hat", hx(&hm_message_hash(msg))),
                ("b", hx(com.b.as_flattened())),
                ("y", hx(&com.y)),
                ("commitment", hx(&com.to_bytes())),
                ("d", hx(&com_digest(&com))),
            ],
            "      ",
        ));
    }
    object(
        &[
            (
                "definitions",
                q(
                    "m_hat = SHA-256(TAG_MESSAGE || msg); b_k = m_hat[16k..16k+16] + sum_i a[k][i] r[i] \
                   (little-endian polynomial basis, x^128 + x^7 + x^2 + x + 1); \
                   y = SHA-256(TAG_NONCE || r); commitment = a || b || y; \
                   d = SHA-256(TAG_DIGEST || commitment)",
                ),
            ),
            ("tag_message", hx(&XMSS_TAGS.message)),
            ("tag_nonce", hx(&XMSS_TAGS.nonce)),
            ("tag_digest", hx(&XMSS_TAGS.digest)),
            ("vectors", list(&out, "    ")),
        ],
        "  ",
    )
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/xmss"));
    std::fs::create_dir_all(&dir).expect("create the output directory");
    let mut rng = StdRng::seed_from_u64(0x584d_5353_0001);

    let mut json = String::new();
    writeln!(
        json,
        "{}",
        object(
            &[
                (
                    "scheme",
                    q(
                        "target-sum XMSS over SHA-256, (n, v, w, T) = (128, 42, 8, 195), \
                       24-level path (binius64/src/ts_xmss, longfellow/src/sha.h)"
                    ),
                ),
                ("log_lifetime", LOG_LIFETIME.to_string()),
                ("hashes", hash_vectors(&mut rng)),
                ("keys", key_vectors(&mut rng)),
                ("commitment", commitment_vectors()),
            ],
            "",
        )
    )
    .unwrap();
    let path = dir.join("sha256-xmss.json");
    std::fs::write(&path, json).expect("write the vectors");
    eprintln!("wrote {}", path.display());
}
