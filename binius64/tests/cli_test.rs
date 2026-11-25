//! The `blindsig` binary across process boundaries, in both schemes.
//! The stateless cases generate real SLH-DSA-SHA2-128-24 keys, which takes
//! seconds per key in a release build.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("blindsig-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_blindsig"))
        .args(args)
        .arg("-d")
        .arg(dir)
        .output()
        .unwrap()
}

fn ok(dir: &Dir, args: &[&str]) -> String {
    let out = run(&dir.0, args);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{args:?} failed:\n{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

fn fails(dir: &Dir, args: &[&str]) -> String {
    let out = run(&dir.0, args);
    assert!(!out.status.success(), "{args:?} should fail");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// One session; returns what `sign` printed.
fn session(dir: &Dir, keygen: &[&str]) -> String {
    let msg = dir.file("msg");
    std::fs::write(&msg, b"blind signature CLI test").unwrap();
    let msg = msg.to_str().unwrap();
    let other = dir.file("other");
    std::fs::write(&other, b"a different message").unwrap();

    ok(dir, keygen);
    assert!(dir.file("signer_cache.bin").exists(), "keygen writes the tree cache");
    ok(dir, &["commit", msg]);
    let signed = ok(dir, &["sign"]);
    assert!(signed.contains("from signer_cache.bin"), "{signed}");
    ok(dir, &["prove"]);
    assert!(ok(dir, &["verify", msg]).contains("[PASS]"));
    assert!(fails(dir, &["verify", other.to_str().unwrap()]).contains("[FAIL]"));
    signed
}

/// A missing or corrupted cache only costs time: sign rebuilds and rewrites it.
fn cache_is_rebuilt(dir: &Dir) {
    let cache = dir.read("signer_cache.bin");
    let mut bad = cache.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    std::fs::write(dir.file("signer_cache.bin"), &bad).unwrap();
    assert!(ok(dir, &["sign"]).contains("rebuilt"));
    assert_eq!(dir.read("signer_cache.bin"), cache, "the rebuilt cache is the original");
    ok(dir, &["prove"]);
    std::fs::remove_file(dir.file("signer_cache.bin")).unwrap();
    assert!(ok(dir, &["sign"]).contains("rebuilt"));
    assert_eq!(dir.read("signer_cache.bin"), cache);
    assert!(ok(dir, &["sign"]).contains("from signer_cache.bin"));
    ok(dir, &["prove"]);
}

#[test]
fn stateful_is_the_default_and_advances_the_key() {
    let dir = Dir::new("stateful");
    session(&dir, &["keygen", "--height", "3"]);
    let key = dir.read("signer_key.bin");
    assert_eq!(&key[key.len() - 8..], &1u64.to_le_bytes(), "next_leaf after one signature");
    cache_is_rebuilt(&dir);

    // Above the split height (8), sign rebuilds one 256-leaf subtree from the cache.
    let tall = Dir::new("stateful-tall");
    session(&tall, &["keygen", "--height", "12"]);
    assert_eq!(tall.read("signer_cache.bin").len(), 8 + 2 + 16 * 31 + 32);

    let explicit = Dir::new("stateful-flag");
    session(&explicit, &["keygen", "--stateful", "--height", "2"]);
    assert!(!explicit.file("slh_sig.bin").exists());
}

#[test]
fn stateless_single_and_multi_signer() {
    let dir = Dir::new("stateless");
    session(&dir, &["keygen", "--stateless"]);
    let key = dir.read("signer_key.bin");
    assert!(key.starts_with(b"HBS-SLHK"));
    assert!(!dir.file("xmss_sig.bin").exists());

    // Signing again leaves the key alone and gives a fresh, hedged signature.
    let first = dir.read("slh_sig.bin");
    ok(&dir, &["sign"]);
    assert_eq!(dir.read("signer_key.bin"), key, "a stateless key is never rewritten");
    assert_ne!(dir.read("slh_sig.bin"), first);
    ok(&dir, &["prove"]);

    cache_is_rebuilt(&dir);

    // A state committed under the stateless key does not mix with stateful keys.
    ok(&dir, &["keygen", "--height", "2"]);
    assert!(fails(&dir, &["prove"]).contains("run commit again"));

    let multi = Dir::new("stateless-multi");
    session(&multi, &["keygen", "--stateless", "-n", "2"]);
    assert_eq!(multi.read("signer_pub.bin").len(), 9 + 2 * 32);
}

#[test]
fn scheme_flags_are_validated() {
    let dir = Dir::new("flags");
    assert!(fails(&dir, &["keygen", "--stateful", "--stateless"]).contains("mutually exclusive"));
    assert!(fails(&dir, &["keygen", "--stateless", "--height", "3"]).contains("--height"));
    assert!(fails(&dir, &["sign", "--stateless"]).contains("keygen options"));
    let msg = dir.file("msg");
    std::fs::write(&msg, b"m").unwrap();
    assert!(fails(&dir, &["commit", msg.to_str().unwrap()]).contains("run keygen first"));
}
