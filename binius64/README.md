# Blind XMSS with Binius64

Rust implementation of the Binius64-based blind-signature instantiation using
BLAKE3. It also supports the blind multi-signature extension.

See the [project README](../README.md) for the protocol overview, CLI usage,
build command, and benchmarks.

> ⚠️ Research/educational code. Not for production use.

## Test

```sh
cargo test
```

The Binius64 dependency is fetched over SSH, so Cargo needs access to a GitHub
SSH key.
