# Blind XMSS with Binius64

Rust implementation of the Binius64-based blind-signature instantiation using
SHA-256. It also supports the blind multi-signature extension. The XMSS circuit
(`src/ts_xmss`) is upstream's `hash_based_sig` with the SHA-256 hashes of the
Longfellow implementation and a 24-level path.

See the [project README](../README.md) for the protocol overview, CLI usage,
build command, and benchmarks.

> ⚠️ Research/educational code. Not for production use.

The optional `wide-wiring` feature supports a Cargo patch that partitions the
Binius64 wiring matrix. The locked dependency uses 63-bit wiring addresses.

## Test

```sh
cargo test --release --locked
```
