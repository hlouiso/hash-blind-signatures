# Hash-Based Blind Signatures

Three implementations of the hash-based **blind (multi)signature** scheme
described in the accompanying paper.

All three share a **Halevi–Micali statistically-hiding commitment** over
GF(2¹²⁸) and one **target-sum WOTS+/XMSS** parameter set at tree height 10, and prove
the same statement: that the user holds a valid XMSS signature on a commitment
opening to the message. The commitment, the signature and the leaf index all
stay secret, so the issued signature is unlinkable to the signing session. The
instantiations differ in the proof system underneath:

| Directory | Proof system | Hash | Language | Notes |
|---|---|---|---|---|
| [`binius64/`](binius64/) | [Binius64](https://github.com/binius-zk/binius64) | BLAKE3 | Rust | Fastest; also implements the blind **multi-signature** |
| [`kkw/`](kkw/) |[KKW](https://eprint.iacr.org/2018/475) | BLAKE3 | C | |
| [`longfellow/`](longfellow/) | [Longfellow ZK](https://github.com/google/longfellow-zk) | SHA-256 | C++ | Smallest proofs of the three |

Each directory is self-contained, with its own build system, tests, benchmarks
and README. Measured sizes and timings are in the paper.

> ⚠️ Research/educational code. Not suitable for production use.

## AI-use disclosure

Large language models provided by Anthropic and OpenAI were used as assistive
tools to review and improve the mathematical proofs and all three software
implementations.
The models were not treated as authors or as authoritative sources. The human
authors reviewed all model-assisted changes, checked citations against the cited
sources, and retain full responsibility for the correctness, originality,
attribution, and reproducibility of the paper and its implementations.

## The `blindsig` CLI

All three build one binary, `blindsig`, exposing the protocol as the same five
commands over the same artefact files, so a session reads identically whichever
proof system is underneath:

```sh
blindsig keygen              # signer:   → signer_key.bin, signer_pub.bin
blindsig commit <msg_file>   # user:     → commitment.bin, user_state.bin
blindsig sign                # signer:   → xmss_sig.bin; next_leaf++
blindsig prove               # user:     → blind_sig.bin  (the blind signature)
blindsig verify <msg_file>   # verifier: [PASS]
```

`--height <h>` sets the *real* XMSS tree height at `keygen` (default 10, max
32), i.e. how many one-time signatures the key can issue. The circuit climbs 32
levels at any height, so nothing else about the session changes.
Raising it costs keygen time and security bits.

`-d, --dir <path>` keeps the artefacts out of the working directory.
`signer_pub.bin` is a trust anchor and is not carried by the signature: it has
to reach the verifier over an authenticated channel.

In `binius64/`, `blindsig keygen --signers n` switches the same five commands to
the blind multi-signature: `n` signers share one `pk_seed` and one commitment,
`sign` returns `n` XMSS signatures at a shared epoch, and `prove` aggregates
them into a single proof.

| Directory | Build the CLI | Binary |
|---|---|---|
| `binius64/` | `cargo build --release --bin blindsig` | `target/release/blindsig` |
| `kkw/` | `make -C kkw N=16 cli` | `kkw/build/n16-w16/blindsig` |
| `longfellow/` | `cmake --build build -j` | `build/blindsig` |

## Benchmarks

One command per implementation reproduces every figure that implementation contributes to the paper:

| Directory | Command | Also produces |
|---|---|---|
| `binius64/` | `RUSTFLAGS="-C target-cpu=native" cargo bench` | the multi-signature sweep, n = 1…64 |
| `kkw/` | `make -C kkw bench` | the MPC-party sweep, N = 4…64 |
| `longfellow/` | `./build/bench [iters]` | |


## License

[Apache 2.0](LICENSE)
