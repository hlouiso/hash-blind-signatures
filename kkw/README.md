# Blind XMSS with KKW

C implementation of the KKW MPC-in-the-head blind-signature instantiation
using BLAKE3.

See the [project README](../README.md) for the protocol overview, CLI usage,
build command, and benchmarks.

> ⚠️ Research/educational code. Not for production use.

## Requirements and tests

Building requires CMake 3.18 or newer, a C toolchain with an assembler, and
OpenMP (`libomp` on macOS). The first build also fetches BLAKE3.

```sh
make test
```

Run `make help` to see the available build options.
