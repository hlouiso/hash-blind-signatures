# Blind XMSS with Longfellow

C++ implementation of the Longfellow-based blind-signature instantiation
using SHA-256.

See the [project README](../README.md) for the protocol overview, CLI usage,
build command, and benchmarks.

> ⚠️ Research/educational code. Not for production use.

## Requirements and tests

Building requires CMake 3.14 or newer, a C++17 compiler, and OpenSSL.
Longfellow ZK is fetched automatically by CMake.

```sh
ctest --test-dir build
```
