# Blind XMSS with VOLE-in-the-head

C/C++ implementation of the VOLE-in-the-head blind-signature instantiation
using SHAKE256, FAEST's QuickSilver components and PoMFRIT's Keccak constraints.

See the [project README](../README.md) for the protocol overview, CLI usage,
build command, and benchmarks.

> ⚠️ Research/educational code. Not for production use.

## Requirements and tests

Building requires CMake 3.20 or newer, Git, a C++23 compiler, and Python 3 for tests.
Supported platforms are macOS and Linux on AArch64 with crypto extensions or
x86-64 with AVX2, AES, PCLMUL and BMI. CMake downloads pinned dependencies into
the build directory; the first configuration requires network access. Source
revisions and license notices are in [THIRD_PARTY.md](THIRD_PARTY.md).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```
