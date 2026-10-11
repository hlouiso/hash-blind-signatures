# Sources

The new adapter code retains the existing repository's Apache-2.0 license.
Downloaded and adapted third-party code retains its upstream notices; that license
does not relicense the upstream files.

CMake downloads the following pinned dependencies into the build directory
(`build/_deps` by default), with their upstream license files and notices.

- FAEST: selected components from
  https://github.com/faest-sign/faest-arch-opt at
  `1d8330979cb467c54edac43ffe695da249fa3417` (MIT, license included).
  `cmake/include/generated_crt_constants.hpp` is an empty integration header
  because this backend uses the original, non-CRT VOLE mask construction.
- PoMFRIT: Keccak witness generation in `vole/common/fips202.*` from
  https://github.com/shibammukherjee/pq_blind_signatures at
  `b984d1f141e318a351af9a660a3e6cee26307b65` (Public Domain and Apache-2.0
  according to its SPDX notice). `cmake/pomfrit-trace.patch` is applied to a
  build-directory copy of these files. A wrapper exposes the permutation and its
  snapshots at the configured round spacing (6, 8 or 9). The degree-64
  extension uses snapshots after rounds 9 and 18 and a partial final output.
  The witness pointer increments were generalized to support odd spacings.
- `src/keccak_constraints.hpp`: round functions and constants adapted from
  PoMFRIT's `vole/conservative_bs/owf_proof.inc` and `constants.hpp` at the same
  revision. PoMFRIT does not include a separate top-level license for these
  additions; the MIT notice in its bundled FAEST directory covers the FAEST
  base. This file records attribution without assigning a new upstream license.
  The integration adds the sparse inverse-theta factorization, partial final
  output evaluation and degree-32/64 scheduling; these changes are tested
  against the independent permutation and all theta basis vectors.
- XKCP: the required portable SHAKE implementation from
  https://github.com/XKCP/XKCP at
  `4affab454735d54e78156880b3b44e38dcbf765c` (individual notices and license included).
  `cmake/include/config.h` selects the portable Keccak configuration.
- `src/native`: XMSS, HM field arithmetic and entropy acquisition adapted
  from this repository's KKW implementation; application hashes and keyed
  expansion are replaced with separate SHAKE256 domains.

PoMFRIT: Baum, Beckmann, Beullens, Mukherjee and Rechberger,
*Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and
the MAYO Trapdoor*, USENIX Security 2026, https://eprint.iacr.org/2026/109.
This integration proves an XMSS/HM relation and uses no MAYO component.
