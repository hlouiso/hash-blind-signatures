// Copyright 2026 The Binius Developers
// Copyright (c) 2026 leanEthereum
//! Target-sum XMSS over SHA-256, natively and in circuit.
//!
//! This is upstream's `binius_circuits::hash_based_sig` (Binius64 487127b4,
//! after leanVM-b's `xmss`) with two changes:
//!
//! - The tweakable hash is SHA-256 in the byte formats of the Longfellow
//!   implementation (`longfellow/src/sha.h`), instead of keyed BLAKE3, so both
//!   implementations verify the same XMSS instance.
//! - The Merkle path has [`LOG_LIFETIME`] = 24 levels instead of 32, the
//!   lifetime of SLH-DSA-128-24.
//!
//! The parameters, the target-sum encoding and the pooled chain walk are
//! upstream's. Integer fields are little-endian:
//!
//! ```text
//! message = pp || 02 || epoch || randomness || message              (full digest)
//! chain   = pp || 00 || epoch || node || chain || position          (one block)
//! leaf    = pp || 01 || epoch || chain ends                         (11 blocks)
//! tree    = (pp || 03 || 0^47) || level || index || left || right  (constant first block)
//! ```
//!
//! Chain, leaf and tree digests are SHA-256 truncated to [`DIGEST_LEN`] bytes.
//! A chain step's position is the one it lands on, `1..CHAIN_LENGTH`; a tree
//! node's level byte is its children's level and its index is its own.
//!
//! In circuit, a verification costs 137 SHA-256 compressions: 2 for the
//! message, 99 chain steps (fixed by the target sum), 11 for the leaf, one per
//! path level, and one for the midstate after the tree prefix.

pub mod hashing;
pub mod wots;
pub mod xmss;

/// Digest length in bytes: n = 128 bits.
pub const DIGEST_LEN: usize = 16;

/// A digest packed into 64-bit wires, eight big-endian bytes each.
pub const DIGEST_WIRES: usize = DIGEST_LEN / 8;

/// Public parameter length in bytes. The parameter separates users.
pub const PUBLIC_PARAM_LEN: usize = 16;

/// Wires holding a public parameter.
pub const PUBLIC_PARAM_WIRES: usize = PUBLIC_PARAM_LEN / 8;

/// Signature randomness length in bytes, ground until the encoding is valid.
pub const RANDOMNESS_LEN: usize = 24;

/// Wires holding the randomness.
pub const RANDOMNESS_WIRES: usize = RANDOMNESS_LEN / 8;

/// Length of the signed message in bytes.
pub const MESSAGE_LEN: usize = 32;

/// The message as big-endian 32-bit words, such as a SHA-256 output.
pub const MESSAGE_WORDS: usize = MESSAGE_LEN / 4;

/// Number of Winternitz hash chains.
pub const V: usize = 42;

/// Bits per encoding digit.
pub const W: usize = 3;

/// Chain length: a digit selects one of `2^W` positions.
pub const CHAIN_LENGTH: usize = 1 << W;

/// Chain hashes the verifier walks, summed over all chains: `sum(CHAIN_LENGTH - 1 - e_i)`.
///
/// Constant because the encoding sum is fixed to [`TARGET_SUM`].
pub const NUM_CHAIN_HASHES: usize = 99;

/// A WOTS encoding `(e_0, .., e_{V-1})` is valid exactly when every `e_i < CHAIN_LENGTH`, the
/// digits sum to this, and the two leftover digest bits are zero.
pub const TARGET_SUM: usize = V * (CHAIN_LENGTH - 1) - NUM_CHAIN_HASHES;

/// Merkle tree height: a key is valid for up to `2^LOG_LIFETIME` epochs.
pub const LOG_LIFETIME: usize = 24;

/// A 128-bit digest.
pub type Digest = [u8; DIGEST_LEN];

/// A per-signer public parameter.
pub type PublicParam = [u8; PUBLIC_PARAM_LEN];

/// Signature randomness.
pub type Randomness = [u8; RANDOMNESS_LEN];

/// The message to sign.
pub type Message = [u8; MESSAGE_LEN];

// The encoding uses V*W = 126 of the digest's 128 bits; the 2 leftover top bits are ground to
// zero, so the digest decomposes exactly into the digits.
const _: () = assert!(V * W + 2 == DIGEST_LEN * 8);

// The target sum is what fixes the verifier's chain work.
const _: () = assert!(TARGET_SUM == 195);

// Chain indices and positions are single bytes of the chain hash.
const _: () = assert!(V <= 256 && CHAIN_LENGTH <= 256);

// Epochs and node indices are four bytes of the hashes.
const _: () = assert!(LOG_LIFETIME <= 32);
