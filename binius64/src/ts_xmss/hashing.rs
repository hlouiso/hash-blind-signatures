//! The XMSS hash layer: SHA-256 in the byte formats of `longfellow/src/sha.h`.
//!
//! Every hash input starts with the public parameter and a one-byte tweak,
//! which separates the four call sites. Chain, leaf and message hashes then
//! carry the epoch; a tree hash carries its level and index instead, after a
//! constant 64-byte prefix whose midstate is computed once per circuit.
//!
//! In circuit, a node is four big-endian 32-bit words. Witness and public
//! nodes are packed into two 64-bit wires, eight big-endian bytes each, and
//! unpacked here, which also keeps every word fed to SHA-256 below 2^32.

use binius_circuits::sha256::{State, sha256_compress, sha256_compress_2x};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use sha2::{Digest as _, Sha256, block_api::compress256};

use super::{
    DIGEST_LEN, Digest, LOG_LIFETIME, MESSAGE_WORDS, Message, PUBLIC_PARAM_LEN, PUBLIC_PARAM_WIRES,
    PublicParam, RANDOMNESS_WIRES, Randomness, V,
};
use crate::sha_stream::{Chunk, SHA256_IV, ShaStream, Shift, c, wire, wire_bytes};

/// Tweak of a chain step.
pub const TWEAK_CHAIN: u8 = 0x00;
/// Tweak of a WOTS public-key (Merkle leaf) hash.
pub const TWEAK_LEAF: u8 = 0x01;
/// Tweak of the message hash.
pub const TWEAK_MESSAGE: u8 = 0x02;
/// Tweak of an internal Merkle node.
pub const TWEAK_TREE: u8 = 0x03;

/// The bytes before a chain, leaf or message payload: `pp || tweak || epoch`.
pub const PREFIX_LEN: usize = PUBLIC_PARAM_LEN + 1 + 4;

/// The constant first block of a tree hash.
pub const TREE_PREFIX_LEN: usize = 64;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn truncate(h: &[u8; 32]) -> Digest {
    h[..DIGEST_LEN]
        .try_into()
        .expect("a digest is a prefix of the hash")
}

fn prefix(pp: &PublicParam, tweak: u8, epoch: u32) -> [u8; PREFIX_LEN] {
    let mut out = [0u8; PREFIX_LEN];
    out[..PUBLIC_PARAM_LEN].copy_from_slice(pp);
    out[PUBLIC_PARAM_LEN] = tweak;
    out[PUBLIC_PARAM_LEN + 1..].copy_from_slice(&epoch.to_le_bytes());
    out
}

/// SHA-256(pp || 02 || epoch || randomness || message), the full digest. The
/// encoding reads its first [`DIGEST_LEN`] bytes.
pub fn message_hash(
    pp: &PublicParam,
    epoch: u32,
    randomness: &Randomness,
    message: &Message,
) -> [u8; 32] {
    sha256(&[&prefix(pp, TWEAK_MESSAGE, epoch), randomness, message])
}

/// SHA-256(pp || 00 || epoch || x || chain || position), truncated.
/// `position` is the chain position this step lands on.
pub fn chain_hash(pp: &PublicParam, epoch: u32, x: &Digest, chain: u8, position: u8) -> Digest {
    truncate(&sha256(&[
        &prefix(pp, TWEAK_CHAIN, epoch),
        x,
        &[chain, position],
    ]))
}

/// SHA-256(pp || 01 || epoch || ends), truncated: the Merkle leaf.
pub fn leaf_hash(pp: &PublicParam, epoch: u32, ends: &[Digest; V]) -> Digest {
    let mut h = Sha256::new();
    h.update(prefix(pp, TWEAK_LEAF, epoch));
    for end in ends {
        h.update(end);
    }
    truncate(&h.finalize().into())
}

/// `pp || 03 || 0^47`, the first block of every tree hash.
pub fn tree_prefix(pp: &PublicParam) -> [u8; TREE_PREFIX_LEN] {
    let mut out = [0u8; TREE_PREFIX_LEN];
    out[..PUBLIC_PARAM_LEN].copy_from_slice(pp);
    out[PUBLIC_PARAM_LEN] = TWEAK_TREE;
    out
}

/// The SHA-256 state after [`tree_prefix`].
pub fn tree_midstate(pp: &PublicParam) -> [u32; 8] {
    let mut st = SHA256_IV;
    compress256(&mut st, &[tree_prefix(pp)]);
    st
}

/// SHA-256(tree_prefix || level || index || left || right), truncated.
/// `level` is the children's level, 0 for a parent of two leaves, and `index`
/// is the parent's index within its own level.
pub fn tree_hash(pp: &PublicParam, level: u8, index: u32, left: &Digest, right: &Digest) -> Digest {
    truncate(&sha256(&[
        &tree_prefix(pp),
        &[level],
        &index.to_le_bytes(),
        left,
        right,
    ]))
}

/// A node as four big-endian 32-bit words, each in the low half of its wire.
pub type NodeW = [Wire; 4];

/// The 64-bit words that hold `bytes` eight big-endian bytes at a time.
pub fn packed_words(bytes: &[u8]) -> Vec<Word> {
    assert_eq!(bytes.len() % 8, 0, "packed values are whole 64-bit words");
    bytes
        .chunks_exact(8)
        .map(|b| Word(u64::from_be_bytes(b.try_into().expect("eight bytes"))))
        .collect()
}

/// Fills `wires` with [`packed_words`] of `bytes`.
pub fn pack_be(w: &mut WitnessFiller<'_>, wires: &[Wire], bytes: &[u8]) {
    let words = packed_words(bytes);
    assert_eq!(words.len(), wires.len(), "one wire per eight bytes");
    for (wire, word) in wires.iter().zip(words) {
        w[*wire] = word;
    }
}

/// The in-circuit hashes of one public parameter and one epoch.
///
/// The parameter's words, the epoch's bytes and the tree midstate are built
/// once and shared by every hash, and by every signer of a multisignature.
pub struct XmssHasher<'a> {
    pub s: ShaStream<'a>,
    mask32: Wire,
    pp: NodeW,
    epoch: Wire,
    epoch_bytes: [Wire; 4],
    tree_mid: [Wire; 8],
}

impl<'a> XmssHasher<'a> {
    /// Also constrains the epoch below `2^LOG_LIFETIME`, so that its four
    /// hashed bytes are the epoch itself.
    pub fn new(
        b: &'a CircuitBuilder,
        public_param: &[Wire; PUBLIC_PARAM_WIRES],
        epoch: Wire,
    ) -> Self {
        b.assert_zero("xmss_epoch_in_range", b.shr(epoch, LOG_LIFETIME as u32));

        let s = ShaStream::new(b);
        let mask32 = s.konst(0xFFFF_FFFF);
        let pp = unpack_with(b, mask32, public_param);

        let mut blk = [s.konst(0); 16];
        blk[..4].copy_from_slice(&pp);
        blk[PUBLIC_PARAM_LEN / 4] = s.konst((TWEAK_TREE as u64) << 24);
        let tree_mid = sha256_compress(b, State(s.iv()), blk).0;

        let mut hasher = Self {
            s,
            mask32,
            pp,
            epoch,
            epoch_bytes: [epoch; 4],
            tree_mid,
        };
        hasher.epoch_bytes = hasher.shifted_bytes(0);
        hasher
    }

    pub fn builder(&self) -> &'a CircuitBuilder {
        self.s.b
    }

    pub fn epoch(&self) -> Wire {
        self.epoch
    }

    /// The four little-endian bytes of `epoch >> shift`, each in its own wire.
    fn shifted_bytes(&self, shift: usize) -> [Wire; 4] {
        std::array::from_fn(|k| {
            let up = 56 - shift - 8 * k;
            self.s.shift(
                self.s.shift(self.epoch, Shift::Shl(up as u32)),
                Shift::Shr(56),
            )
        })
    }

    /// Splits a packed node into its four words.
    pub fn unpack(&self, packed: &[Wire; 2]) -> NodeW {
        unpack_with(self.s.b, self.mask32, packed)
    }

    /// The words of a packed value of any length.
    pub fn unpack_words(&self, packed: &[Wire]) -> Vec<Wire> {
        packed
            .iter()
            .flat_map(|&p| {
                [
                    self.s.shift(p, Shift::Shr(32)),
                    self.s.b.band(p, self.mask32),
                ]
            })
            .collect()
    }

    /// Packs a node's four words, which must have empty high halves.
    pub fn pack(&self, n: &NodeW) -> [Wire; 2] {
        let b = self.s.b;
        [b.bxor(b.shl(n[0], 32), n[1]), b.bxor(b.shl(n[2], 32), n[3])]
    }

    fn prefix(&self, tweak: u8) -> Vec<Chunk> {
        let mut chunks: Vec<Chunk> = self.pp.iter().map(|&w| wire(w)).collect();
        chunks.push(c(tweak as u32, 1));
        chunks.extend(self.epoch_bytes.iter().map(|&w| wire_bytes(w, 1)));
        chunks
    }

    fn digest(&self, init: [Wire; 8], chunks: &[Chunk], prefix_bytes: usize) -> [Wire; 8] {
        self.s.sha256(init, self.s.assemble(chunks, prefix_bytes))
    }

    /// [`message_hash`], from the randomness as big-endian words.
    pub fn message(
        &self,
        randomness: &[Wire; 2 * RANDOMNESS_WIRES],
        message: &[Wire; MESSAGE_WORDS],
    ) -> [Wire; 8] {
        let mut chunks = self.prefix(TWEAK_MESSAGE);
        chunks.extend(randomness.iter().chain(message).map(|&w| wire(w)));
        self.digest(self.s.iv(), &chunks, 0)
    }

    /// [`chain_hash`]. The chain and position must be wires below 2^8, which
    /// the chain walk's constraints ensure.
    pub fn chain(&self, x: &NodeW, chain: Wire, position: Wire) -> NodeW {
        let block = self.chain_block(x, chain, position);
        head(&sha256_compress(self.s.b, State(self.s.iv()), block).0)
    }

    fn chain_block(&self, x: &NodeW, chain: Wire, position: Wire) -> [Wire; 16] {
        let mut chunks = self.prefix(TWEAK_CHAIN);
        chunks.extend(x.iter().map(|&w| wire(w)));
        chunks.push(wire_bytes(chain, 1));
        chunks.push(wire_bytes(position, 1));
        let [block] = self
            .s
            .assemble(&chunks, 0)
            .try_into()
            .expect("one XMSS chain block");
        block
    }

    /// Hash two independent chain entries in the two SHA-256 lanes of a word.
    pub(super) fn chain_pair(&self, pair: [(&NodeW, Wire, Wire); 2]) -> [[Wire; 2]; 2] {
        let [lo, hi] = pair.map(|(x, chain, pos)| self.chain_block(x, chain, pos));
        let b = self.builder();
        let block = std::array::from_fn(|i| b.bxor(lo[i], b.shl(hi[i], 32)));
        let iv = SHA256_IV.map(|v| self.s.konst(u64::from(v) * 0x1_0000_0001));
        let out = sha256_compress_2x(b, State(iv), block).0;
        let low = std::array::from_fn(|i| b.band(out[i], self.mask32));
        let high = std::array::from_fn(|i| b.shr(out[i], 32));
        [self.pack(&low), self.pack(&high)]
    }

    /// [`leaf_hash`].
    pub fn leaf(&self, ends: &[NodeW; V]) -> NodeW {
        let mut chunks = self.prefix(TWEAK_LEAF);
        chunks.extend(ends.iter().flatten().map(|&w| wire(w)));
        head(&self.digest(self.s.iv(), &chunks, 0))
    }

    /// [`tree_hash`] at `level` of the path from the epoch's leaf: the parent
    /// index is `epoch >> (level + 1)`.
    pub fn tree(&self, level: usize, left: &NodeW, right: &NodeW) -> NodeW {
        let mut chunks = vec![c(level as u32, 1)];
        chunks.extend(
            self.shifted_bytes(level + 1)
                .iter()
                .map(|&w| wire_bytes(w, 1)),
        );
        chunks.extend(left.iter().chain(right).map(|&w| wire(w)));
        head(&self.digest(self.tree_mid, &chunks, TREE_PREFIX_LEN))
    }
}

fn unpack_with(b: &CircuitBuilder, mask32: Wire, packed: &[Wire; 2]) -> NodeW {
    [
        b.shr(packed[0], 32),
        b.band(packed[0], mask32),
        b.shr(packed[1], 32),
        b.band(packed[1], mask32),
    ]
}

fn head(h: &[Wire; 8]) -> NodeW {
    [h[0], h[1], h[2], h[3]]
}

#[cfg(test)]
mod tests {
    use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

    use super::*;
    use crate::ts_xmss::{MESSAGE_LEN, RANDOMNESS_LEN};

    fn random<const N: usize>(rng: &mut StdRng) -> [u8; N] {
        let mut out = [0u8; N];
        rng.fill_bytes(&mut out);
        out
    }

    /// Builds one hash of each kind and checks the circuit against the native hashes.
    fn check(pp: PublicParam, epoch: u32, seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let x: Digest = random(&mut rng);
        let ends: [Digest; V] = std::array::from_fn(|_| random(&mut rng));
        let randomness: Randomness = random(&mut rng);
        let message: Message = random(&mut rng);
        let (left, right): (Digest, Digest) = (random(&mut rng), random(&mut rng));
        let (chain, position) = (rng.random_range(0..V as u8), rng.random_range(1..8u8));
        let level = rng.random_range(0..LOG_LIFETIME);

        let b = CircuitBuilder::new();
        let pp_w: [Wire; 2] = std::array::from_fn(|_| b.add_inout());
        let epoch_w = b.add_inout();
        let x_w: [Wire; 2] = std::array::from_fn(|_| b.add_witness());
        let ends_w: [[Wire; 2]; V] =
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()));
        let rnd_w: [Wire; RANDOMNESS_WIRES] = std::array::from_fn(|_| b.add_witness());
        let msg_w: [Wire; 4] = std::array::from_fn(|_| b.add_witness());
        let lr_w: [[Wire; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()));
        let chain_w = b.add_constant_64(chain as u64);
        let position_w = b.add_constant_64(position as u64);

        let h = XmssHasher::new(&b, &pp_w, epoch_w);
        let x_n = h.unpack(&x_w);
        let ends_n: [NodeW; V] = std::array::from_fn(|i| h.unpack(&ends_w[i]));
        let rnd: [Wire; 6] = h.unpack_words(&rnd_w).try_into().unwrap();
        let msg: [Wire; 8] = h.unpack_words(&msg_w).try_into().unwrap();
        let outputs = [
            h.message(&rnd, &msg).to_vec(),
            h.chain(&x_n, chain_w, position_w).to_vec(),
            h.leaf(&ends_n).to_vec(),
            h.tree(level, &h.unpack(&lr_w[0]), &h.unpack(&lr_w[1]))
                .to_vec(),
        ];
        let out_w: Vec<Vec<Wire>> = outputs
            .iter()
            .map(|o| {
                o.iter()
                    .map(|&w| {
                        let e = b.add_inout();
                        b.assert_eq("hash", w, e);
                        e
                    })
                    .collect()
            })
            .collect();

        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        pack_be(&mut w, &pp_w, &pp);
        w[epoch_w] = Word::from_u64(epoch as u64);
        pack_be(&mut w, &x_w, &x);
        for (wires, end) in ends_w.iter().zip(&ends) {
            pack_be(&mut w, wires, end);
        }
        pack_be(&mut w, &rnd_w, &randomness);
        pack_be(&mut w, &msg_w, &message);
        pack_be(&mut w, &lr_w[0], &left);
        pack_be(&mut w, &lr_w[1], &right);

        let index = epoch >> (level + 1);
        let expected: [Vec<u8>; 4] = [
            message_hash(&pp, epoch, &randomness, &message).to_vec(),
            chain_hash(&pp, epoch, &x, chain, position).to_vec(),
            leaf_hash(&pp, epoch, &ends).to_vec(),
            tree_hash(&pp, level as u8, index, &left, &right).to_vec(),
        ];
        for (wires, bytes) in out_w.iter().zip(&expected) {
            for (wire, word) in wires.iter().zip(bytes.chunks_exact(4)) {
                w[*wire] = Word(u32::from_be_bytes(word.try_into().unwrap()) as u64);
            }
        }

        circuit.populate_wire_witness(&mut w).unwrap();
        let values = w.into_value_vec();
        circuit.constraint_system().verify(&values).unwrap();
    }

    #[test]
    fn circuit_hashes_match_native() {
        let mut rng = StdRng::seed_from_u64(1);
        for (i, epoch) in [0u32, 1, 0x00AB_CDEF, (1 << LOG_LIFETIME) - 1]
            .into_iter()
            .enumerate()
        {
            check(random(&mut rng), epoch, i as u64);
        }
    }

    #[test]
    fn an_epoch_past_the_lifetime_has_no_witness() {
        let b = CircuitBuilder::new();
        let pp_w: [Wire; 2] = std::array::from_fn(|_| b.add_inout());
        let epoch_w = b.add_inout();
        let _h = XmssHasher::new(&b, &pp_w, epoch_w);
        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        w[epoch_w] = Word::from_u64(1 << LOG_LIFETIME);
        assert!(circuit.populate_wire_witness(&mut w).is_err());
    }

    #[test]
    fn byte_layouts_are_longfellow_s() {
        let pp = [0x11u8; PUBLIC_PARAM_LEN];
        let p = prefix(&pp, TWEAK_CHAIN, 0x0403_0201);
        assert_eq!(&p[16..], &[0, 1, 2, 3, 4]);
        let t = tree_prefix(&pp);
        assert_eq!((t[16], t[17..].iter().all(|&b| b == 0)), (TWEAK_TREE, true));
        assert_eq!(PREFIX_LEN + DIGEST_LEN + 2, 39);
        assert_eq!(PREFIX_LEN + RANDOMNESS_LEN + MESSAGE_LEN, 77);
    }

    #[test]
    fn the_midstate_resumes_the_tree_hash() {
        let mut rng = StdRng::seed_from_u64(9);
        let pp: PublicParam = random(&mut rng);
        let (l, r): (Digest, Digest) = (random(&mut rng), random(&mut rng));
        let mut st = tree_midstate(&pp);
        let mut tail = [0u8; 64];
        tail[0] = 5;
        tail[1..5].copy_from_slice(&7u32.to_le_bytes());
        tail[5..21].copy_from_slice(&l);
        tail[21..37].copy_from_slice(&r);
        tail[37] = 0x80;
        tail[56..].copy_from_slice(&((64u64 + 37) * 8).to_be_bytes());
        compress256(&mut st, &[tail]);
        let out: Vec<u8> = st.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(&out[..DIGEST_LEN], &tree_hash(&pp, 5, 7, &l, &r));
    }
}
