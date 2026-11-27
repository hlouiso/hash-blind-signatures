//! In-circuit pure SLH-DSA verification (empty context) at n = 16 with SHA-256.
//!
//! Mirrors `native::SlhCtx::verify_internal`: H_msg, the FORS public key, then
//! d XMSS layers, ending in an equality with the public root. Every value is a
//! big-endian 32-bit word in the low half of a wire, the layout of upstream's
//! `sha256_compress`. The tweakable hashes resume from the midstate after the
//! PK.seed block, which is a public input the verifier computes from the key.
//!
//! The WOTS+ chains take all w - 1 steps, keeping step s exactly when the digit
//! is at most s, so the circuit does not depend on the digits. The signature,
//! R, and therefore the digest, indices and addresses are all private.

use std::array;

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use super::native::{FORS_ROOTS, FORS_TREE, Node, SlhSignature, TREE, WOTS_HASH, WOTS_PK};
use super::params::{N, SlhParams};
use crate::sha_stream::{Chunk, ShaStream, Shift, V32, c, wire};

/// A 16-byte node as four big-endian 32-bit words.
pub type NodeW = [Wire; 4];

pub fn node_words(n: &Node) -> [Word; 4] {
    array::from_fn(|i| Word(u32::from_be_bytes(n[4 * i..4 * i + 4].try_into().unwrap()) as u64))
}

/// The compressed address ADRSc, with the variable fields as wires.
#[derive(Clone, Copy)]
struct AdrsW {
    layer: u32,
    tree_hi: V32,
    tree_lo: V32,
    ty: u32,
    kp: V32,
    ch: V32,
    ix: V32,
}

impl AdrsW {
    fn chunks(&self) -> [Chunk; 7] {
        [
            c(self.layer, 1),
            Chunk { v: self.tree_hi, len: 4 },
            Chunk { v: self.tree_lo, len: 4 },
            c(self.ty, 1),
            Chunk { v: self.kp, len: 4 },
            Chunk { v: self.ch, len: 4 },
            Chunk { v: self.ix, len: 4 },
        ]
    }
}

/// A hypertree address: the tree index as two 32-bit halves.
#[derive(Clone, Copy)]
struct TreeW {
    hi: V32,
    lo: V32,
}

struct Ops<'a> {
    b: &'a CircuitBuilder,
    mid: [Wire; 8],
    s: ShaStream<'a>,
}

impl<'a> Ops<'a> {
    fn konst(&self, v: u64) -> Wire {
        self.s.konst(v)
    }

    fn shift(&self, w: Wire, s: Shift) -> Wire {
        self.s.shift(w, s)
    }

    fn assemble(&self, chunks: &[Chunk], prefix_bytes: usize) -> Vec<[Wire; 16]> {
        self.s.assemble(chunks, prefix_bytes)
    }

    fn sha256(&self, init: [Wire; 8], blocks: Vec<[Wire; 16]>) -> [Wire; 8] {
        self.s.sha256(init, blocks)
    }

    fn iv(&self) -> [Wire; 8] {
        self.s.iv()
    }

    /// Trunc_n(SHA-256(PK.seed || 0^(64-n) || ADRSc || data)), from the midstate.
    fn thash(&self, adrs: &AdrsW, data: &[NodeW]) -> NodeW {
        let mut chunks: Vec<Chunk> = adrs.chunks().to_vec();
        chunks.extend(data.iter().flatten().map(|&w| wire(w)));
        let out = self.sha256(self.mid, self.assemble(&chunks, 64));
        [out[0], out[1], out[2], out[3]]
    }

    /// Bits [start, start + len) of a big-endian stream of 32-bit words.
    fn extract_bits(&self, words: &[Wire], start: usize, len: usize) -> Wire {
        assert!((1..=64).contains(&len));
        let end = start + len;
        let mut terms = Vec::new();
        for q in start / 32..=(end - 1) / 32 {
            let (s, e) = (start.max(32 * q), end.min(32 * q + 32));
            let lsb = 32 * q + 32 - e;
            let width = e - s;
            let mut piece = self.shift(words[q], Shift::Shr(lsb as u32));
            if width < 32 - lsb {
                piece = self.b.band(piece, self.konst((1u64 << width) - 1));
            }
            terms.push(self.shift(piece, Shift::Shl((end - e) as u32)));
        }
        if terms.len() == 1 { terms[0] } else { self.b.bxor_multi(&terms) }
    }

    /// All ones when bit `j` of `x` is set, else zero.
    fn bit_mask(&self, x: Wire, j: usize) -> Wire {
        self.b.sar(self.b.shl(x, 63 - j as u32), 63)
    }

    /// (left, right) = (node, sib) when the mask is clear, (sib, node) when set.
    fn order(&self, mask: Wire, node: &NodeW, sib: &NodeW) -> (NodeW, NodeW) {
        let t: NodeW = array::from_fn(|i| self.b.band(mask, self.b.bxor(node[i], sib[i])));
        (
            array::from_fn(|i| self.b.bxor(node[i], t[i])),
            array::from_fn(|i| self.b.bxor(sib[i], t[i])),
        )
    }

    fn select(&self, mask: Wire, t: &NodeW, f: &NodeW) -> NodeW {
        array::from_fn(|i| self.b.bxor(f[i], self.b.band(mask, self.b.bxor(t[i], f[i]))))
    }

    fn split_tree(&self, tree: Wire) -> TreeW {
        TreeW {
            hi: V32::W(self.b.shr(tree, 32)),
            lo: V32::W(self.b.band(tree, self.konst(0xFFFF_FFFF))),
        }
    }
}

/// Witness wires of one signature. `raw` holds the 32-bit words of the
/// FIPS 205 encoding in order; the circuit reads them masked to 32 bits, since
/// the unaligned byte shifts would otherwise carry a high half into the
/// hashed address bytes.
pub struct SlhSigWires {
    raw: Vec<Wire>,
    r: NodeW,
    fors_sk: Vec<NodeW>,
    fors_auth: Vec<Vec<NodeW>>,
    wots: Vec<Vec<NodeW>>,
    xmss_auth: Vec<Vec<NodeW>>,
}

impl SlhSigWires {
    fn new(b: &CircuitBuilder, p: &SlhParams) -> Self {
        let mask32 = b.add_constant(Word(0xFFFF_FFFF));
        let mut raw = Vec::with_capacity(p.sig_bytes() / 4);
        let mut node = || -> NodeW {
            array::from_fn(|_| {
                let w = b.add_witness();
                raw.push(w);
                b.band(w, mask32)
            })
        };
        let r = node();
        let (mut fors_sk, mut fors_auth) = (Vec::new(), Vec::new());
        for _ in 0..p.k {
            fors_sk.push(node());
            fors_auth.push((0..p.a).map(|_| node()).collect());
        }
        let (mut wots, mut xmss_auth) = (Vec::new(), Vec::new());
        for _ in 0..p.d {
            wots.push((0..p.len()).map(|_| node()).collect());
            xmss_auth.push((0..p.hp).map(|_| node()).collect());
        }
        Self {
            raw,
            r,
            fors_sk,
            fors_auth,
            wots,
            xmss_auth,
        }
    }

    fn populate(&self, w: &mut WitnessFiller<'_>, sig: &SlhSignature) {
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 4 * self.raw.len(), "signature shape");
        for (i, wire) in self.raw.iter().enumerate() {
            let word = u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
            w[*wire] = Word(word as u64);
        }
    }
}

/// Public inputs, in order: PK.seed (4 words), PK.root (4), PK.seed midstate (8).
pub const SLH_INOUTS: usize = 16;

pub struct SlhVerifyGadget {
    pub pk_seed: NodeW,
    pub pk_root: NodeW,
    pub mid: [Wire; 8],
    sig: SlhSigWires,
}

impl SlhVerifyGadget {
    /// Verifies a pure SLH-DSA signature, empty context, on the 32-byte
    /// message given as eight big-endian 32-bit words with empty high halves,
    /// such as a SHA-256 output.
    pub fn new(b: &CircuitBuilder, p: SlhParams, msg_be32: &[Wire; 8]) -> Self {
        assert!(p.m <= 32, "H_msg output beyond one MGF1 block");
        let pk_seed: NodeW = array::from_fn(|_| b.add_inout());
        let pk_root: NodeW = array::from_fn(|_| b.add_inout());
        let mid: [Wire; 8] = array::from_fn(|_| b.add_inout());
        let sig = SlhSigWires::new(b, &p);
        let ops = Ops {
            b,
            mid,
            s: ShaStream::new(b),
        };

        // M' = 0x00 || 0x00 || M.
        let m_be: &[Wire] = msg_be32;

        // H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M'), m).
        let mut chunks: Vec<Chunk> = Vec::new();
        chunks.extend(sig.r.iter().chain(&pk_seed).chain(&pk_root).map(|&w| wire(w)));
        chunks.push(c(0, 2));
        chunks.extend(m_be.iter().map(|&w| wire(w)));
        let inner = ops.sha256(ops.iv(), ops.assemble(&chunks, 0));
        let mut chunks: Vec<Chunk> = Vec::new();
        chunks.extend(sig.r.iter().chain(&pk_seed).chain(&inner).map(|&w| wire(w)));
        chunks.push(c(0, 4));
        let digest = ops.sha256(ops.iv(), ops.assemble(&chunks, 0));

        let md_bits = 8 * p.md_bytes();
        let tree_end = md_bits + 8 * p.tree_bytes();
        let leaf_end = tree_end + 8 * p.leaf_bytes();
        let idx_tree = (p.tree_bits() > 0)
            .then(|| ops.extract_bits(&digest, tree_end - p.tree_bits(), p.tree_bits()));
        let mut idx_leaf = ops.extract_bits(&digest, leaf_end - p.hp, p.hp);

        let mut tree = match idx_tree {
            Some(t) => ops.split_tree(t),
            None => TreeW {
                hi: V32::C(0),
                lo: V32::C(0),
            },
        };
        let adrs = |layer: u32, tree: TreeW, ty: u32, kp: V32, ch: V32, ix: V32| AdrsW {
            layer,
            tree_hi: tree.hi,
            tree_lo: tree.lo,
            ty,
            kp,
            ch,
            ix,
        };

        // Algorithm 17.
        let roots: Vec<NodeW> = (0..p.k)
            .map(|i| {
                let idx = ops.extract_bits(&digest, p.a * i, p.a);
                let leaf_index = b.bxor(idx, ops.konst(((i as u64) << p.a) as u64));
                let a0 = adrs(0, tree, FORS_TREE, V32::W(idx_leaf), V32::C(0), V32::W(leaf_index));
                let mut node = ops.thash(&a0, &[sig.fors_sk[i]]);
                for j in 0..p.a {
                    let (l, r) = ops.order(ops.bit_mask(idx, j), &node, &sig.fors_auth[i][j]);
                    let ix = ops.shift(leaf_index, Shift::Shr(j as u32 + 1));
                    let aj = adrs(
                        0,
                        tree,
                        FORS_TREE,
                        V32::W(idx_leaf),
                        V32::C(j as u32 + 1),
                        V32::W(ix),
                    );
                    node = ops.thash(&aj, &[l, r]);
                }
                node
            })
            .collect();
        let pk_adrs = adrs(0, tree, FORS_ROOTS, V32::W(idx_leaf), V32::C(0), V32::C(0));
        let mut node = ops.thash(&pk_adrs, &roots);

        // Algorithm 13, one XMSS layer at a time.
        let w = p.w();
        let mut tree_wire = idx_tree;
        for layer in 0..p.d {
            if layer > 0 {
                let t = tree_wire.expect("layers above 0 need tree bits");
                idx_leaf = b.band(t, ops.konst((1u64 << p.hp) - 1));
                let next = ops.shift(t, Shift::Shr(p.hp as u32));
                tree_wire = Some(next);
                tree = ops.split_tree(next);
            }
            let l = layer as u32;
            let kp = V32::W(idx_leaf);

            // Algorithm 8: digits, then the checksum digits.
            let mut digits: Vec<Wire> =
                (0..p.len1()).map(|i| ops.extract_bits(&node, p.lg_w * i, p.lg_w)).collect();
            let wm1 = ops.konst((w - 1) as u64);
            let csum = digits
                .iter()
                .map(|&d| b.bxor(d, wm1))
                .reduce(|acc, x| b.iadd_32(acc, x))
                .unwrap();
            for t in 0..p.len2() {
                let sh = ops.shift(csum, Shift::Shr((p.lg_w * (p.len2() - 1 - t)) as u32));
                digits.push(b.band(sh, wm1));
            }

            let ends: Vec<NodeW> = digits
                .iter()
                .enumerate()
                .map(|(i, &d)| {
                    let mut x = sig.wots[layer][i];
                    for s in 0..w - 1 {
                        let a = adrs(l, tree, WOTS_HASH, kp, V32::C(i as u32), V32::C(s as u32));
                        let y = ops.thash(&a, &[x]);
                        let keep = b.sar(b.icmp_ule(d, ops.konst(s as u64)), 63);
                        x = ops.select(keep, &y, &x);
                    }
                    x
                })
                .collect();
            let pk_adrs = adrs(l, tree, WOTS_PK, kp, V32::C(0), V32::C(0));
            node = ops.thash(&pk_adrs, &ends);

            // Algorithm 11, lines 7-16.
            for k in 0..p.hp {
                let (lft, rgt) =
                    ops.order(ops.bit_mask(idx_leaf, k), &node, &sig.xmss_auth[layer][k]);
                let ix = ops.shift(idx_leaf, Shift::Shr(k as u32 + 1));
                let a = adrs(l, tree, TREE, V32::C(0), V32::C(k as u32 + 1), V32::W(ix));
                node = ops.thash(&a, &[lft, rgt]);
            }
        }

        for i in 0..4 {
            b.assert_eq("slh_root", node[i], pk_root[i]);
        }

        Self {
            pk_seed,
            pk_root,
            mid,
            sig,
        }
    }

    pub fn inout_wires(&self) -> [Wire; SLH_INOUTS] {
        let mut out = [self.mid[0]; SLH_INOUTS];
        out[..4].copy_from_slice(&self.pk_seed);
        out[4..8].copy_from_slice(&self.pk_root);
        out[8..].copy_from_slice(&self.mid);
        out
    }

    pub fn populate(&self, w: &mut WitnessFiller<'_>, sig: &SlhSignature) {
        self.sig.populate(w, sig);
    }
}

/// The public words of `SlhVerifyGadget::inout_wires` for a public key.
pub fn slh_public_words(pk_seed: &Node, pk_root: &Node) -> [Word; SLH_INOUTS] {
    let mid = super::native::pk_seed_midstate(pk_seed);
    let mut out = [Word(0); SLH_INOUTS];
    out[..4].copy_from_slice(&node_words(pk_seed));
    out[4..8].copy_from_slice(&node_words(pk_root));
    for i in 0..8 {
        out[8 + i] = Word(mid[i] as u64);
    }
    debug_assert_eq!(N, 16);
    out
}
