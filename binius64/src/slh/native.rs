//! Native SLH-DSA (FIPS 205) at security category 1, with SHA-256 or SHAKE256.
//!
//! Follows FIPS 205 Algorithms 1-20 directly, generic over the parameters in
//! [`SlhParams`] and over the hash family: Section 11.2.1 (SHA2, the default)
//! or Section 11.1 (SHAKE). The SHA2 tweakable hashes start from the midstate
//! of the PK.seed block, which depends only on the public key; the SHAKE ones
//! hash PK.seed || ADRS || M with the full 32-byte ADRS. Signing parallelises
//! the tree computations with rayon and caches upper levels of the top XMSS
//! tree in the key, as SP 800-230 Section 3 permits.

use rayon::prelude::*;
use sha2::{Digest, Sha256, block_api::compress256};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, XofReader};

use super::params::{N, SlhParams};

/// The instantiation of H_msg, PRF, PRF_msg, F, H and T_l.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashFamily {
    /// FIPS 205 Section 11.2.1, security category 1.
    Sha2,
    /// FIPS 205 Section 11.1.
    Shake,
}

impl HashFamily {
    /// The standard's name of `p` in this family, e.g. "SLH-DSA-SHAKE-128-24".
    pub fn set_name(self, p: &SlhParams) -> String {
        match self {
            HashFamily::Sha2 => p.name.to_string(),
            HashFamily::Shake => p.name.replace("SHA2", "SHAKE"),
        }
    }
}

/// SHAKE256 of the concatenated `parts`, `out.len()` bytes.
pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        sha3::digest::Update::update(&mut h, p);
    }
    h.finalize_xof().read(out);
}

fn shake_node(parts: &[&[u8]]) -> Node {
    let mut out = [0u8; N];
    shake256(parts, &mut out);
    out
}

pub type Node = [u8; N];

pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;

/// Recursion depth at and above which FORS subtrees are split across threads.
const PAR_HEIGHT: u32 = 10;

/// The 32-byte address of FIPS 205 Section 4.2.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Adrs(pub [u8; 32]);

impl Adrs {
    fn put(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
    fn get(&self, at: usize) -> u32 {
        u32::from_be_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    pub fn set_layer(&mut self, l: u32) {
        self.put(0, l);
    }
    pub fn set_tree(&mut self, t: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&t.to_be_bytes());
    }
    pub fn set_type_and_clear(&mut self, ty: u32) {
        self.put(16, ty);
        self.0[20..32].fill(0);
    }
    pub fn set_keypair(&mut self, kp: u32) {
        self.put(20, kp);
    }
    pub fn keypair(&self) -> u32 {
        self.get(20)
    }
    pub fn set_chain(&mut self, c: u32) {
        self.put(24, c);
    }
    pub fn set_tree_height(&mut self, z: u32) {
        self.put(24, z);
    }
    pub fn set_hash(&mut self, x: u32) {
        self.put(28, x);
    }
    pub fn set_tree_index(&mut self, i: u32) {
        self.put(28, i);
    }
    /// ADRSc of FIPS 205 Section 11.2.
    pub fn compressed(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.0[3];
        c[1..9].copy_from_slice(&self.0[8..16]);
        c[9] = self.0[19];
        c[10..22].copy_from_slice(&self.0[20..32]);
        c
    }
}

/// State after compressing the block PK.seed || 0^(64 - n).
pub fn pk_seed_midstate(pk_seed: &Node) -> [u32; 8] {
    let mut block = [0u8; 64];
    block[..N].copy_from_slice(pk_seed);
    let mut st = SHA256_IV;
    compress256(&mut st, &[block]);
    st
}

fn state_to_node(st: &[u32; 8]) -> Node {
    let mut out = [0u8; N];
    for i in 0..N / 4 {
        out[4 * i..4 * i + 4].copy_from_slice(&st[i].to_be_bytes());
    }
    out
}

/// Trunc_n(SHA-256(PK.seed || 0^(64-n) || ADRSc || data)): F, H, T_l and PRF.
fn thash(mid: &[u32; 8], adrs: &Adrs, data: &[u8]) -> Node {
    let body = 22 + data.len();
    let total_bits = ((64 + body) as u64) * 8;
    let mut st = *mid;
    if body + 9 <= 64 {
        let mut block = [0u8; 64];
        block[..22].copy_from_slice(&adrs.compressed());
        block[22..body].copy_from_slice(data);
        block[body] = 0x80;
        block[56..].copy_from_slice(&total_bits.to_be_bytes());
        compress256(&mut st, &[block]);
    } else {
        let nblocks = (body + 9).div_ceil(64);
        let mut buf = vec![0u8; nblocks * 64];
        buf[..22].copy_from_slice(&adrs.compressed());
        buf[22..body].copy_from_slice(data);
        buf[body] = 0x80;
        let end = nblocks * 64;
        buf[end - 8..].copy_from_slice(&total_bits.to_be_bytes());
        let (blocks, _) = buf.as_chunks::<64>();
        compress256(&mut st, blocks);
    }
    state_to_node(&st)
}

fn mgf1_sha256(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut c = 0u32;
    while out.len() < len {
        let mut hs = Sha256::new();
        hs.update(seed);
        hs.update(c.to_be_bytes());
        out.extend_from_slice(&hs.finalize());
        c += 1;
    }
    out.truncate(len);
    out
}

/// H_msg of FIPS 205 Section 11.1: SHAKE256(R || PK.seed || PK.root || M, 8m).
pub fn h_msg_shake(r: &Node, pk_seed: &Node, pk_root: &Node, msg: &[u8], m: usize) -> Vec<u8> {
    let mut out = vec![0u8; m];
    shake256(&[r, pk_seed, pk_root, msg], &mut out);
    out
}

/// PRF_msg of FIPS 205 Section 11.1: SHAKE256(SK.prf || opt_rand || M, 8n).
pub fn prf_msg_shake(sk_prf: &Node, opt_rand: &Node, msg: &[u8]) -> Node {
    shake_node(&[sk_prf, opt_rand, msg])
}

/// H_msg of FIPS 205 Section 11.2.1.
pub fn h_msg(r: &Node, pk_seed: &Node, pk_root: &Node, msg: &[u8], m: usize) -> Vec<u8> {
    let mut hs = Sha256::new();
    hs.update(r);
    hs.update(pk_seed);
    hs.update(pk_root);
    hs.update(msg);
    let inner = hs.finalize();
    let mut seed = Vec::with_capacity(2 * N + 32);
    seed.extend_from_slice(r);
    seed.extend_from_slice(pk_seed);
    seed.extend_from_slice(&inner);
    mgf1_sha256(&seed, m)
}

/// HMAC-SHA-256 (RFC 2104) of the concatenated parts, for keys of at most one block.
pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    assert!(key.len() <= 64);
    let mut k0 = [0u8; 64];
    k0[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(k0.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k0.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// PRF_msg of FIPS 205 Section 11.2.1.
pub fn prf_msg(sk_prf: &Node, opt_rand: &Node, msg: &[u8]) -> Node {
    hmac_sha256(sk_prf, &[opt_rand, msg])[..N].try_into().unwrap()
}

/// Algorithm 4.
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut inp = 0;
    let mut bits = 0usize;
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | x[inp] as u64;
            inp += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & ((1u64 << b) - 1)) as u32);
    }
    out
}

fn to_int(x: &[u8]) -> u64 {
    x.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn low_bits(x: u64, bits: usize) -> u64 {
    if bits >= 64 { x } else { x & ((1u64 << bits) - 1) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssSig {
    pub wots: Vec<Node>,
    pub auth: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForsTreeSig {
    pub sk: Node,
    pub auth: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlhSignature {
    pub r: Node,
    pub fors: Vec<ForsTreeSig>,
    pub ht: Vec<XmssSig>,
}

impl SlhSignature {
    pub(super) fn has_shape(&self, p: &SlhParams) -> bool {
        self.fors.len() == p.k
            && self.fors.iter().all(|t| t.auth.len() == p.a)
            && self.ht.len() == p.d
            && self.ht.iter().all(|x| x.wots.len() == p.len() && x.auth.len() == p.hp)
    }

    /// The FIPS 205 encoding R || SIG_FORS || SIG_HT.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.r);
        for t in &self.fors {
            out.extend_from_slice(&t.sk);
            t.auth.iter().for_each(|n| out.extend_from_slice(n));
        }
        for x in &self.ht {
            x.wots.iter().for_each(|n| out.extend_from_slice(n));
            x.auth.iter().for_each(|n| out.extend_from_slice(n));
        }
        out
    }
}

/// Hash calls one verification makes: tweakable hashes plus the one H_msg.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyStats {
    pub f: u64,
    pub h: u64,
    pub t: u64,
}

impl VerifyStats {
    pub fn hash_calls(&self) -> u64 {
        self.f + self.h + self.t + 1
    }
}

/// Public operations, keyed by the public seed.
#[derive(Clone)]
pub struct SlhCtx {
    pub p: SlhParams,
    pub family: HashFamily,
    pub pk_seed: Node,
    /// The SHA-256 midstate of PK.seed || 0^48; unused for SHAKE.
    pub mid: [u32; 8],
}

impl SlhCtx {
    /// The SHA2 instantiation.
    pub fn new(p: SlhParams, pk_seed: &Node) -> Self {
        Self::with_family(p, HashFamily::Sha2, pk_seed)
    }

    pub fn with_family(p: SlhParams, family: HashFamily, pk_seed: &Node) -> Self {
        Self {
            p,
            family,
            pk_seed: *pk_seed,
            mid: pk_seed_midstate(pk_seed),
        }
    }

    /// F, H, T_l and PRF share the input format PK.seed || ADRS || data.
    fn thash(&self, adrs: &Adrs, data: &[u8]) -> Node {
        match self.family {
            HashFamily::Sha2 => thash(&self.mid, adrs, data),
            HashFamily::Shake => shake_node(&[&self.pk_seed, &adrs.0, data]),
        }
    }

    pub fn h_msg(&self, r: &Node, pk_root: &Node, msg: &[u8]) -> Vec<u8> {
        match self.family {
            HashFamily::Sha2 => h_msg(r, &self.pk_seed, pk_root, msg, self.p.m),
            HashFamily::Shake => h_msg_shake(r, &self.pk_seed, pk_root, msg, self.p.m),
        }
    }

    pub fn prf_msg(&self, sk_prf: &Node, opt_rand: &Node, msg: &[u8]) -> Node {
        match self.family {
            HashFamily::Sha2 => prf_msg(sk_prf, opt_rand, msg),
            HashFamily::Shake => prf_msg_shake(sk_prf, opt_rand, msg),
        }
    }

    pub fn f(&self, adrs: &Adrs, m: &Node) -> Node {
        self.thash(adrs, m)
    }

    pub fn h(&self, adrs: &Adrs, l: &Node, r: &Node) -> Node {
        let mut buf = [0u8; 2 * N];
        buf[..N].copy_from_slice(l);
        buf[N..].copy_from_slice(r);
        self.thash(adrs, &buf)
    }

    pub fn t(&self, adrs: &Adrs, nodes: &[Node]) -> Node {
        self.thash(adrs, nodes.as_flattened())
    }

    pub fn prf(&self, adrs: &Adrs, sk_seed: &Node) -> Node {
        self.thash(adrs, sk_seed)
    }

    /// The len base-w digits of Algorithms 7 and 8: message, then checksum.
    pub fn wots_digits(&self, msg: &Node) -> Vec<u32> {
        let p = &self.p;
        let w = p.w() as u32;
        let mut d = base_2b(msg, p.lg_w, p.len1());
        let csum: u64 = d.iter().map(|&x| (w - 1 - x) as u64).sum::<u64>() << p.csum_shift();
        let cb = csum.to_be_bytes();
        d.extend(base_2b(&cb[8 - p.csum_bytes()..], p.lg_w, p.len2()));
        d
    }

    /// Algorithm 5.
    fn chain(&self, mut x: Node, i: u32, s: u32, adrs: &mut Adrs) -> Node {
        for j in i..i + s {
            adrs.set_hash(j);
            x = self.f(adrs, &x);
        }
        x
    }

    fn wots_sk(&self, sk_seed: &Node, adrs: &Adrs, i: u32) -> Node {
        let mut a = *adrs;
        a.set_type_and_clear(WOTS_PRF);
        a.set_keypair(adrs.keypair());
        a.set_chain(i);
        self.prf(&a, sk_seed)
    }

    /// Algorithm 6.
    pub fn wots_pkgen(&self, sk_seed: &Node, adrs: &Adrs) -> Node {
        let mut ends = vec![[0; N]; self.p.len()];
        self.wots_pkgen_with_scratch(sk_seed, adrs, &mut ends)
    }

    fn wots_pkgen_with_scratch(&self, sk_seed: &Node, adrs: &Adrs, ends: &mut [Node]) -> Node {
        let w = self.p.w() as u32;
        for (i, end) in ends.iter_mut().enumerate() {
            let sk = self.wots_sk(sk_seed, adrs, i as u32);
            let mut a = *adrs;
            a.set_chain(i as u32);
            *end = self.chain(sk, 0, w - 1, &mut a);
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_keypair(adrs.keypair());
        self.t(&pk_adrs, ends)
    }

    /// Algorithm 7.
    pub fn wots_sign(&self, msg: &Node, sk_seed: &Node, adrs: &Adrs) -> Vec<Node> {
        self.wots_digits(msg)
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                let sk = self.wots_sk(sk_seed, adrs, i as u32);
                let mut a = *adrs;
                a.set_chain(i as u32);
                self.chain(sk, 0, d, &mut a)
            })
            .collect()
    }

    /// Algorithm 8.
    pub fn wots_pk_from_sig(
        &self,
        sig: &[Node],
        msg: &Node,
        adrs: &Adrs,
        stats: &mut VerifyStats,
    ) -> Node {
        let w = self.p.w() as u32;
        let tmp: Vec<Node> = self
            .wots_digits(msg)
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                let mut a = *adrs;
                a.set_chain(i as u32);
                stats.f += (w - 1 - d) as u64;
                self.chain(sig[i], d, w - 1 - d, &mut a)
            })
            .collect();
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_keypair(adrs.keypair());
        stats.t += 1;
        self.t(&pk_adrs, &tmp)
    }

    fn xmss_adrs(layer: u32, tree: u64) -> Adrs {
        let mut a = Adrs::default();
        a.set_layer(layer);
        a.set_tree(tree);
        a
    }

    fn xmss_parent(&self, base: &Adrs, i: u32, height: u32, l: &Node, r: &Node) -> Node {
        let mut a = *base;
        a.set_type_and_clear(TREE);
        a.set_tree_height(height);
        a.set_tree_index(i);
        self.h(&a, l, r)
    }

    // Algorithm 9 for a short subtree. Its index is global within this XMSS tree.
    fn xmss_node(
        &self,
        sk_seed: &Node,
        base: &Adrs,
        i: u32,
        height: u32,
        ends: &mut [Node],
    ) -> Node {
        if height == 0 {
            let mut a = *base;
            a.set_type_and_clear(WOTS_HASH);
            a.set_keypair(i);
            return self.wots_pkgen_with_scratch(sk_seed, &a, ends);
        }
        let l = self.xmss_node(sk_seed, base, 2 * i, height - 1, ends);
        let r = self.xmss_node(sk_seed, base, 2 * i + 1, height - 1, ends);
        self.xmss_parent(base, i, height, &l, &r)
    }

    /// Every level of one XMSS tree, from the leaves to the root.
    pub fn xmss_levels(&self, sk_seed: &Node, layer: u32, tree: u64) -> Vec<Vec<Node>> {
        self.xmss_levels_from(sk_seed, layer, tree, 0)
    }

    fn xmss_levels_from(
        &self,
        sk_seed: &Node,
        layer: u32,
        tree: u64,
        first_height: usize,
    ) -> Vec<Vec<Node>> {
        let base = Self::xmss_adrs(layer, tree);
        let mut levels = vec![Vec::new(); first_height];
        levels.push(
            (0..1u32 << (self.p.hp - first_height))
                .into_par_iter()
                .map_init(
                    || vec![[0; N]; self.p.len()],
                    |ends, i| self.xmss_node(sk_seed, &base, i, first_height as u32, ends),
                )
                .collect(),
        );
        for z in first_height + 1..=self.p.hp {
            let prev = levels.last().unwrap();
            let next = prev
                .par_chunks_exact(2)
                .enumerate()
                .map(|(i, pair)| self.xmss_parent(&base, i as u32, z as u32, &pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        levels
    }

    /// Algorithm 10, recomputing authentication siblings below the cache.
    fn xmss_sign(
        &self,
        msg: &Node,
        sk_seed: &Node,
        idx: u32,
        layer: u32,
        tree: u64,
        levels: &[Vec<Node>],
    ) -> XmssSig {
        let mut a = Self::xmss_adrs(layer, tree);
        let mut ends = if levels[0].is_empty() { vec![[0; N]; self.p.len()] } else { Vec::new() };
        let auth = (0..self.p.hp)
            .map(|j| {
                let sibling = (idx >> j) ^ 1;
                if levels[j].is_empty() {
                    self.xmss_node(sk_seed, &a, sibling, j as u32, &mut ends)
                } else {
                    levels[j][sibling as usize]
                }
            })
            .collect();
        a.set_type_and_clear(WOTS_HASH);
        a.set_keypair(idx);
        XmssSig {
            wots: self.wots_sign(msg, sk_seed, &a),
            auth,
        }
    }

    /// Algorithm 11.
    pub fn xmss_pk_from_sig(
        &self,
        idx: u32,
        sig: &XmssSig,
        msg: &Node,
        layer: u32,
        tree: u64,
        stats: &mut VerifyStats,
    ) -> Node {
        let mut a = Self::xmss_adrs(layer, tree);
        a.set_type_and_clear(WOTS_HASH);
        a.set_keypair(idx);
        let mut node = self.wots_pk_from_sig(&sig.wots, msg, &a, stats);
        a.set_type_and_clear(TREE);
        for k in 0..self.p.hp {
            a.set_tree_height(k as u32 + 1);
            a.set_tree_index(idx >> (k + 1));
            node = if (idx >> k) & 1 == 0 {
                self.h(&a, &node, &sig.auth[k])
            } else {
                self.h(&a, &sig.auth[k], &node)
            };
            stats.h += 1;
        }
        node
    }

    /// Algorithm 14.
    fn fors_sk(&self, sk_seed: &Node, adrs: &Adrs, idx: u32) -> Node {
        let mut a = *adrs;
        a.set_type_and_clear(FORS_PRF);
        a.set_keypair(adrs.keypair());
        a.set_tree_index(idx);
        self.prf(&a, sk_seed)
    }

    /// Algorithm 15.
    fn fors_node(&self, sk_seed: &Node, i: u32, z: u32, adrs: &Adrs) -> Node {
        let mut a = *adrs;
        if z == 0 {
            let sk = self.fors_sk(sk_seed, adrs, i);
            a.set_tree_height(0);
            a.set_tree_index(i);
            return self.f(&a, &sk);
        }
        let (l, r) = if z >= PAR_HEIGHT {
            rayon::join(
                || self.fors_node(sk_seed, 2 * i, z - 1, adrs),
                || self.fors_node(sk_seed, 2 * i + 1, z - 1, adrs),
            )
        } else {
            (
                self.fors_node(sk_seed, 2 * i, z - 1, adrs),
                self.fors_node(sk_seed, 2 * i + 1, z - 1, adrs),
            )
        };
        a.set_tree_height(z);
        a.set_tree_index(i);
        self.h(&a, &l, &r)
    }

    /// Algorithm 16.
    fn fors_sign(&self, md: &[u8], sk_seed: &Node, adrs: &Adrs) -> Vec<ForsTreeSig> {
        let (a, k) = (self.p.a as u32, self.p.k);
        let indices = base_2b(md, self.p.a, k);
        (0..k)
            .into_par_iter()
            .map(|i| {
                let i = i as u32;
                let sk = self.fors_sk(sk_seed, adrs, (i << a) + indices[i as usize]);
                let auth = (0..a)
                    .into_par_iter()
                    .map(|j| {
                        let s = (indices[i as usize] >> j) ^ 1;
                        self.fors_node(sk_seed, (i << (a - j)) + s, j, adrs)
                    })
                    .collect();
                ForsTreeSig { sk, auth }
            })
            .collect()
    }

    /// Algorithm 17.
    pub fn fors_pk_from_sig(
        &self,
        sig: &[ForsTreeSig],
        md: &[u8],
        adrs: &Adrs,
        stats: &mut VerifyStats,
    ) -> Node {
        let a = self.p.a as u32;
        let indices = base_2b(md, self.p.a, self.p.k);
        let mut ad = *adrs;
        let roots: Vec<Node> = (0..self.p.k)
            .map(|i| {
                let idx = indices[i];
                let leaf_index = ((i as u32) << a) + idx;
                ad.set_tree_height(0);
                ad.set_tree_index(leaf_index);
                let mut node = self.f(&ad, &sig[i].sk);
                stats.f += 1;
                for j in 0..a {
                    ad.set_tree_height(j + 1);
                    ad.set_tree_index(leaf_index >> (j + 1));
                    node = if (idx >> j) & 1 == 0 {
                        self.h(&ad, &node, &sig[i].auth[j as usize])
                    } else {
                        self.h(&ad, &sig[i].auth[j as usize], &node)
                    };
                    stats.h += 1;
                }
                node
            })
            .collect();
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(FORS_ROOTS);
        pk_adrs.set_keypair(adrs.keypair());
        stats.t += 1;
        self.t(&pk_adrs, &roots)
    }

    /// Lines 7-11 of Algorithms 19 and 20: (md, idx_tree, idx_leaf).
    pub fn split_digest<'a>(&self, digest: &'a [u8]) -> (&'a [u8], u64, u32) {
        let p = &self.p;
        let (md, rest) = digest.split_at(p.md_bytes());
        let (tree_b, rest) = rest.split_at(p.tree_bytes());
        let leaf_b = &rest[..p.leaf_bytes()];
        let idx_tree = low_bits(to_int(tree_b), p.tree_bits());
        let idx_leaf = low_bits(to_int(leaf_b), p.hp) as u32;
        (md, idx_tree, idx_leaf)
    }

    fn fors_adrs(idx_tree: u64, idx_leaf: u32) -> Adrs {
        let mut a = Adrs::default();
        a.set_tree(idx_tree);
        a.set_type_and_clear(FORS_TREE);
        a.set_keypair(idx_leaf);
        a
    }

    /// Algorithm 20 (slh_verify_internal), also counting the hash calls.
    pub fn verify_internal(
        &self,
        pk_root: &Node,
        msg: &[u8],
        sig: &SlhSignature,
    ) -> (bool, VerifyStats) {
        let p = &self.p;
        let mut stats = VerifyStats::default();
        if !sig.has_shape(p) {
            return (false, stats);
        }
        let digest = self.h_msg(&sig.r, pk_root, msg);
        let (md, mut idx_tree, mut idx_leaf) = self.split_digest(&digest);
        let adrs = Self::fors_adrs(idx_tree, idx_leaf);
        let mut node = self.fors_pk_from_sig(&sig.fors, md, &adrs, &mut stats);
        // Algorithm 13.
        for (j, x) in sig.ht.iter().enumerate() {
            if j > 0 {
                idx_leaf = low_bits(idx_tree, p.hp) as u32;
                idx_tree >>= p.hp;
            }
            node = self.xmss_pk_from_sig(idx_leaf, x, &node, j as u32, idx_tree, &mut stats);
        }
        (node == *pk_root, stats)
    }
}

/// M' of Algorithms 22 and 24 for the pure variant: 0 || |ctx| || ctx || M.
pub fn pure_message(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255);
    let mut out = Vec::with_capacity(2 + ctx.len() + msg.len());
    out.push(0);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(msg);
    out
}

pub struct SlhKey {
    pub ctx: SlhCtx,
    pub sk_seed: Node,
    pub sk_prf: Node,
    pub pk_root: Node,
    /// Cached levels of the top-layer tree. Omitted lower levels are empty.
    top_levels: Vec<Vec<Node>>,
}

impl SlhKey {
    /// Algorithm 18, SHA2 instantiation.
    pub fn keygen_internal(p: SlhParams, sk_seed: &Node, sk_prf: &Node, pk_seed: &Node) -> Self {
        Self::keygen_internal_with(p, HashFamily::Sha2, sk_seed, sk_prf, pk_seed)
    }

    /// Algorithm 18.
    pub fn keygen_internal_with(
        p: SlhParams,
        family: HashFamily,
        sk_seed: &Node,
        sk_prf: &Node,
        pk_seed: &Node,
    ) -> Self {
        let ctx = SlhCtx::with_family(p, family, pk_seed);
        // Keep short trees whole. At h' = 22, keeping heights 6..22 costs
        // 2 MiB per key; signing recomputes 63 WOTS leaves on the selected path.
        let first_height = p.hp.saturating_sub(16).min(6);
        let top_levels = ctx.xmss_levels_from(sk_seed, (p.d - 1) as u32, 0, first_height);
        let pk_root = top_levels[p.hp][0];
        Self {
            ctx,
            sk_seed: *sk_seed,
            sk_prf: *sk_prf,
            pk_root,
            top_levels,
        }
    }

    pub fn pk_seed(&self) -> &Node {
        &self.ctx.pk_seed
    }

    /// The first stored height of the top-layer tree, and the stored levels
    /// from there to the root, the part `from_top_cache` takes back.
    pub fn top_cache(&self) -> (usize, &[Vec<Node>]) {
        let first = self.top_levels.iter().take_while(|l| l.is_empty()).count();
        (first, &self.top_levels[first..])
    }

    /// Rebuilds a key from its seeds and `top_cache`, without key generation.
    /// None unless the levels form the top-layer tree's upper part, rooted at
    /// `pk_root`.
    pub fn from_top_cache(
        p: SlhParams,
        family: HashFamily,
        sk_seed: &Node,
        sk_prf: &Node,
        pk_seed: &Node,
        pk_root: &Node,
        first: usize,
        levels: Vec<Vec<Node>>,
    ) -> Option<Self> {
        let ctx = SlhCtx::with_family(p, family, pk_seed);
        let shaped = first <= p.hp
            && levels.len() == p.hp - first + 1
            && levels.iter().enumerate().all(|(k, l)| l.len() == 1 << (p.hp - first - k));
        if !shaped || levels[p.hp - first][0] != *pk_root {
            return None;
        }
        let base = SlhCtx::xmss_adrs((p.d - 1) as u32, 0);
        for k in 1..levels.len() {
            let z = (first + k) as u32;
            let ok = levels[k].par_iter().enumerate().all(|(i, node)| {
                *node == ctx.xmss_parent(&base, i as u32, z, &levels[k - 1][2 * i], &levels[k - 1][2 * i + 1])
            });
            if !ok {
                return None;
            }
        }
        let mut top_levels = vec![Vec::new(); first];
        top_levels.extend(levels);
        Some(Self {
            ctx,
            sk_seed: *sk_seed,
            sk_prf: *sk_prf,
            pk_root: *pk_root,
            top_levels,
        })
    }

    /// Algorithm 12, reusing the cached top tree.
    fn ht_sign(&self, msg: &Node, idx_tree: u64, idx_leaf: u32) -> Vec<XmssSig> {
        let c = &self.ctx;
        let p = &c.p;
        let (mut tree, mut leaf, mut node) = (idx_tree, idx_leaf, *msg);
        let mut sigs = Vec::with_capacity(p.d);
        for j in 0..p.d {
            if j > 0 {
                leaf = low_bits(tree, p.hp) as u32;
                tree >>= p.hp;
            }
            let computed;
            let levels = if j == p.d - 1 {
                debug_assert_eq!(tree, 0);
                &self.top_levels
            } else {
                computed = c.xmss_levels(&self.sk_seed, j as u32, tree);
                &computed
            };
            sigs.push(c.xmss_sign(&node, &self.sk_seed, leaf, j as u32, tree, levels));
            node = levels[p.hp][0];
        }
        sigs
    }

    /// Algorithm 19; `addrnd = None` is the deterministic variant.
    pub fn sign_internal(&self, msg: &[u8], addrnd: Option<&Node>) -> SlhSignature {
        let c = &self.ctx;
        let opt_rand = addrnd.unwrap_or(&c.pk_seed);
        let r = c.prf_msg(&self.sk_prf, opt_rand, msg);
        let digest = c.h_msg(&r, &self.pk_root, msg);
        let (md, idx_tree, idx_leaf) = c.split_digest(&digest);
        let adrs = SlhCtx::fors_adrs(idx_tree, idx_leaf);
        let fors = c.fors_sign(md, &self.sk_seed, &adrs);
        let pk_fors = c.fors_pk_from_sig(&fors, md, &adrs, &mut VerifyStats::default());
        let ht = self.ht_sign(&pk_fors, idx_tree, idx_leaf);
        SlhSignature { r, fors, ht }
    }

    /// Pure SLH-DSA with an empty context (Algorithm 22, lines 6-8).
    pub fn sign(&self, msg: &[u8], addrnd: Option<&Node>) -> SlhSignature {
        self.sign_internal(&pure_message(msg, &[]), addrnd)
    }
}

/// Pure SLH-DSA verification with an empty context (Algorithm 24), SHA2.
pub fn slh_verify(
    p: SlhParams,
    pk_seed: &Node,
    pk_root: &Node,
    msg: &[u8],
    sig: &SlhSignature,
) -> bool {
    slh_verify_with(p, HashFamily::Sha2, pk_seed, pk_root, msg, sig)
}

/// Pure SLH-DSA verification with an empty context (Algorithm 24).
pub fn slh_verify_with(
    p: SlhParams,
    family: HashFamily,
    pk_seed: &Node,
    pk_root: &Node,
    msg: &[u8],
    sig: &SlhSignature,
) -> bool {
    SlhCtx::with_family(p, family, pk_seed)
        .verify_internal(pk_root, &pure_message(msg, &[]), sig)
        .0
}

impl SlhSignature {
    /// Parses the FIPS 205 encoding R || SIG_FORS || SIG_HT.
    pub fn from_bytes(p: &SlhParams, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != p.sig_bytes() {
            return None;
        }
        let mut nodes = bytes.chunks_exact(N).map(|c| -> Node { c.try_into().unwrap() });
        let mut take = |n: usize| -> Vec<Node> { (0..n).map(|_| nodes.next().unwrap()).collect() };
        let r = take(1)[0];
        let fors = (0..p.k)
            .map(|_| ForsTreeSig {
                sk: take(1)[0],
                auth: take(p.a),
            })
            .collect();
        let ht = (0..p.d)
            .map(|_| XmssSig {
                wots: take(p.len()),
                auth: take(p.hp),
            })
            .collect();
        Some(Self { r, fors, ht })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_resumed_from_its_top_cache_signs_identically() {
        let p = SlhParams { name: "toy-w4-d1", h: 6, d: 1, hp: 6, a: 5, k: 6, lg_w: 2, m: 5 };
        let (sk_seed, sk_prf, pk_seed) = ([0x11; N], [0x22; N], [0x33; N]);
        for family in [HashFamily::Sha2, HashFamily::Shake] {
            let full = SlhKey::keygen_internal_with(p, family, &sk_seed, &sk_prf, &pk_seed);
            let (first, levels) = full.top_cache();
            assert_eq!((first, levels.len()), (0, p.hp + 1));
            for cut in [0, 2, p.hp] {
                let levels = full.ctx.xmss_levels_from(&sk_seed, 0, 0, cut)[cut..].to_vec();
                let resume = |levels: Vec<Vec<Node>>, root: &Node| {
                    SlhKey::from_top_cache(p, family, &sk_seed, &sk_prf, &pk_seed, root, cut, levels)
                };
                let resumed = resume(levels.clone(), &full.pk_root).unwrap();
                assert_eq!(resumed.top_cache().0, cut);
                for msg in [&b"one"[..], b"two", b"three"] {
                    assert_eq!(resumed.sign_internal(msg, None), full.sign_internal(msg, None));
                }
                let mut wrong_root = full.pk_root;
                wrong_root[0] ^= 1;
                assert!(resume(levels.clone(), &wrong_root).is_none());
                assert!(resume(levels[1..].to_vec(), &full.pk_root).is_none());
                if cut < p.hp {
                    let mut bad = levels.clone();
                    bad[0][0][0] ^= 1;
                    assert!(resume(bad, &full.pk_root).is_none(), "cut {cut}");
                }
            }
        }
    }

    #[test]
    fn partial_cache_reproduces_full_tree_and_authentication_paths() {
        let p = SlhParams { name: "toy-w16-d7", h: 28, d: 7, hp: 4, a: 12, k: 14, lg_w: 4, m: 25 };
        let seed = [0x91; N];
        for family in [HashFamily::Sha2, HashFamily::Shake] {
            let ctx = SlhCtx::with_family(p, family, &[0x24; N]);
            let (layer, tree) = (2, 19);
            let full = ctx.xmss_levels(&seed, layer, tree);
            for cut in [1, 3, p.hp] {
                let partial = ctx.xmss_levels_from(&seed, layer, tree, cut);
                assert!(partial[..cut].iter().all(Vec::is_empty));
                assert_eq!(partial[cut..], full[cut..]);
                for idx in 0..(1 << p.hp) {
                    let sign = |levels: &[Vec<Node>]| {
                        ctx.xmss_sign(&[0x52; N], &seed, idx, layer, tree, levels)
                    };
                    assert_eq!(sign(&partial), sign(&full));
                }
            }
        }
    }
}
