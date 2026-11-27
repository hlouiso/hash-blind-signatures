//! SHA-256 over byte strings built from constant and wire chunks, for the
//! XMSS and SLH-DSA circuits.
//!
//! Every value is a big-endian 32-bit word in the low half of a wire, the
//! layout of upstream's `sha256_compress`. A chunk is the low `len` bytes of a
//! value, appended big-endian, so a field that sits at an unaligned offset
//! costs only shifts and XORs.

use std::array;
use std::cell::RefCell;
use std::collections::HashMap;

use binius_circuits::sha256::{State, sha256_compress};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// The SHA-256 initial hash value.
pub const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A value below 2^32, fixed at build time or carried by a wire.
#[derive(Clone, Copy)]
pub enum V32 {
    C(u32),
    W(Wire),
}

/// The low `len` bytes of a value, appended big-endian to a byte stream.
#[derive(Clone, Copy)]
pub struct Chunk {
    pub v: V32,
    pub len: usize,
}

/// A constant chunk.
pub fn c(v: u32, len: usize) -> Chunk {
    Chunk { v: V32::C(v), len }
}

/// A whole 32-bit word.
pub fn wire(w: Wire) -> Chunk {
    Chunk {
        v: V32::W(w),
        len: 4,
    }
}

/// A wire that holds a value below 2^(8 len) with an empty high half.
pub fn wire_bytes(w: Wire, len: usize) -> Chunk {
    Chunk { v: V32::W(w), len }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shift {
    Shl(u32),
    Shr(u32),
    Sll32(u32),
}

impl Shift {
    fn apply(self, x: u32) -> u32 {
        match self {
            Shift::Shl(s) | Shift::Sll32(s) => x.checked_shl(s).unwrap_or(0),
            Shift::Shr(s) => x.checked_shr(s).unwrap_or(0),
        }
    }
}

/// A circuit builder with shared constants and shifted wires.
pub struct ShaStream<'a> {
    pub b: &'a CircuitBuilder,
    shifts: RefCell<HashMap<(Wire, Shift), Wire>>,
    consts: RefCell<HashMap<u64, Wire>>,
}

impl<'a> ShaStream<'a> {
    pub fn new(b: &'a CircuitBuilder) -> Self {
        Self {
            b,
            shifts: RefCell::new(HashMap::new()),
            consts: RefCell::new(HashMap::new()),
        }
    }

    pub fn konst(&self, v: u64) -> Wire {
        *self
            .consts
            .borrow_mut()
            .entry(v)
            .or_insert_with(|| self.b.add_constant(Word(v)))
    }

    pub fn shift(&self, w: Wire, s: Shift) -> Wire {
        if matches!(s, Shift::Shl(0) | Shift::Shr(0) | Shift::Sll32(0)) {
            return w;
        }
        if let Some(&r) = self.shifts.borrow().get(&(w, s)) {
            return r;
        }
        let r = match s {
            Shift::Shl(n) => self.b.shl(w, n),
            Shift::Shr(n) => self.b.shr(w, n),
            Shift::Sll32(n) => self.b.sll32(w, n),
        };
        self.shifts.borrow_mut().insert((w, s), r);
        r
    }

    /// The SHA-256 blocks of `chunks`, padded for a message that follows
    /// `prefix_bytes` already-compressed bytes. Wire chunks must hold values
    /// below 2^(8 len) with an empty high half.
    pub fn assemble(&self, chunks: &[Chunk], prefix_bytes: usize) -> Vec<[Wire; 16]> {
        let body: usize = chunks.iter().map(|c| c.len).sum();
        let nbytes = (body + 9).div_ceil(64) * 64;
        let bit_len = ((prefix_bytes + body) as u64) * 8;
        let mut consts = vec![0u32; nbytes / 4];
        let mut vars: Vec<Vec<Wire>> = vec![Vec::new(); nbytes / 4];

        let mut place = |ch: Chunk, p: usize| {
            let (r, k) = (p % 4, p / 4);
            let mut add = |k: usize, s: Shift| match ch.v {
                V32::C(x) => consts[k] ^= s.apply(x),
                V32::W(w) => vars[k].push(self.shift(w, s)),
            };
            if r + ch.len <= 4 {
                add(k, Shift::Shl((8 * (4 - r - ch.len)) as u32));
            } else {
                let rest = ch.len - (4 - r);
                add(k, Shift::Shr((8 * rest) as u32));
                add(k + 1, Shift::Sll32((8 * (4 - rest)) as u32));
            }
        };
        let mut p = 0;
        for &ch in chunks {
            assert!((1..=4).contains(&ch.len));
            place(ch, p);
            p += ch.len;
        }
        place(c(0x80, 1), p);
        place(c((bit_len >> 32) as u32, 4), nbytes - 8);
        place(c(bit_len as u32, 4), nbytes - 4);

        let words: Vec<Wire> = consts
            .into_iter()
            .zip(vars)
            .map(|(k, mut v)| {
                if k != 0 || v.is_empty() {
                    v.push(self.konst(k as u64));
                }
                if v.len() == 1 {
                    v[0]
                } else {
                    self.b.bxor_multi(&v)
                }
            })
            .collect();
        words
            .chunks_exact(16)
            .map(|blk| array::from_fn(|i| blk[i]))
            .collect()
    }

    pub fn sha256(&self, init: [Wire; 8], blocks: Vec<[Wire; 16]>) -> [Wire; 8] {
        let mut st = State(init);
        for blk in blocks {
            st = sha256_compress(self.b, st, blk);
        }
        st.0
    }

    pub fn iv(&self) -> [Wire; 8] {
        array::from_fn(|i| self.konst(SHA256_IV[i] as u64))
    }
}
