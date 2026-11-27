// Copyright 2026 The Binius Developers
// Copyright (c) 2026 leanEthereum
//! WOTS (Winternitz one-time signature) with target-sum encoding.
//!
//! There are no checksum chains. Instead the signer grinds the signature randomness until the
//! encoding's digits sum to [`TARGET_SUM`], and a verifier that checks the sum knows no digit can
//! have been lowered without another being raised.
//!
//! Upstream's `hash_based_sig::wots`, with the hashes of [`super::hashing`].

use std::iter;

use binius_circuits::bytes::swap_bytes_32;
use binius_circuits::multiplexer::multi_wire_multiplex;
use binius_core::Word;
use binius_frontend::{Hint, Wire};
use rand::CryptoRng;

use super::{
    CHAIN_LENGTH, DIGEST_LEN, DIGEST_WIRES, Digest, MESSAGE_WORDS, Message, NUM_CHAIN_HASHES,
    PUBLIC_PARAM_LEN, PUBLIC_PARAM_WIRES, PublicParam, RANDOMNESS_LEN, RANDOMNESS_WIRES,
    Randomness, TARGET_SUM, V, W,
    hashing::{NodeW, XmssHasher, chain_hash, leaf_hash, message_hash},
};

/// Digits carried by each of the digest's two 64-bit words.
const DIGITS_PER_WORD: usize = V / 2;

const _: () = assert!(2 * DIGITS_PER_WORD == V);

/// The target-sum encoding.
///
/// `D` is the first 16 bytes of the message hash. Each of its two little-endian 64-bit words
/// holds 21 digits of [`W`] bits: digit `i < 21` at bits `3i` of word 0, digit `i >= 21` at bits
/// `3(i - 21)` of word 1.
///
/// The encoding is valid exactly when the leftover top bit of *each* word (bits 63 and 127) is
/// zero and the digits sum to [`TARGET_SUM`].
///
/// Returns `None` when the randomness does not produce a valid encoding, which is the signal the
/// grinding loop retries on.
pub fn wots_encode(
    message: &Message,
    epoch: u32,
    public_param: &PublicParam,
    randomness: &Randomness,
) -> Option<[u8; V]> {
    let hash = message_hash(public_param, epoch, randomness, message);
    let digest = &hash[..DIGEST_LEN];

    if digest[7] >> 7 != 0 || digest[DIGEST_LEN - 1] >> 7 != 0 {
        return None; // the leftover top bit of each 64-bit word must be zero
    }
    let bit = |j: usize| (digest[j / 8] >> (j % 8)) & 1;
    let pos = |i: usize| {
        if i < DIGITS_PER_WORD {
            W * i
        } else {
            64 + W * (i - DIGITS_PER_WORD)
        }
    };
    let encoding: [u8; V] =
        std::array::from_fn(|i| (0..W).fold(0, |acc, k| acc | (bit(pos(i) + k) << k)));
    (encoding.iter().map(|&x| x as usize).sum::<usize>() == TARGET_SUM).then_some(encoding)
}

/// Draws randomness until it encodes validly, about `2^14.85` attempts on average.
pub fn find_randomness_for_wots_encoding(
    message: &Message,
    epoch: u32,
    public_param: &PublicParam,
    rng: &mut impl CryptoRng,
) -> (Randomness, [u8; V]) {
    loop {
        let mut randomness = [0u8; RANDOMNESS_LEN];
        rng.fill_bytes(&mut randomness);
        if let Some(encoding) = wots_encode(message, epoch, public_param, &randomness) {
            return (randomness, encoding);
        }
    }
}

/// One chain step, from chain value `step` to `step + 1`.
pub fn chain_step(
    public_param: &PublicParam,
    epoch: u32,
    chain_index: usize,
    step: usize,
    x: &Digest,
) -> Digest {
    chain_hash(public_param, epoch, x, chain_index as u8, (step + 1) as u8)
}

/// Walks chain `chain_index` for `n` steps starting at chain value `start_step`.
pub fn iterate_hash(
    a: &Digest,
    n: usize,
    public_param: &PublicParam,
    epoch: u32,
    chain_index: usize,
    start_step: usize,
) -> Digest {
    (0..n).fold(*a, |acc, j| {
        chain_step(public_param, epoch, chain_index, start_step + j, &acc)
    })
}

/// Walks every chain from its tip to the public-key end.
pub fn recover_public_key(
    chain_tips: &[Digest; V],
    encoding: &[u8; V],
    epoch: u32,
    public_param: &PublicParam,
) -> [Digest; V] {
    std::array::from_fn(|i| {
        let digit = encoding[i] as usize;
        iterate_hash(
            &chain_tips[i],
            CHAIN_LENGTH - 1 - digit,
            public_param,
            epoch,
            i,
            digit,
        )
    })
}

/// The Merkle leaf: the hash over the [`V`] concatenated chain ends.
pub fn wots_public_key_hash(
    public_param: &PublicParam,
    epoch: u32,
    chain_ends: &[Digest; V],
) -> Digest {
    leaf_hash(public_param, epoch, chain_ends)
}

/// In-circuit form of [`wots_encode`], returning the digits and constraining them to be a valid
/// encoding.
///
/// Both validity conditions are asserted rather than returned: an encoding whose leftover bits are
/// set, or whose digits miss the target sum, has no satisfying witness.
pub fn circuit_wots_encode(
    h: &XmssHasher<'_>,
    message: &[Wire; MESSAGE_WORDS],
    randomness: &[Wire; RANDOMNESS_WIRES],
) -> [Wire; V] {
    let builder = h.builder();
    let zero = builder.add_constant_64(0);

    let randomness: [Wire; 2 * RANDOMNESS_WIRES] =
        h.unpack_words(randomness).try_into().expect("six words");
    let hash = h.message(&randomness, message);

    // The first 16 digest bytes as two little-endian 64-bit words: swapping the bytes within each
    // 32-bit half of `hash[1] || hash[0]` turns big-endian words into little-endian ones.
    let digest: [Wire; 2] = std::array::from_fn(|k| {
        let pair = builder.bxor(builder.shl(hash[2 * k + 1], 32), hash[2 * k]);
        swap_bytes_32(builder, pair)
    });

    // With `V * W = 126` of the digest's 128 bits spent on digits, the two leftover top bits are
    // what would otherwise let a word carry a slack term the digits do not account for.
    for (k, &word) in digest.iter().enumerate() {
        builder.assert_zero(format!("encoding_leftover_bit[{k}]"), builder.shr(word, 63));
    }

    // A digit is W bits from the middle of its word: lift them to the top of the word, then drop
    // them back to the bottom, so nothing above or below them survives.
    let digits: [Wire; V] = std::array::from_fn(|i| {
        let word = digest[i / DIGITS_PER_WORD];
        let shift = (W * (i % DIGITS_PER_WORD)) as u32;
        builder.shr(
            builder.shl(word, u64::BITS - shift - W as u32),
            u64::BITS - W as u32,
        )
    });

    // The digits are each below CHAIN_LENGTH by construction, so the sum cannot overflow.
    let sum = digits
        .iter()
        .fold(zero, |acc, &digit| builder.iadd(acc, digit).0);
    builder.assert_eq(
        "encoding_target_sum",
        sum,
        builder.add_constant_64(TARGET_SUM as u64),
    );

    digits
}

/// Words per chain hash: the packed input digest and a packed (chain, count, digit).
const HINT_WORDS_PER_HASH: usize = DIGEST_WIRES + 1;

/// Words the hint reads.
const HINT_INPUTS: usize = PUBLIC_PARAM_WIRES + 1 + V + V * DIGEST_WIRES;

/// Words the hint writes: one entry per chain hash, then where each chain's last entry sits.
const HINT_OUTPUTS: usize = NUM_CHAIN_HASHES * HINT_WORDS_PER_HASH + V;

/// Computes the chain hashes a verifier actually walks, and where each chain's last one sits.
///
/// The verifier's work is the concatenation of the chain tails: chain `i` contributes its steps
/// from `digit_i` up to `CHAIN_LENGTH - 2`, and the tails run in chain order. How long each tail
/// is depends on the digits, so the list cannot be laid out at circuit construction time — it is
/// hinted here and pinned by the constraints in [`circuit_recover_public_key`].
struct ChainHashesHint;

impl Hint for ChainHashesHint {
    const NAME: &'static str = "blind.xmss_sha256_chain_hashes";

    fn shape(&self, _dimensions: &[usize]) -> (usize, usize) {
        (HINT_INPUTS, HINT_OUTPUTS)
    }

    fn execute(&self, _dimensions: &[usize], inputs: &[Word], outputs: &mut [Word]) {
        let public_param = bytes_from_words::<PUBLIC_PARAM_LEN>(&inputs[..PUBLIC_PARAM_WIRES]);
        let epoch = inputs[PUBLIC_PARAM_WIRES].as_u64() as u32;
        let digits = &inputs[PUBLIC_PARAM_WIRES + 1..][..V];
        let tips = &inputs[PUBLIC_PARAM_WIRES + 1 + V..];

        let (hashes, offsets) = outputs.split_at_mut(NUM_CHAIN_HASHES * HINT_WORDS_PER_HASH);
        hashes.fill(Word::ZERO);
        offsets.fill(Word::ZERO);

        let mut written = 0;
        for i in 0..V {
            let digit = digits[i].as_u64() as usize;
            let mut current =
                bytes_from_words::<DIGEST_LEN>(&tips[i * DIGEST_WIRES..][..DIGEST_WIRES]);

            // A chain walks from its digit to the last step. A digit of `CHAIN_LENGTH - 1` walks
            // nothing, and a digit past that (an unsatisfiable witness) walks nothing either.
            for (step, position) in (digit..CHAIN_LENGTH - 1).enumerate() {
                // Digits that miss the target sum overrun the list. The encoding constraints
                // reject them, so stopping short here only has to avoid a panic.
                if written == NUM_CHAIN_HASHES {
                    break;
                }
                let slot = &mut hashes[written * HINT_WORDS_PER_HASH..][..HINT_WORDS_PER_HASH];
                bytes_to_words(&current, &mut slot[..DIGEST_WIRES]);
                let count = step + 1;
                let label = (i << (2 * W)) | (count << W) | digit;
                slot[DIGEST_WIRES] = Word::from_u64(label as u64);

                current = chain_step(&public_param, epoch, i, position, &current);
                written += 1;
                // An empty chain leaves its offset at zero; nothing reads it.
                offsets[i] = Word::from_u64((written - 1) as u64);
            }
        }
    }
}

/// Big-endian bytes from packed 64-bit words.
fn bytes_from_words<const N: usize>(words: &[Word]) -> [u8; N] {
    let mut bytes = [0u8; N];
    let (chunks, _) = bytes.as_chunks_mut::<8>();
    for (chunk, word) in iter::zip(chunks, words) {
        chunk.copy_from_slice(&word.as_u64().to_be_bytes());
    }
    bytes
}

/// The inverse of [`bytes_from_words`].
fn bytes_to_words(bytes: &[u8], words: &mut [Word]) {
    let (chunks, _) = bytes.as_chunks::<8>();
    for (word, &chunk) in iter::zip(words, chunks) {
        *word = Word::from_u64(u64::from_be_bytes(chunk));
    }
}

/// In-circuit form of [`recover_public_key`], spending only the hashes a verifier walks.
///
/// A chain's tail is `CHAIN_LENGTH - 1 - digit` hashes, and the target sum fixes the total across
/// all chains at [`NUM_CHAIN_HASHES`] however the digits fall. So rather than give every chain
/// room for its longest possible tail — `V * (CHAIN_LENGTH - 1)` hashes, two thirds of them
/// discarded — the tails are concatenated into one list of exactly that total, hinted, and pinned
/// by constraints. Each entry carries its input digest, its chain, its digit, and the number of
/// hashes through this entry; its output is the hash, not a hinted value, so nothing has
/// to check it.
///
/// # What pins the list
///
/// - `chain` only ever increases, so a chain's entries are one contiguous run.
/// - Within a run the step advances by one, the digit holds, and each input is the previous output.
/// - A run opens at count one, and so does the list.
///
/// Then one lookup per chain finds that chain's last entry, and checks it belongs to this chain,
/// carries this chain's digit, and sits at the last position — `digit + count == CHAIN_LENGTH - 1`.
///
/// A run's length is therefore at least `CHAIN_LENGTH - 1 - digit`, the runs are disjoint, and the
/// target sum makes those lengths add up to the list. So every run has exactly that length and no
/// entry belongs to anything but a walking chain: every chain index is below [`V`] and every
/// position at most `CHAIN_LENGTH - 1`, which is what lets each fill one byte of its hash.
///
/// Each run carries its first input through to its last row. The endpoint lookup also checks
/// that first input against this chain's signature tip.
///
/// Chain tips come in and chain ends go out packed, two wires per digest.
pub fn circuit_recover_public_key(
    h: &XmssHasher<'_>,
    public_param: &[Wire; PUBLIC_PARAM_WIRES],
    chain_tips: &[[Wire; DIGEST_WIRES]; V],
    digits: &[Wire; V],
) -> [[Wire; DIGEST_WIRES]; V] {
    let builder = h.builder();
    let epoch = h.epoch();
    let mut hint_inputs = Vec::with_capacity(HINT_INPUTS);
    hint_inputs.extend_from_slice(public_param);
    hint_inputs.push(epoch);
    hint_inputs.extend_from_slice(digits);
    hint_inputs.extend(chain_tips.iter().flatten().copied());
    let hinted = builder.call_hint(ChainHashesHint, &[], &hint_inputs);

    let input_of = |k: usize| -> [Wire; DIGEST_WIRES] {
        std::array::from_fn(|w| hinted[k * HINT_WORDS_PER_HASH + w])
    };
    let label_of = |k: usize| hinted[k * HINT_WORDS_PER_HASH + DIGEST_WIRES];
    let mask = builder.add_constant_64((CHAIN_LENGTH - 1) as u64);
    let chains: [_; NUM_CHAIN_HASHES] =
        std::array::from_fn(|k| builder.shr(label_of(k), (2 * W) as u32));
    let counts: [_; NUM_CHAIN_HASHES] =
        std::array::from_fn(|k| builder.band(builder.shr(label_of(k), W as u32), mask));
    let digits_at: [_; NUM_CHAIN_HASHES] = std::array::from_fn(|k| builder.band(label_of(k), mask));
    let offset_of = |i: usize| hinted[NUM_CHAIN_HASHES * HINT_WORDS_PER_HASH + i];

    // Where a chain's last entry can sit. Chains before this one contribute at most
    // `CHAIN_LENGTH - 1` entries each and so do the chains after, which pins the last entry of
    // chain `i` into a window of the list — and only that window has to be muxed over.
    let window = |i: usize| -> (usize, usize) {
        let per_chain = CHAIN_LENGTH - 1;
        let earliest = (NUM_CHAIN_HASHES).saturating_sub((V - i) * per_chain);
        let latest = ((i + 1) * per_chain - 1).min(NUM_CHAIN_HASHES - 1);
        (earliest, latest)
    };

    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);

    // Hinting the inputs makes adjacent hashes independent. Pack pairs into
    // SHA-256's two lanes, then handle the odd last entry in a single lane.
    let entry = |k: usize| {
        let landing = builder.iadd(digits_at[k], counts[k]).0;
        (h.unpack(&input_of(k)), chains[k], landing)
    };
    let mut outputs = Vec::with_capacity(NUM_CHAIN_HASHES);
    for k in (0..NUM_CHAIN_HASHES - 1).step_by(2) {
        let (x, i, pos) = entry(k);
        let (y, j, next_pos) = entry(k + 1);
        outputs.extend(h.chain_pair([(&x, i, pos), (&y, j, next_pos)]));
    }
    if NUM_CHAIN_HASHES % 2 != 0 {
        let (x, i, pos) = entry(NUM_CHAIN_HASHES - 1);
        outputs.push(h.pack(&h.chain(&x, i, pos)));
    }

    // Walking the list: every rule here is local, which is what leaves the entries with nothing
    // to look up.
    let mut starts = Vec::with_capacity(NUM_CHAIN_HASHES);
    starts.push(input_of(0));
    for k in 0..NUM_CHAIN_HASHES {
        let b = builder.subcircuit(format!("chain_hash[{k}]"));
        let (chain, count) = (chains[k], counts[k]);

        let Some(previous) = k.checked_sub(1) else {
            // The list opens a chain, so it opens at its first hash.
            b.assert_eq("first_count_is_one", count, one);
            continue;
        };

        // An entry either continues the one before it or opens a new chain. The chain field is
        // what says which, and it only ever increases, so a chain's entries stay contiguous.
        let continues = b.icmp_eq(chain, chains[previous]);
        starts.push(std::array::from_fn(|w| {
            b.select(continues, starts[previous][w], input_of(k)[w])
        }));
        b.assert_true("chain_non_decreasing", b.icmp_ule(chains[previous], chain));

        // Continuing: one more hash of the same chain, on the value the last one produced.
        let next_count = b.iadd(counts[previous], one).0;
        b.assert_eq("chain_count", count, b.select(continues, next_count, one));
        b.assert_eq(
            "digit_holds",
            b.select(continues, digits_at[k], digits_at[previous]),
            digits_at[previous],
        );
        for w in 0..DIGEST_WIRES {
            let carried = outputs[previous][w];
            b.assert_eq(
                format!("input_continues[{w}]"),
                b.select(continues, input_of(k)[w], carried),
                carried,
            );
        }
    }

    // One lookup per chain, into the window its last entry has to sit in. What the offset lands
    // on is checked, so the offset itself needs no pinning.
    std::array::from_fn(|i| {
        let b = builder.subcircuit(format!("chain_end[{i}]"));
        let (earliest, latest) = window(i);
        let entries = (earliest..=latest)
            .map(|k| {
                [
                    label_of(k),
                    outputs[k][0],
                    outputs[k][1],
                    starts[k][0],
                    starts[k][1],
                ]
            })
            .collect::<Vec<_>>();
        let rows = entries.iter().map(|e| e.as_slice()).collect::<Vec<_>>();

        let earliest_wire = b.add_constant_64(earliest as u64);
        let index = b.isub_bin_bout(offset_of(i), earliest_wire, zero).0;
        let found = multi_wire_multiplex(&b, &rows, index);
        let end = [found[1], found[2]];

        // Last count = 2^W - 1 - digit, the W-bit complement of digit.
        // The full label equality binds all three fields in a single lookup.
        let walks = b.bnot(b.icmp_eq(digits[i], mask));
        let expected = b.bxor_multi(&[
            b.add_constant_64((i << (2 * W)) as u64),
            b.shl(b.bxor(mask, digits[i]), W as u32),
            digits[i],
        ]);
        b.assert_eq(
            "chain_end_label",
            b.select(walks, found[0], expected),
            expected,
        );

        std::array::from_fn(|w| {
            let tip = chain_tips[i][w];
            b.assert_eq("chain_start_tip", b.select(walks, found[3 + w], tip), tip);
            b.select(walks, end[w], tip)
        })
    })
}

/// In-circuit form of [`wots_public_key_hash`], over packed chain ends.
pub fn circuit_wots_public_key_hash(
    h: &XmssHasher<'_>,
    chain_ends: &[[Wire; DIGEST_WIRES]; V],
) -> NodeW {
    let ends: [NodeW; V] = std::array::from_fn(|i| h.unpack(&chain_ends[i]));
    h.leaf(&ends)
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;
    use binius_frontend::CircuitBuilder;

    use crate::ts_xmss::{MESSAGE_LEN, hashing::pack_be};

    /// A signature at `epoch`: random chain preimages walked to the digits the message encodes to.
    struct TestSignature {
        public_param: PublicParam,
        message: Message,
        randomness: Randomness,
        encoding: [u8; V],
        chain_tips: [Digest; V],
        chain_ends: [Digest; V],
    }

    impl TestSignature {
        fn generate(rng: &mut StdRng, epoch: u32) -> Self {
            let mut public_param = [0u8; PUBLIC_PARAM_LEN];
            rng.fill_bytes(&mut public_param);
            let mut message = [0u8; MESSAGE_LEN];
            rng.fill_bytes(&mut message);

            let (randomness, encoding) =
                find_randomness_for_wots_encoding(&message, epoch, &public_param, rng);

            let mut pre_images = [[0u8; DIGEST_LEN]; V];
            for pre_image in pre_images.iter_mut() {
                rng.fill_bytes(pre_image);
            }
            let chain_tips: [Digest; V] = std::array::from_fn(|i| {
                iterate_hash(
                    &pre_images[i],
                    encoding[i] as usize,
                    &public_param,
                    epoch,
                    i,
                    0,
                )
            });
            let chain_ends = recover_public_key(&chain_tips, &encoding, epoch, &public_param);

            Self {
                public_param,
                message,
                randomness,
                encoding,
                chain_tips,
                chain_ends,
            }
        }
    }

    #[test]
    fn encoding_is_valid_by_construction() {
        let mut rng = StdRng::seed_from_u64(0);
        let sig = TestSignature::generate(&mut rng, 7);
        assert_eq!(
            sig.encoding.iter().map(|&e| e as usize).sum::<usize>(),
            TARGET_SUM
        );
        assert!(sig.encoding.iter().all(|&e| (e as usize) < CHAIN_LENGTH));
    }

    #[test]
    fn the_fixture_covers_empty_and_walked_chains() {
        let mut rng = StdRng::seed_from_u64(1);
        let sig = TestSignature::generate(&mut rng, 12345);
        assert!(sig.encoding.iter().any(|&e| e as usize == CHAIN_LENGTH - 1));
        assert!(
            sig.encoding
                .iter()
                .any(|&e| (e as usize) < CHAIN_LENGTH - 1)
        );
    }

    /// Builds the encode-and-walk circuit, populates it from `sig`, and returns the result of
    /// checking the constraint system.
    fn run(sig: &TestSignature, epoch: u32) -> Result<(), String> {
        let b = CircuitBuilder::new();
        let param_w: [Wire; PUBLIC_PARAM_WIRES] = std::array::from_fn(|_| b.add_inout());
        let epoch_w = b.add_inout();
        let message_w: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
        let randomness_w: [Wire; RANDOMNESS_WIRES] = std::array::from_fn(|_| b.add_witness());
        let tips_w: [[Wire; DIGEST_WIRES]; V] =
            std::array::from_fn(|_| std::array::from_fn(|_| b.add_witness()));
        let leaf_w: [Wire; DIGEST_WIRES] = std::array::from_fn(|_| b.add_inout());

        let h = XmssHasher::new(&b, &param_w, epoch_w);
        let message: [Wire; MESSAGE_WORDS] = h.unpack_words(&message_w).try_into().unwrap();
        let digits = circuit_wots_encode(&h, &message, &randomness_w);
        let ends = circuit_recover_public_key(&h, &param_w, &tips_w, &digits);
        let leaf = h.pack(&circuit_wots_public_key_hash(&h, &ends));
        b.assert_eq_v("leaf", leaf, leaf_w);

        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        pack_be(&mut w, &param_w, &sig.public_param);
        w[epoch_w] = Word::from_u64(epoch as u64);
        pack_be(&mut w, &message_w, &sig.message);
        pack_be(&mut w, &randomness_w, &sig.randomness);
        for (wires, tip) in tips_w.iter().zip(&sig.chain_tips) {
            pack_be(&mut w, wires, tip);
        }
        pack_be(
            &mut w,
            &leaf_w,
            &wots_public_key_hash(&sig.public_param, epoch, &sig.chain_ends),
        );

        circuit
            .populate_wire_witness(&mut w)
            .map_err(|e| format!("populate: {e:?}"))?;
        let cs = circuit.constraint_system();
        cs.verify(w.value_vec())
            .map_err(|e| format!("verify: {e:?}"))?;

        // Keep the populated chain fixed. Its first row must bind the supplied
        // signature tip even when that chain takes one or more hash steps.
        let walked = sig
            .encoding
            .iter()
            .position(|&d| (d as usize) < CHAIN_LENGTH - 1)
            .unwrap();
        let tip = tips_w[walked][0];
        w[tip] = Word::from_u64(w[tip].as_u64() ^ 1);
        assert!(cs.verify(w.value_vec()).is_err());
        Ok(())
    }

    #[test]
    fn circuit_recovers_the_public_key() {
        let mut rng = StdRng::seed_from_u64(1);
        let epoch = 12345;
        let sig = TestSignature::generate(&mut rng, epoch);
        run(&sig, epoch).unwrap();
    }

    #[test]
    fn circuit_digits_match_the_reference_encoding() {
        let mut rng = StdRng::seed_from_u64(2);
        let epoch = 9;
        let sig = TestSignature::generate(&mut rng, epoch);

        let b = CircuitBuilder::new();
        let param_w: [Wire; PUBLIC_PARAM_WIRES] = std::array::from_fn(|_| b.add_inout());
        let epoch_w = b.add_inout();
        let message_w: [Wire; 4] = std::array::from_fn(|_| b.add_inout());
        let randomness_w: [Wire; RANDOMNESS_WIRES] = std::array::from_fn(|_| b.add_inout());
        let h = XmssHasher::new(&b, &param_w, epoch_w);
        let message: [Wire; MESSAGE_WORDS] = h.unpack_words(&message_w).try_into().unwrap();
        let digits = circuit_wots_encode(&h, &message, &randomness_w);
        let expected: [Wire; V] = std::array::from_fn(|_| b.add_inout());
        b.assert_eq_v("digits", digits, expected);

        let circuit = b.build();
        let mut w = circuit.new_witness_filler();
        pack_be(&mut w, &param_w, &sig.public_param);
        w[epoch_w] = Word::from_u64(epoch as u64);
        pack_be(&mut w, &message_w, &sig.message);
        pack_be(&mut w, &randomness_w, &sig.randomness);
        for (wire, &digit) in expected.iter().zip(&sig.encoding) {
            w[*wire] = Word::from_u64(digit as u64);
        }

        circuit.populate_wire_witness(&mut w).unwrap();
        circuit
            .constraint_system()
            .verify(&w.into_value_vec())
            .unwrap();
    }

    #[test]
    fn circuit_rejects_randomness_that_does_not_encode() {
        let mut rng = StdRng::seed_from_u64(3);
        let epoch = 4;
        let mut sig = TestSignature::generate(&mut rng, epoch);
        let mut bad = sig.randomness;
        bad[0] ^= 0xFF;
        assert!(wots_encode(&sig.message, epoch, &sig.public_param, &bad).is_none());
        sig.randomness = bad;
        assert!(
            run(&sig, epoch).is_err(),
            "an invalid encoding must not verify"
        );
    }

    #[test]
    fn circuit_rejects_a_tampered_chain_tip() {
        let mut rng = StdRng::seed_from_u64(4);
        let epoch = 4;
        let mut sig = TestSignature::generate(&mut rng, epoch);
        sig.chain_tips[0][0] ^= 0xFF;
        assert!(
            run(&sig, epoch).is_err(),
            "a tampered tip must not reach the public key"
        );
    }

    #[test]
    fn circuit_rejects_a_signature_from_another_epoch() {
        let mut rng = StdRng::seed_from_u64(5);
        let epoch = 4;
        let sig = TestSignature::generate(&mut rng, epoch);
        assert!(
            run(&sig, epoch + 1).is_err(),
            "an epoch it was not signed at must not verify"
        );
    }
}
