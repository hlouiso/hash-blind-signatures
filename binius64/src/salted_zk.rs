//! Per-leaf Merkle salts provide the hiding required by the BCS zero-knowledge
//! bound; witness masking alone does not hide unopened compiled-oracle leaves.
//! Salts for opened leaves are decommitment advice and are not absorbed into
//! the Fiat–Shamir transcript.

use std::{borrow::BorrowMut, marker::PhantomData, sync::Arc};

use binius_compute::{Allocator, BufferPool, GlobalAllocator};
use binius_core::{
    constraint_system::{InoutSegment, ValueVec},
    word::Word,
};
use binius_field::{BinaryField, BinaryField128bGhash as B128, Field, PackedField, Random};
use binius_hash::{StdHashSuite, binary_merkle_tree::HashSuite};
use binius_iop::{
    merkle_channel::{
        Error as MerkleChannelError, MerkleIPVerifierChannel, TranscriptMerkleCommitment,
    },
    merkle_tree::{BinaryMerkleTreeScheme, Commitment, MerkleTreeScheme},
};
use binius_iop_prover::{
    basefold::compiler::BaseFoldProverCompiler,
    merkle_channel::MerkleIPProverChannel,
    merkle_tree::{MerkleTreeProver, prover::BinaryMerkleTreeProver},
};
use binius_ip::channel::{IPVerifierChannel, WordIPVerifierChannel};
use binius_ip_prover::channel::{IPProverChannel, WordIPProverChannel};
use binius_math::{
    FieldSlice,
    ntt::{NeighborsLastMultiThread, domain_context::GaoMateerPreExpanded},
};
use binius_prover::{
    IOPProver, OptimalPackedB128, protocols::shift::build_key_collection,
    zk_config::Error as ProverError,
};
use binius_spartan_frontend::constraint_system::WitnessLayout;
use binius_spartan_prover::{
    IOPProver as SpartanIOPProver,
    wrapper::{ReplayChannel, ZKWrappedProverChannel},
};
use binius_spartan_verifier::wrapper::ZKWrappedVerifierChannel;
use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::Challenger};
use binius_utils::{
    DeserializeBytes, FixedSizeSerializeBytes, SerializeBytes, checked_arithmetics::checked_log_2,
    rayon::prelude::*,
};
use binius_verifier::{
    IOPVerifier,
    protocols::shift::WiringEvalClaim,
    zk_config::{Error as VerifierError, ZKVerifier},
};
use digest::Output;
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};

pub const MERKLE_SALT_ELEMENTS: usize = 2; // 256 bits over GF(2^128)

const SALT_CHUNK: usize = 1 << 14;

type ProverNtt = NeighborsLastMultiThread<GaoMateerPreExpanded<B128>>;

fn sample_salts<F: Field + Random>(rng: &mut impl Rng, n: usize) -> Vec<F> {
    let mut key = [0u8; blake3::KEY_LEN];
    rng.fill_bytes(&mut key);
    let hasher = blake3::Hasher::new_keyed(&key);

    let mut salts = vec![F::ZERO; n];
    salts
        .par_chunks_mut(SALT_CHUNK)
        .enumerate()
        .for_each(|(task, chunk)| {
            let mut seed = <StdRng as SeedableRng>::Seed::default();
            let mut reader = hasher.finalize_xof();
            reader.set_position((task * seed.len()) as u64);
            reader.fill(&mut seed);

            let mut task_rng = StdRng::from_seed(seed);
            for slot in chunk {
                *slot = F::random(&mut task_rng);
            }
        });
    salts
}

pub struct SaltedProverCommitment<F, C> {
    committed: C,

    salts: Vec<F>,
    depth: usize,
    log_leaf_size: usize,
}

pub struct SaltedProverMerkleChannel<
    T,
    Challenger_,
    F,
    H: HashSuite,
    R,
    A: Allocator = GlobalAllocator,
> {
    transcript: T,
    merkle_prover: BinaryMerkleTreeProver<F, H, A>,
    rng: R,
    salt_len: usize,
    _challenger_marker: PhantomData<Challenger_>,
}

impl<T, Challenger_, F, H: HashSuite, R> SaltedProverMerkleChannel<T, Challenger_, F, H, R> {
    pub fn new(transcript: T, rng: R, salt_len: usize) -> Self {
        Self::with_merkle_prover(transcript, BinaryMerkleTreeProver::new(), rng, salt_len)
    }
}

impl<T, Challenger_, F, H: HashSuite, R, A: Allocator>
    SaltedProverMerkleChannel<T, Challenger_, F, H, R, A>
{
    pub fn with_merkle_prover(
        transcript: T,
        merkle_prover: BinaryMerkleTreeProver<F, H, A>,
        rng: R,
        salt_len: usize,
    ) -> Self {
        assert!(salt_len > 0, "precondition: salt_len must be non-zero");
        Self {
            transcript,
            merkle_prover,
            rng,
            salt_len,
            _challenger_marker: PhantomData,
        }
    }

    pub fn into_transcript(self) -> T {
        self.transcript
    }
}

impl<F, T, Challenger_, H, R, A> IPProverChannel<F>
    for SaltedProverMerkleChannel<T, Challenger_, F, H, R, A>
where
    F: Field,
    T: BorrowMut<ProverTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
    A: Allocator,
{
    fn send_one(&mut self, elem: F) {
        self.transcript.borrow_mut().send_one(elem)
    }

    fn send_many(&mut self, elems: &[F]) {
        self.transcript.borrow_mut().send_many(elems)
    }

    fn observe_one(&mut self, val: F) {
        self.transcript.borrow_mut().observe_one(val)
    }

    fn observe_many(&mut self, vals: &[F]) {
        self.transcript.borrow_mut().observe_many(vals)
    }

    fn sample(&mut self) -> F {
        IPProverChannel::sample(self.transcript.borrow_mut())
    }
}

impl<F, T, Challenger_, H, R, A> WordIPProverChannel<F>
    for SaltedProverMerkleChannel<T, Challenger_, F, H, R, A>
where
    F: Field,
    T: BorrowMut<ProverTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
    A: Allocator,
{
    type Word = Word;

    fn observe_words(&mut self, words: &[Word]) {
        WordIPProverChannel::<F>::observe_words(self.transcript.borrow_mut(), words);
    }

    fn sample_bits(&mut self, bits: usize) -> Word {
        WordIPProverChannel::<F>::sample_bits(self.transcript.borrow_mut(), bits)
    }
}

impl<F, T, Challenger_, H, R, A> MerkleIPProverChannel<F>
    for SaltedProverMerkleChannel<T, Challenger_, F, H, R, A>
where
    F: Field + Random,
    T: BorrowMut<ProverTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
    R: Rng,
    A: Allocator,
    Output<H::LeafHash>: SerializeBytes,
{
    type Commitment = SaltedProverCommitment<
        F,
        <BinaryMerkleTreeProver<F, H, A> as MerkleTreeProver<F>>::Committed,
    >;

    fn send_merkle_commitment<P: PackedField<Scalar = F>>(
        &mut self,
        data: FieldSlice<P>,
        leaf_size: usize,
    ) -> Self::Commitment {
        assert!(
            leaf_size.is_power_of_two(),
            "precondition: leaf_size must be a power of two"
        );
        let log_leaf_size = checked_log_2(leaf_size);
        let n_leaves = 1usize << (data.log_len() - log_leaf_size);

        let salts = sample_salts::<F>(&mut self.rng, n_leaves * self.salt_len);

        let (commitment, committed) = self.merkle_prover.commit_iterated(
            data.par_chunk_scalars(log_leaf_size)
                .zip(salts.par_chunks(self.salt_len))
                .map(|(values, salt)| values.chain(salt.iter().copied())),
            leaf_size + self.salt_len,
        );

        self.transcript
            .borrow_mut()
            .message()
            .write(&commitment.root);

        SaltedProverCommitment {
            committed,
            salts,
            depth: commitment.depth,
            log_leaf_size,
        }
    }

    fn send_openings<P: PackedField<Scalar = F>>(
        &mut self,
        commitment: &Self::Commitment,
        data: FieldSlice<P>,
        indices: &[Word],
    ) {
        let tree_depth = commitment.depth;
        debug_assert_eq!(tree_depth, data.log_len() - commitment.log_leaf_size);
        let indices = indices
            .iter()
            .map(|index| index.as_u64() as usize)
            .collect::<Vec<_>>();
        assert!(indices.iter().all(|&index| index < 1 << tree_depth));

        let scheme = self.merkle_prover.scheme();
        let layer_depth = scheme.optimal_verify_layer(indices.len(), tree_depth);
        let layer = self.merkle_prover.layer(&commitment.committed, layer_depth);
        let mut advice = self.transcript.borrow_mut().decommitment();
        advice.write_slice(layer);
        for &index in &indices {
            let leaf = data.chunk(commitment.log_leaf_size, index);
            advice.write_scalar_iter(leaf.iter_scalars());
            advice.write_scalar_slice(&commitment.salts[index * self.salt_len..][..self.salt_len]);
            self.merkle_prover.prove_opening(
                &commitment.committed,
                layer_depth,
                index,
                &mut advice,
            );
        }
    }

    fn send_committed_vector<P: PackedField<Scalar = F>>(
        &mut self,
        commitment: &Self::Commitment,
        data: FieldSlice<P>,
    ) {
        debug_assert_eq!(commitment.depth, data.log_len() - commitment.log_leaf_size);

        let mut advice = self.transcript.borrow_mut().decommitment();
        for index in 0..1usize << commitment.depth {
            let leaf = data.chunk(commitment.log_leaf_size, index);
            advice.write_scalar_iter(leaf.iter_scalars());
            advice.write_scalar_slice(&commitment.salts[index * self.salt_len..][..self.salt_len]);
        }
    }
}

pub struct SaltedVerifierMerkleChannel<T, Challenger_, F, H: HashSuite> {
    transcript: T,
    scheme: BinaryMerkleTreeScheme<F, H>,
    salt_len: usize,
    _challenger_marker: PhantomData<Challenger_>,
}

impl<T, Challenger_, F, H: HashSuite> SaltedVerifierMerkleChannel<T, Challenger_, F, H> {
    pub fn new(transcript: T, salt_len: usize) -> Self {
        Self {
            transcript,
            scheme: BinaryMerkleTreeScheme::new(),
            salt_len,
            _challenger_marker: PhantomData,
        }
    }

    pub fn into_transcript(self) -> T {
        self.transcript
    }
}

impl<F, T, Challenger_, H> IPVerifierChannel<F>
    for SaltedVerifierMerkleChannel<T, Challenger_, F, H>
where
    F: Field,
    T: BorrowMut<VerifierTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
{
    type Elem = F;

    fn recv_one(&mut self) -> Result<F, binius_ip::channel::Error> {
        self.transcript.borrow_mut().recv_one()
    }

    fn recv_many(&mut self, n: usize) -> Result<Vec<F>, binius_ip::channel::Error> {
        self.transcript.borrow_mut().recv_many(n)
    }

    fn recv_array<const N: usize>(&mut self) -> Result<[F; N], binius_ip::channel::Error> {
        self.transcript.borrow_mut().recv_array()
    }

    fn sample(&mut self) -> F {
        IPVerifierChannel::sample(self.transcript.borrow_mut())
    }

    fn observe_one(&mut self, val: F) -> F {
        self.transcript.borrow_mut().observe_one(val)
    }

    fn observe_many(&mut self, vals: &[F]) -> Vec<F> {
        self.transcript.borrow_mut().observe_many(vals)
    }

    fn assert_zero(&mut self, val: F) -> Result<(), binius_ip::channel::Error> {
        self.transcript.borrow_mut().assert_zero(val)
    }
}

impl<F, T, Challenger_, H> WordIPVerifierChannel<F>
    for SaltedVerifierMerkleChannel<T, Challenger_, F, H>
where
    F: BinaryField,
    T: BorrowMut<VerifierTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
{
    type Word = Word;

    fn observe_words(&mut self, words: &[Word]) -> Vec<Word> {
        WordIPVerifierChannel::<F>::observe_words(self.transcript.borrow_mut(), words)
    }

    fn subset_sum(&mut self, elems: &[F], word: &Word) -> F {
        WordIPVerifierChannel::<F>::subset_sum(self.transcript.borrow_mut(), elems, word)
    }

    fn select(&mut self, elems: &[F], word: &Word) -> F {
        WordIPVerifierChannel::<F>::select(self.transcript.borrow_mut(), elems, word)
    }

    fn sample_bits(&mut self, bits: usize) -> Word {
        WordIPVerifierChannel::<F>::sample_bits(self.transcript.borrow_mut(), bits)
    }

    fn pack_words(&mut self, words: &[Word]) -> Vec<F> {
        WordIPVerifierChannel::<F>::pack_words(self.transcript.borrow_mut(), words)
    }
}

impl<F, T, Challenger_, H> MerkleIPVerifierChannel<F>
    for SaltedVerifierMerkleChannel<T, Challenger_, F, H>
where
    F: BinaryField + FixedSizeSerializeBytes,
    T: BorrowMut<VerifierTranscript<Challenger_>>,
    Challenger_: Challenger,
    H: HashSuite,
    Output<H::LeafHash>: DeserializeBytes,
{
    type Commitment = TranscriptMerkleCommitment<Output<H::LeafHash>>;

    fn recv_merkle_commitment(
        &mut self,
        leaf_size: usize,
        depth: usize,
    ) -> Result<Self::Commitment, MerkleChannelError> {
        let root = self.transcript.borrow_mut().message().read()?;
        Ok(TranscriptMerkleCommitment {
            commitment: Commitment { root, depth },
            leaf_size,
        })
    }

    fn recv_openings(
        &mut self,
        commitment: &Self::Commitment,
        indices: &[Word],
    ) -> Result<Vec<F>, MerkleChannelError> {
        let tree_depth = commitment.commitment.depth;
        let indices = indices
            .iter()
            .map(|index| index.as_u64() as usize)
            .collect::<Vec<_>>();
        assert!(indices.iter().all(|&index| index < 1 << tree_depth));

        let layer_depth = self.scheme.optimal_verify_layer(indices.len(), tree_depth);
        let mut advice = self.transcript.borrow_mut().decommitment();
        let layer_digests = advice.read_vec(1 << layer_depth)?;
        self.scheme
            .verify_layer(&commitment.commitment.root, layer_depth, &layer_digests)?;

        let mut values = Vec::with_capacity(indices.len() * commitment.leaf_size);
        for &index in &indices {
            let mut leaf = advice.read_scalar_slice::<F>(commitment.leaf_size)?;
            let salted_len = leaf.len();
            leaf.extend_from_slice(&advice.read_scalar_slice::<F>(self.salt_len)?);
            self.scheme.verify_opening(
                index,
                &leaf,
                layer_depth,
                tree_depth,
                &layer_digests,
                &mut advice,
            )?;
            leaf.truncate(salted_len);
            values.extend_from_slice(&leaf);
        }
        Ok(values)
    }

    fn recv_committed_vector(
        &mut self,
        commitment: &Self::Commitment,
    ) -> Result<Vec<F>, MerkleChannelError> {
        let leaf_size = commitment.leaf_size;
        let salted_leaf_size = leaf_size + self.salt_len;
        let n_leaves = 1usize << commitment.commitment.depth;
        let data = self
            .transcript
            .borrow_mut()
            .decommitment()
            .read_scalar_slice::<F>(salted_leaf_size * n_leaves)?;
        self.scheme
            .verify_vector(&commitment.commitment.root, &data, salted_leaf_size)?;

        let mut values = Vec::with_capacity(leaf_size * n_leaves);
        for leaf in data.chunks_exact(salted_leaf_size) {
            values.extend_from_slice(&leaf[..leaf_size]);
        }
        Ok(values)
    }
}

pub struct SaltedZkProver {
    inner_iop_prover: IOPProver,
    inner_iop_verifier: IOPVerifier,
    outer_iop_prover: SpartanIOPProver<B128>,
    outer_layout: Arc<WitnessLayout<B128>>,
    basefold_compiler: BaseFoldProverCompiler<OptimalPackedB128, ProverNtt>,
    pool: BufferPool,
}

impl SaltedZkProver {
    pub fn setup(zk_verifier: &ZKVerifier<StdHashSuite>) -> Result<Self, ProverError> {
        let key_collection = build_key_collection(
            zk_verifier.inner_iop_verifier().constraint_system(),
            InoutSegment::Public,
        );
        let inner_iop_verifier = zk_verifier.inner_iop_verifier().clone();
        let inner_iop_prover = IOPProver::new(inner_iop_verifier.clone(), key_collection);

        let outer_cs = zk_verifier.outer_iop_verifier().constraint_system().clone();
        let outer_iop_prover = SpartanIOPProver::new(outer_cs);
        let outer_layout = zk_verifier.outer_layout_arc();

        let log_domain_size = zk_verifier.basefold_compiler().max_log_domain_size();
        let domain_context = GaoMateerPreExpanded::generate(log_domain_size);
        let log_num_shares = binius_utils::rayon::current_num_threads().ilog2() as usize;
        let ntt = NeighborsLastMultiThread::new(domain_context, log_num_shares);
        let basefold_compiler =
            BaseFoldProverCompiler::from_verifier_compiler(zk_verifier.basefold_compiler(), ntt);

        Ok(Self {
            inner_iop_prover,
            inner_iop_verifier,
            outer_iop_prover,
            outer_layout,
            basefold_compiler,
            pool: BufferPool::new(),
        })
    }

    pub fn prove<Challenger_: Challenger>(
        &self,
        witness: &ValueVec,
        mut rng: impl CryptoRng,
        transcript: &mut ProverTranscript<Challenger_>,
    ) -> Result<(), ProverError> {
        let inout_words = witness.inout();

        let alloc = &self.pool;

        let mut salt_seed = <StdRng as SeedableRng>::Seed::default();
        rng.fill_bytes(&mut salt_seed);
        let merkle_channel =
            SaltedProverMerkleChannel::<_, Challenger_, B128, StdHashSuite, _, _>::with_merkle_prover(
                transcript,
                BinaryMerkleTreeProver::with_allocator(alloc),
                StdRng::from_seed(salt_seed),
                MERKLE_SALT_ELEMENTS,
            );
        let basefold_channel =
            self.basefold_compiler
                .create_channel(merkle_channel, &mut rng, alloc);
        let mut wrapped_channel = ZKWrappedProverChannel::new(
            basefold_channel,
            &self.outer_iop_prover,
            Arc::clone(&self.outer_layout),
            &alloc,
            &mut rng,
            {
                let inner_iop_verifier = &self.inner_iop_verifier;
                move |replay_channel: &mut ReplayChannel<B128>| {
                    let inout = replay_channel.observe_words(inout_words);

                    let _ = inner_iop_verifier
                        .verify(&inout, replay_channel)
                        .expect("replay verification should not fail");
                }
            },
        );

        self.inner_iop_prover.prove::<_, OptimalPackedB128, _>(
            witness,
            &mut wrapped_channel,
            &alloc,
        )?;
        wrapped_channel.finish(rng)?;
        Ok(())
    }
}

pub fn verify_salted<Challenger_: Challenger>(
    zk_verifier: &ZKVerifier<StdHashSuite>,
    inout: &[Word],
    transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(), VerifierError> {
    let merkle_channel = SaltedVerifierMerkleChannel::<_, Challenger_, B128, StdHashSuite>::new(
        transcript,
        MERKLE_SALT_ELEMENTS,
    );
    let basefold_channel = zk_verifier
        .basefold_compiler()
        .create_channel(merkle_channel);
    let mut wrapped_channel = ZKWrappedVerifierChannel::new(
        basefold_channel,
        zk_verifier.outer_iop_verifier(),
        zk_verifier.outer_layout_arc(),
    )?;

    let inout = wrapped_channel.observe_words(inout);
    let claim = zk_verifier
        .inner_iop_verifier()
        .verify(&inout, &mut wrapped_channel)?;

    let public_value = |elem| {
        wrapped_channel
            .public_value(elem)
            .expect("a public claim and its inputs are public wires")
    };
    WiringEvalClaim {
        inputs: claim.inputs.iter().map(public_value).collect(),
        claimed: public_value(&claim.claimed),
        eval_fn: claim.eval_fn,
    }
    .check_native()
    .map_err(binius_verifier::Error::from)?;

    wrapped_channel.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use binius_field::{BinaryField128bGhash as B128, PackedBinaryGhash2x128b, Random};
    use binius_hash::{StdDigest, StdHashSuite};
    use binius_math::FieldBuffer;
    use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    type StdChallenger = HasherChallenger<StdDigest>;
    type P = PackedBinaryGhash2x128b;
    type ProverChannel<T, R> = SaltedProverMerkleChannel<T, StdChallenger, B128, StdHashSuite, R>;
    type VerifierChannel<T> = SaltedVerifierMerkleChannel<T, StdChallenger, B128, StdHashSuite>;

    const LOG_LEN: usize = 8;
    const LOG_LEAF_SIZE: usize = 2;
    const LEAF_SIZE: usize = 1 << LOG_LEAF_SIZE;
    const DEPTH: usize = LOG_LEN - LOG_LEAF_SIZE;
    const N_QUERIES: usize = 5;

    fn random_scalars(rng: &mut StdRng, n: usize) -> Vec<B128> {
        std::iter::repeat_with(|| B128::random(&mut *rng))
            .take(n)
            .collect()
    }

    #[test]
    fn salted_merkle_channel_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0);

        let scalars = random_scalars(&mut rng, 1 << LOG_LEN);
        let data = FieldBuffer::<P, _>::from_values(&scalars);

        let mut transcript = ProverTranscript::new(StdChallenger::default());
        let indices = {
            let mut prover_channel =
                ProverChannel::new(&mut transcript, &mut rng, MERKLE_SALT_ELEMENTS);
            let commitment = prover_channel.send_merkle_commitment(data.to_ref(), LEAF_SIZE);
            let indices = (0..N_QUERIES)
                .map(|_| WordIPProverChannel::<B128>::sample_bits(&mut prover_channel, DEPTH))
                .collect::<Vec<_>>();
            prover_channel.send_openings(&commitment, data.to_ref(), &indices);
            prover_channel.send_committed_vector(&commitment, data.to_ref());
            indices
        };

        let mut verifier_channel =
            VerifierChannel::new(transcript.into_verifier(), MERKLE_SALT_ELEMENTS);
        let commitment = verifier_channel
            .recv_merkle_commitment(LEAF_SIZE, DEPTH)
            .unwrap();
        let verifier_indices = (0..N_QUERIES)
            .map(|_| WordIPVerifierChannel::<B128>::sample_bits(&mut verifier_channel, DEPTH))
            .collect::<Vec<_>>();
        assert_eq!(verifier_indices, indices);

        let openings = verifier_channel
            .recv_openings(&commitment, &verifier_indices)
            .unwrap();
        assert_eq!(openings.len(), N_QUERIES * LEAF_SIZE);
        for (query, index) in verifier_indices.iter().enumerate() {
            let index = index.as_u64() as usize;
            assert_eq!(
                &openings[query * LEAF_SIZE..(query + 1) * LEAF_SIZE],
                &scalars[index * LEAF_SIZE..(index + 1) * LEAF_SIZE],
            );
        }

        let full = verifier_channel.recv_committed_vector(&commitment).unwrap();
        assert_eq!(full, scalars);
    }

    #[test]
    fn salts_randomize_the_commitment() {
        let mut rng = StdRng::seed_from_u64(1);
        let scalars = random_scalars(&mut rng, 1 << LOG_LEN);
        let data = FieldBuffer::<P, _>::from_values(&scalars);

        let root_of = |rng: &mut StdRng| {
            let mut transcript = ProverTranscript::new(StdChallenger::default());
            {
                let mut channel = ProverChannel::new(&mut transcript, rng, MERKLE_SALT_ELEMENTS);
                channel.send_merkle_commitment(data.to_ref(), LEAF_SIZE);
            }
            transcript.finalize()
        };

        assert_ne!(root_of(&mut rng), root_of(&mut rng));
    }
}
