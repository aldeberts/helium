//! Dropout-key aggregation with a succinct proof (the Helium extension).
//!
//! In Heli the light server re-derives the key of every client that dropped
//! out of a round, so its work is linear in the number of dropouts. Here the
//! heavy server sums those keys under encryption instead, and proves that it
//! summed a set of distinct clients. The light server checks the proof with
//! one Paillier decryption and one group exponentiation, whatever the number
//! of clients or dropouts.
//!
//! # Protocol
//!
//! Client `i` is assigned the `i`-th point of a multiplicative subgroup of the
//! BLS12-381 scalar field, with Lagrange basis `L_i` and vanishing polynomial
//! `Z`. The light server holds a secret point `tau` and a secret multiplier
//! `beta` modulo the Paillier modulus `N`.
//!
//! * **Setup.** For each client the light server gives the heavy server a
//!   [`KeyRecord`]: a Paillier encryption of `beta` times the packing of the
//!   client's key, a constant one, and `L_i(tau)`, plus the group elements
//!   `[L_i(tau)]` and `[(L_i(tau)^2 - L_i(tau)) / Z(tau)]`.
//! * **Prove.** For a dropout set `D` the heavy server multiplies the
//!   ciphertexts of `D` and commits to the quotient `Q = (B^2 - B) / Z`, where
//!   `B` is the sum of `L_i` over `D`. Only records of `D` are touched.
//! * **Verify.** The light server decrypts, divides by `beta`, and unpacks the
//!   key sum, the size of `D`, and `B(tau)`. It accepts if the packing is
//!   well-formed and `[(B(tau)^2 - B(tau)) / Z(tau)]` equals the commitment.
//!
//! # Security
//!
//! The proof must stop a malicious heavy server from obtaining a weighted or
//! shifted key sum, which would let it decrypt a weighted sum of client
//! inputs. The argument, which is a sketch and not a proof:
//!
//! * The heavy server can only combine the ciphertexts linearly. One
//!   ciphertext per client carries all three values, so they are combined
//!   with the same coefficients.
//! * `Z` divides `B^2 - B` only if `B` is 0 or 1 at every client's point, so
//!   the quotient check forces those coefficients to be 0 or 1. This is the
//!   only check that does so, and it holds as long as `tau` stays secret: the
//!   heavy server sees `tau` only through the group elements.
//! * Any constant the heavy server adds reaches the light server divided by
//!   the unknown `beta`, which makes the plaintext a random element modulo
//!   `N` and far too large to be a packing. `beta` stays unknown as long as
//!   the heavy server knows no client's whole packing, `L_i(tau)` included,
//!   so this too rests on `tau`.
//! * Other coefficients, such as ones too large for the slots or fractions
//!   modulo `N`, leave either a malformed packing or one that fails the
//!   quotient check.
//!
//! So whether a proof is accepted should depend only on how the heavy server
//! built it, not on any secret. Which check a dishonest proof fails can
//! depend on secrets, so verification evaluates every check before rejecting
//! and reports a single error, and the light server should stop serving a
//! heavy server whose proof it rejects.
//!
//! The simulated key is public, so simulated deployments have no soundness.

use crate::crypto::{Scalar, paillier};

use anyhow::{Result, bail, ensure};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, UniformRand, Zero, batch_inversion};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use rayon::prelude::*;
use rug::{Integer, integer::Order};
use serde::{Deserialize, Serialize};

/// Size of the Paillier modulus (roughly 112-bit security).
pub const PAILLIER_MODULUS_BITS: u32 = 2048;

/// Width of each value packed into a Paillier plaintext. A slot holds the sum
/// of up to 2^64 values below 2^256 without carrying into the next slot.
const SLOT_BITS: u32 = 320;

/// The slots of a packing, from the least significant: the client's key, the
/// constant one, and `L_i(tau)`.
const NUM_SLOTS: usize = 3;

/// Size of a packing. The bits of the Paillier modulus above it are what
/// makes a random plaintext overwhelmingly unlikely to be well-formed.
const PACKING_BITS: u32 = NUM_SLOTS as u32 * SLOT_BITS;
const _: () = assert!(PAILLIER_MODULUS_BITS >= PACKING_BITS + 256);

/// Seed of the fixed key used by simulated setups (benchmarking only).
const SIMULATED_KEY_SEED: [u8; 32] = *b"simulate_helium_dropout_key_seed";

/// The light server's secret key for dropout proofs. Its size is independent
/// of the number of clients.
#[derive(Clone, Serialize, Deserialize)]
pub struct DropoutVerifierKey {
    paillier: paillier::SecretKey,
    num_clients: usize,
    /// Secret evaluation point of the bit polynomial.
    #[serde(with = "ark_serde")]
    tau: Fr,
    /// Secret multiplier applied to every packing before encryption, and its
    /// inverse, both modulo the Paillier modulus.
    #[serde(with = "paillier::integer_serde")]
    blind: Integer,
    #[serde(with = "paillier::integer_serde")]
    unblind: Integer,
}

/// What the heavy server stores for one client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Encryption of the blinded packing of the client's key.
    encrypted_key: paillier::Ciphertext,
    /// `[L_i(tau)]`
    #[serde(with = "ark_serde::trusted")]
    bit_base: G1Affine,
    /// `[(L_i(tau)^2 - L_i(tau)) / Z(tau)]`
    #[serde(with = "ark_serde::trusted")]
    square_base: G1Affine,
}

/// The heavy server's key for proving dropout-key sums.
pub struct DropoutProverKey {
    paillier: paillier::PublicKey,
    records: Vec<KeyRecord>,
}

/// An encrypted sum of dropped-out clients' keys, with a proof that it sums
/// each of a set of distinct clients exactly once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropoutProof {
    key_sum: paillier::Ciphertext,
    /// Commitment to the quotient `(B^2 - B) / Z`.
    #[serde(with = "ark_serde")]
    quotient: G1Affine,
}

/// The verified content of a [`DropoutProof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropoutKeySum {
    /// Sum of the dropped-out clients' keys.
    pub key_sum: Scalar,
    /// Number of dropped-out clients.
    pub count: usize,
}

impl DropoutVerifierKey {
    pub fn generate<R: RngCore + CryptoRng>(num_clients: usize, rng: &mut R) -> Self {
        let paillier = paillier::SecretKey::generate(PAILLIER_MODULUS_BITS, rng);
        let domain = domain(num_clients);
        let tau = loop {
            let tau = Fr::rand(rng);
            if !domain.evaluate_vanishing_polynomial(tau).is_zero() {
                break tau;
            }
        };
        let blind = paillier.public_key().random_unit(rng);
        let unblind = blind.clone().invert(paillier.public_key().modulus());
        Self {
            unblind: unblind.expect("the multiplier is a unit"),
            blind,
            paillier,
            num_clients,
            tau,
        }
    }

    /// The fixed, publicly known key of simulated setups, where both servers
    /// derive all key material locally. For benchmarking only.
    pub fn simulated(num_clients: usize) -> Self {
        Self::generate(num_clients, &mut ChaCha20Rng::from_seed(SIMULATED_KEY_SEED))
    }

    pub fn paillier_public_key(&self) -> &paillier::PublicKey {
        self.paillier.public_key()
    }

    /// Builds the records for a batch of clients, given as `(id, key)` pairs.
    pub fn key_records(&self, clients: &[(u32, Scalar)]) -> Vec<KeyRecord> {
        let domain = domain(self.num_clients);
        let vanishing = domain.evaluate_vanishing_polynomial(self.tau);
        let vanishing_inv = vanishing.inverse().expect("tau is outside the domain");

        // L_i(tau) = w^i Z(tau) / (d (tau - w^i)) for the d-th root of unity w.
        let points: Vec<Fr> = clients
            .iter()
            .map(|&(id, _)| {
                assert!((id as usize) < self.num_clients, "client id out of range");
                domain.element(id as usize)
            })
            .collect();
        let mut lagrange: Vec<Fr> = points.iter().map(|point| self.tau - point).collect();
        batch_inversion(&mut lagrange);
        let scale = vanishing * domain.size_inv();
        for (value, point) in lagrange.iter_mut().zip(&points) {
            *value *= scale * point;
        }

        let base_scalars: Vec<Fr> = lagrange
            .iter()
            .flat_map(|l| [*l, (l.square() - l) * vanishing_inv])
            .collect();
        let bases = G1Projective::generator().batch_mul(&base_scalars);

        (clients, lagrange, bases.par_chunks_exact(2))
            .into_par_iter()
            .map(|((_, key), lagrange, bases)| KeyRecord {
                encrypted_key: self
                    .paillier
                    .encrypt(&self.plaintext(key, lagrange), &mut OsRng),
                bit_base: bases[0],
                square_base: bases[1],
            })
            .collect()
    }

    /// The plaintext encrypted for a client with the given key and `L_i(tau)`.
    fn plaintext(&self, key: &Scalar, lagrange: Fr) -> Integer {
        let packing = pack([
            scalar_to_integer(key),
            Integer::from(1),
            fr_to_integer(&lagrange),
        ]);
        packing * &self.blind % self.paillier.public_key().modulus()
    }

    /// Checks `proof` and returns the key sum and dropout count it proves.
    pub fn verify(&self, proof: &DropoutProof) -> Result<DropoutKeySum> {
        let modulus = self.paillier.public_key().modulus();
        let packing = self.paillier.decrypt(&proof.key_sum)? * &self.unblind % modulus;
        let [key_sum, count, bit_eval] = unpack(&packing);
        let count = count.to_usize();
        let well_formed = packing.significant_bits() <= PACKING_BITS && count.is_some();

        // B is 0 or 1 at every client's point iff Z divides B^2 - B.
        let bit_eval = integer_to_fr(&bit_eval);
        let vanishing = domain(self.num_clients).evaluate_vanishing_polynomial(self.tau);
        let quotient_eval = (bit_eval.square() - bit_eval) / vanishing;
        let binary = G1Projective::generator() * quotient_eval == proof.quotient;

        // Both checks are evaluated first, so a rejection does not show which one failed.
        let (Some(count), true) = (count, well_formed & binary) else {
            bail!("invalid dropout proof");
        };
        Ok(DropoutKeySum {
            key_sum: integer_to_scalar(&key_sum),
            count,
        })
    }
}

impl DropoutProverKey {
    /// `records[i]` must be the record of client `i`.
    pub fn new(paillier: paillier::PublicKey, records: Vec<KeyRecord>) -> Self {
        Self { paillier, records }
    }

    pub fn paillier_public_key(&self) -> &paillier::PublicKey {
        &self.paillier
    }

    pub fn records(&self) -> &[KeyRecord] {
        &self.records
    }

    /// Proves the key sum of the clients in `dropouts`, which must be distinct
    /// registered client ids.
    pub fn prove(&self, dropouts: &[u32]) -> Result<DropoutProof> {
        let mut sorted = dropouts.to_vec();
        sorted.sort_unstable();
        ensure!(
            sorted.windows(2).all(|pair| pair[0] < pair[1]),
            "duplicate dropout id"
        );
        ensure!(
            sorted
                .last()
                .is_none_or(|&id| (id as usize) < self.records.len()),
            "dropout id out of range"
        );
        Ok(DropoutProof {
            key_sum: self.sum_keys(&sorted),
            quotient: self.commit_quotient(&sorted),
        })
    }

    /// The encrypted key sum of `dropouts`: the first half of [`Self::prove`],
    /// exposed for benchmarking. Does not validate `dropouts`.
    pub fn sum_keys(&self, dropouts: &[u32]) -> paillier::Ciphertext {
        self.paillier.sum(
            dropouts
                .par_iter()
                .map(|&id| &self.records[id as usize].encrypted_key),
        )
    }

    /// The commitment to `(B^2 - B) / Z` for the bit polynomial `B` of
    /// `dropouts`: the second half of [`Self::prove`], exposed for
    /// benchmarking. Does not validate `dropouts`.
    ///
    /// With `L_i L_j = Z (w^j L_i - w^i L_j) / (d (w^i - w^j))` for `i != j`,
    /// the quotient is the sum over `D` of `(L_i^2 - L_i) / Z + c_i L_i`,
    /// where `c_i = (2 / d) * sum_{j in D, j != i} w^j / (w^i - w^j)`.
    pub fn commit_quotient(&self, dropouts: &[u32]) -> G1Affine {
        let domain = domain(self.records.len());
        let scale = domain.size_inv().double();
        let coefficients: Vec<Fr> = cross_terms(&domain, dropouts)
            .into_par_iter()
            .map(|sum| sum * scale)
            .collect();

        let record = |id: &u32| &self.records[*id as usize];
        let bit_bases: Vec<G1Affine> = dropouts.par_iter().map(|id| record(id).bit_base).collect();
        let squares: G1Projective = dropouts
            .par_iter()
            .fold(G1Projective::zero, |sum, id| sum + record(id).square_base)
            .sum();
        (squares + G1Projective::msm_unchecked(&bit_bases, &coefficients)).into_affine()
    }
}

/// The evaluation domain whose `i`-th point belongs to client `i`.
fn domain(num_clients: usize) -> Radix2EvaluationDomain<Fr> {
    Radix2EvaluationDomain::new(num_clients.max(2)).expect("too many clients for the scalar field")
}

/// For each `i` in `dropouts`, the sum of `w^j / (w^i - w^j)` over the other
/// dropouts `j`, where `w^k` is the domain point of client `k`.
fn cross_terms(domain: &Radix2EvaluationDomain<Fr>, dropouts: &[u32]) -> Vec<Fr> {
    // Pairwise sums are quadratic in the dropouts; the FFTs are quasilinear in the domain.
    if dropouts.len().saturating_mul(dropouts.len()) <= domain.size() {
        cross_terms_pairwise(domain, dropouts)
    } else {
        cross_terms_fft(domain, dropouts)
    }
}

fn cross_terms_pairwise(domain: &Radix2EvaluationDomain<Fr>, dropouts: &[u32]) -> Vec<Fr> {
    let points: Vec<Fr> = dropouts
        .iter()
        .map(|&id| domain.element(id as usize))
        .collect();
    points
        .par_iter()
        .map(|point| {
            // The term for the point itself has numerator 0, so it drops out of the sum.
            let mut inverses: Vec<Fr> = points.iter().map(|other| *point - other).collect();
            batch_inversion(&mut inverses);
            points.iter().zip(&inverses).map(|(p, inv)| *p * inv).sum()
        })
        .collect()
}

/// Uses that the sum for `i` equals `w^i B'(w^i) - (d - 1) / 2`, where `B` is
/// the polynomial that is 1 on the dropouts' points and 0 on the rest of the domain.
fn cross_terms_fft(domain: &Radix2EvaluationDomain<Fr>, dropouts: &[u32]) -> Vec<Fr> {
    let size = domain.size();
    let mut poly = vec![Fr::zero(); size];
    for &id in dropouts {
        poly[id as usize] = Fr::one();
    }
    domain.ifft_in_place(&mut poly);
    for degree in 1..size {
        poly[degree - 1] = poly[degree] * Fr::from(degree as u64);
    }
    poly[size - 1] = Fr::zero();
    domain.fft_in_place(&mut poly);

    let offset = Fr::from(size as u64 - 1) / Fr::from(2u64);
    dropouts
        .par_iter()
        .map(|&id| domain.element(id as usize) * poly[id as usize] - offset)
        .collect()
}

/// Packs `slots`, each below `2^SLOT_BITS`, into one integer.
fn pack(slots: [Integer; NUM_SLOTS]) -> Integer {
    slots
        .into_iter()
        .rev()
        .fold(Integer::new(), |packed, slot| (packed << SLOT_BITS) + slot)
}

/// The slots in the low `PACKING_BITS` bits of `packed`.
fn unpack(packed: &Integer) -> [Integer; NUM_SLOTS] {
    std::array::from_fn(|slot| {
        Integer::from(packed >> (slot as u32 * SLOT_BITS)).keep_bits(SLOT_BITS)
    })
}

fn scalar_to_integer(scalar: &Scalar) -> Integer {
    Integer::from_digits(scalar.as_bytes(), Order::Lsf)
}

/// Reduces `value`, which must be below `2^512`, modulo the group order.
fn integer_to_scalar(value: &Integer) -> Scalar {
    let mut bytes = [0u8; 64];
    value.write_digits(&mut bytes[..value.significant_digits::<u8>()], Order::Lsf);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn fr_to_integer(value: &Fr) -> Integer {
    Integer::from_digits(&value.into_bigint().0, Order::Lsf)
}

fn integer_to_fr(value: &Integer) -> Fr {
    Fr::from_le_bytes_mod_order(&value.to_digits::<u8>(Order::Lsf))
}

/// Serde adapters for arkworks types.
mod ark_serde {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use serde::{Deserialize, Deserializer, Serializer, de, ser};

    fn serialize_with<T: CanonicalSerialize, S: Serializer>(
        value: &T,
        compress: Compress,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::with_capacity(value.serialized_size(compress));
        value
            .serialize_with_mode(&mut bytes, compress)
            .map_err(ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    fn deserialize_with<'de, T: CanonicalDeserialize, D: Deserializer<'de>>(
        compress: Compress,
        validate: Validate,
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        T::deserialize_with_mode(bytes.as_slice(), compress, validate).map_err(de::Error::custom)
    }

    /// Compressed and fully validated: for secrets and untrusted input.
    pub(super) fn serialize<T: CanonicalSerialize, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_with(value, Compress::Yes, serializer)
    }

    pub(super) fn deserialize<'de, T: CanonicalDeserialize, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        deserialize_with(Compress::Yes, Validate::Yes, deserializer)
    }

    /// Uncompressed and unvalidated, which is far cheaper to read. Only for the
    /// prover's bases: malformed ones can do no worse than make its proofs fail.
    pub(super) mod trusted {
        use super::*;

        pub(in super::super) fn serialize<T: CanonicalSerialize, S: Serializer>(
            value: &T,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serialize_with(value, Compress::No, serializer)
        }

        pub(in super::super) fn deserialize<'de, T: CanonicalDeserialize, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<T, D::Error> {
            deserialize_with(Compress::No, Validate::No, deserializer)
        }
    }
}

#[cfg(test)]
impl DropoutProof {
    /// A forgery that pairs the key sum of `self` with the quotient of `other`.
    pub(crate) fn with_quotient_of(&self, other: &Self) -> Self {
        Self {
            key_sum: self.key_sum.clone(),
            quotient: other.quotient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, seq::IteratorRandom};
    use std::sync::OnceLock;

    const NUM_CLIENTS: usize = 40;

    struct Fixture {
        verifier_key: DropoutVerifierKey,
        prover_key: DropoutProverKey,
        client_keys: Vec<Scalar>,
    }

    impl Fixture {
        fn new(num_clients: usize) -> Self {
            let verifier_key = DropoutVerifierKey::generate(num_clients, &mut OsRng);
            let client_keys: Vec<Scalar> = (0..num_clients)
                .map(|_| Scalar::random(&mut OsRng))
                .collect();
            let clients: Vec<(u32, Scalar)> = (0u32..).zip(client_keys.iter().copied()).collect();
            let prover_key = DropoutProverKey::new(
                verifier_key.paillier_public_key().clone(),
                verifier_key.key_records(&clients),
            );
            Self {
                verifier_key,
                prover_key,
                client_keys,
            }
        }

        fn key_sum(&self, dropouts: &[u32]) -> Scalar {
            dropouts
                .iter()
                .map(|&id| self.client_keys[id as usize])
                .sum()
        }

        fn record(&self, id: u32) -> &KeyRecord {
            &self.prover_key.records[id as usize]
        }

        /// Asserts that the honest proof for `dropouts` verifies to the right sum.
        fn assert_proves(&self, dropouts: &[u32]) {
            let proof = self.prover_key.prove(dropouts).unwrap();
            let verified = self.verifier_key.verify(&proof).unwrap();
            assert_eq!(verified.count, dropouts.len());
            assert_eq!(verified.key_sum, self.key_sum(dropouts));
        }

        /// Multiplies the plaintext under `proof` by `factor` and adds `offset`.
        fn tamper_key_sum(&self, proof: &mut DropoutProof, factor: u32, offset: &Integer) {
            let paillier = self.prover_key.paillier_public_key();
            let scaled = paillier.scale(&proof.key_sum, &Integer::from(factor));
            let offset = paillier.encrypt_public(offset);
            proof.key_sum = paillier.sum([&scaled, &offset].into_par_iter());
        }
    }

    /// Key generation dominates test time, so most tests share one fixture.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| Fixture::new(NUM_CLIENTS))
    }

    fn random_dropouts(num_clients: usize, count: usize) -> Vec<u32> {
        (0..num_clients as u32).choose_multiple(&mut OsRng, count)
    }

    #[test]
    fn honest_proofs_verify() {
        let fixture = fixture();
        let all: Vec<u32> = (0..NUM_CLIENTS as u32).collect();
        fixture.assert_proves(&[]);
        fixture.assert_proves(&[0]);
        fixture.assert_proves(&[NUM_CLIENTS as u32 - 1]);
        fixture.assert_proves(&[3, 17]);
        fixture.assert_proves(&[17, 3, 25]);
        fixture.assert_proves(&all);
        for count in [1, 5, 10, 39] {
            fixture.assert_proves(&random_dropouts(NUM_CLIENTS, count));
        }
    }

    #[test]
    fn works_for_any_number_of_clients() {
        for num_clients in [1, 2, 3, 8, 9] {
            let fixture = Fixture::new(num_clients);
            let all: Vec<u32> = (0..num_clients as u32).collect();
            fixture.assert_proves(&[]);
            fixture.assert_proves(&all);
            fixture.assert_proves(&all[..num_clients / 2]);
            fixture.assert_proves(&all[num_clients / 2..]);
        }
    }

    #[test]
    fn cross_term_strategies_agree() {
        let domain = domain(200);
        for count in [0, 1, 2, 7, 200] {
            let dropouts = random_dropouts(200, count);
            assert_eq!(
                cross_terms_pairwise(&domain, &dropouts),
                cross_terms_fft(&domain, &dropouts)
            );
        }
    }

    /// Enough dropouts for `prove` to take the FFT path.
    #[test]
    fn large_dropout_sets_verify() {
        let dropouts = random_dropouts(NUM_CLIENTS, 20);
        let domain = domain(NUM_CLIENTS);
        assert!(dropouts.len().pow(2) > domain.size());
        fixture().assert_proves(&dropouts);
    }

    #[test]
    fn prove_rejects_invalid_dropout_sets() {
        let fixture = fixture();
        assert!(fixture.prover_key.prove(&[4, 9, 4]).is_err());
        assert!(fixture.prover_key.prove(&[NUM_CLIENTS as u32]).is_err());
    }

    #[test]
    fn proof_serializes_compactly() {
        let fixture = fixture();
        let proof = fixture.prover_key.prove(&[1, 2, 3]).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        // A ciphertext mod N^2, a compressed G1 point, and two length prefixes.
        assert!(bytes.len() <= PAILLIER_MODULUS_BITS as usize / 4 + 48 + 16);
        assert_eq!(bincode::deserialize::<DropoutProof>(&bytes).unwrap(), proof);
    }

    #[test]
    fn keys_serialize() {
        let fixture = fixture();
        let dropouts = [2, 30];
        let proof = fixture.prover_key.prove(&dropouts).unwrap();

        let bytes = bincode::serialize(&fixture.verifier_key).unwrap();
        let verifier_key: DropoutVerifierKey = bincode::deserialize(&bytes).unwrap();
        assert_eq!(verifier_key.verify(&proof).unwrap().count, dropouts.len());

        let bytes = bincode::serialize(fixture.prover_key.records()).unwrap();
        let records: Vec<KeyRecord> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(records, fixture.prover_key.records());
    }

    #[test]
    fn simulated_key_is_deterministic() {
        let (a, b) = (
            DropoutVerifierKey::simulated(10),
            DropoutVerifierKey::simulated(10),
        );
        assert_eq!(a.paillier_public_key(), b.paillier_public_key());
        assert_eq!((a.tau, &a.blind), (b.tau, &b.blind));
    }

    // --- Attacks by a malicious heavy server ---

    #[test]
    fn rejects_mismatched_key_sum_and_quotient() {
        let fixture = fixture();
        let proof = fixture.prover_key.prove(&[1, 2, 3]).unwrap();
        let other = fixture.prover_key.prove(&[1, 2, 4]).unwrap();
        let forgery = proof.with_quotient_of(&other);
        assert!(fixture.verifier_key.verify(&forgery).is_err());
    }

    /// Summing a client twice would give its input weight -1 in the aggregate.
    #[test]
    fn rejects_repeated_client() {
        let fixture = fixture();
        let paillier = fixture.prover_key.paillier_public_key();
        let honest = fixture.prover_key.prove(&[5, 6]).unwrap();
        let repeated = &fixture.record(5).encrypted_key;

        // The quotient the prover would compute for the multiset {5, 5, 6}.
        for quotient in [
            honest.quotient,
            fixture.prover_key.commit_quotient(&[5, 5, 6]),
        ] {
            let proof = DropoutProof {
                key_sum: paillier.sum([&honest.key_sum, repeated].into_par_iter()),
                quotient,
            };
            assert!(fixture.verifier_key.verify(&proof).is_err());
        }
    }

    #[test]
    fn rejects_scaled_key_sum() {
        let fixture = fixture();
        for factor in [0, 2, 3, 1 << 20] {
            let mut proof = fixture.prover_key.prove(&[7, 8, 9]).unwrap();
            fixture.tamper_key_sum(&mut proof, factor, &Integer::new());
            assert!(fixture.verifier_key.verify(&proof).is_err());
        }
    }

    /// The offsets a heavy server might add to a packing: one unit in a slot,
    /// or the BLS12-381 scalar field order (which the quotient check cannot
    /// see), each either added or subtracted.
    fn slot_offsets(modulus: &Integer) -> Vec<Integer> {
        let field_order = fr_to_integer(&-Fr::one()) + 1u32;
        let mut offsets = Vec::new();
        for slot in 0..NUM_SLOTS as u32 {
            for value in [Integer::from(1), field_order.clone()] {
                let offset = value << (slot * SLOT_BITS);
                offsets.push(Integer::from(modulus - &offset));
                offsets.push(offset);
            }
        }
        offsets
    }

    /// A constant added by the heavy server reaches the verifier divided by
    /// the secret multiplier, so it is never accepted.
    #[test]
    fn rejects_added_constants() {
        let fixture = fixture();
        let modulus = fixture.prover_key.paillier_public_key().modulus();
        for offset in slot_offsets(modulus) {
            let mut proof = fixture.prover_key.prove(&[7, 8, 9]).unwrap();
            fixture.tamper_key_sum(&mut proof, 1, &offset);
            assert!(fixture.verifier_key.verify(&proof).is_err());
        }
    }

    /// Whether a shifted proof is rejected must not depend on the clients'
    /// keys: otherwise each answer would leak a comparison on their sum.
    #[test]
    fn rejects_shifted_proofs_whatever_the_keys() {
        let fixture = fixture();
        let modulus = fixture.prover_key.paillier_public_key().modulus();
        // Enough to carry out of the key slot for some key sums but not others.
        let field_order = fr_to_integer(&-Fr::one()) + 1u32;
        let slot_size = Integer::from(1) << SLOT_BITS;
        let carrying = Integer::from(&slot_size / &field_order) * field_order;

        let offsets = slot_offsets(modulus).into_iter().chain([carrying]);
        for offset in offsets {
            for count in [1, 2, 3, 8] {
                let dropouts = random_dropouts(NUM_CLIENTS, count);
                let mut proof = fixture.prover_key.prove(&dropouts).unwrap();
                fixture.tamper_key_sum(&mut proof, 1, &offset);
                assert!(fixture.verifier_key.verify(&proof).is_err());
            }
        }
    }

    /// Lowering the count slot would hide dropouts from the threshold check.
    #[test]
    fn rejects_understated_count() {
        let fixture = fixture();
        let paillier = fixture.prover_key.paillier_public_key();
        let mut proof = fixture.prover_key.prove(&[7, 8, 9]).unwrap();
        let minus_one_count = paillier.modulus() - (Integer::from(1) << SLOT_BITS);
        fixture.tamper_key_sum(&mut proof, 1, &minus_one_count);
        assert!(fixture.verifier_key.verify(&proof).is_err());
    }

    /// A coefficient of `1 + r` looks like 1 to the quotient check, but
    /// overflows the packing.
    #[test]
    fn rejects_coefficient_congruent_to_one() {
        let fixture = fixture();
        let paillier = fixture.prover_key.paillier_public_key();
        let honest = fixture.prover_key.prove(&[7, 8]).unwrap();
        let field_order = fr_to_integer(&-Fr::one()) + 1u32;
        let extra = paillier.scale(&fixture.record(8).encrypted_key, &field_order);
        let proof = DropoutProof {
            key_sum: paillier.sum([&honest.key_sum, &extra].into_par_iter()),
            quotient: honest.quotient,
        };
        assert!(fixture.verifier_key.verify(&proof).is_err());
    }

    /// Bits above the packing, or above a machine word in the count slot, are
    /// not silently dropped. (Only the key holder can build these packings.)
    #[test]
    fn rejects_malformed_packing() {
        let fixture = fixture();
        let verifier_key = &fixture.verifier_key;
        let modulus = verifier_key.paillier_public_key().modulus();
        let honest = fixture.prover_key.prove(&[7, 8]).unwrap();
        let plaintext = verifier_key.paillier.decrypt(&honest.key_sum).unwrap();

        for extra_bit in [PACKING_BITS, SLOT_BITS + 64] {
            let extra = Integer::from(&verifier_key.blind << extra_bit);
            let malformed = (&plaintext + extra) % modulus;
            let proof = DropoutProof {
                key_sum: verifier_key.paillier.encrypt(&malformed, &mut OsRng),
                quotient: honest.quotient,
            };
            assert!(verifier_key.verify(&proof).is_err());
        }
    }

    /// This attack presents client `i` with coefficient -1 as "everyone but
    /// `i`" by shifting the slots with constants. That satisfies the quotient
    /// check (`1 - L_i` is a bit polynomial) and reports a plausible count,
    /// yet yields the key sum `-k_i`. It needs the secret multiplier.
    #[test]
    fn rejects_negated_client_with_compensating_constants() {
        // All domain points are in use, so that the constant 1 is a valid bit polynomial.
        let fixture = Fixture::new(8);
        let paillier = fixture.prover_key.paillier_public_key();
        let target = fixture.record(3);

        let group_order = scalar_to_integer(&-Scalar::ONE) + 1u32;
        let field_order = fr_to_integer(&-Fr::one()) + 1u32;
        let offset = pack([group_order, Integer::from(3), field_order + 1u32]);
        let negated = paillier.scale(&target.encrypted_key, &Integer::from(-1));
        let attack = |offset: &Integer| DropoutProof {
            key_sum: paillier.sum([&negated, &paillier.encrypt_public(offset)].into_par_iter()),
            // (1 - L_i)^2 - (1 - L_i) = L_i^2 - L_i
            quotient: target.square_base,
        };

        // With the multiplier, the attack goes through.
        let blinded = Integer::from(&offset * &fixture.verifier_key.blind) % paillier.modulus();
        let verified = fixture.verifier_key.verify(&attack(&blinded)).unwrap();
        assert_eq!(verified.count, 2);
        assert_eq!(verified.key_sum, -fixture.client_keys[3]);

        // Without it, the heavy server can only add the constants unblinded.
        assert!(fixture.verifier_key.verify(&attack(&offset)).is_err());
    }

    #[test]
    fn rejects_garbage() {
        let fixture = fixture();
        let honest = fixture.prover_key.prove(&[1]).unwrap();
        let modulus_squared = fixture
            .prover_key
            .paillier_public_key()
            .modulus()
            .clone()
            .square();
        for _ in 0..10 {
            let mut bytes = [0u8; PAILLIER_MODULUS_BITS as usize / 4];
            OsRng.fill(&mut bytes[..]);
            let random = Integer::from_digits(&bytes, Order::Lsf) % &modulus_squared;
            let proof = DropoutProof {
                key_sum: paillier::Ciphertext::from_integer(random),
                quotient: honest.quotient,
            };
            assert!(fixture.verifier_key.verify(&proof).is_err());
        }
        let proof = DropoutProof {
            key_sum: honest.key_sum,
            quotient: G1Affine::rand(&mut OsRng),
        };
        assert!(fixture.verifier_key.verify(&proof).is_err());
    }

    /// A proof is bound to the verifier key it was made for.
    #[test]
    fn rejects_proof_for_other_key() {
        let other = Fixture::new(NUM_CLIENTS);
        let proof = other.prover_key.prove(&[1, 2]).unwrap();
        assert!(fixture().verifier_key.verify(&proof).is_err());
    }
}
