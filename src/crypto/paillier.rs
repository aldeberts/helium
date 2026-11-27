//! Paillier's additively homomorphic encryption scheme.
//!
//! Specialised to how Helium uses it: the key owner (the light server) is the
//! only party that encrypts or decrypts, so both operations use the
//! factorisation of the modulus; everyone else only adds ciphertexts.
//!
//! This is not a constant-time implementation.

use anyhow::{Result, anyhow, ensure};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use rug::{
    Integer,
    integer::{IsPrime, Order},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

/// Miller-Rabin repetitions used when generating primes.
const PRIMALITY_REPS: u32 = 40;

/// The modulus `N = pq`. Enough to add ciphertexts, which is all that parties
/// other than the key owner do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    n: Integer,
    n_squared: Integer,
}

/// The factorisation of the modulus, with the constants that encryption and
/// decryption by Chinese remaindering need.
#[derive(Clone)]
pub struct SecretKey {
    public: PublicKey,
    p: Factor,
    q: Factor,
    /// `p^-1 mod q`
    p_inv_q: Integer,
    /// `(p^2)^-1 mod q^2`
    p_squared_inv_q_squared: Integer,
}

/// An element of `Z_{N^2}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(Integer);

/// One prime factor of the modulus.
#[derive(Clone)]
struct Factor {
    prime: Integer,
    squared: Integer,
    /// `(-cofactor)^-1 mod prime`: scales `L(c^(prime-1) mod prime^2)` to the plaintext.
    decrypt_scale: Integer,
}

impl PublicKey {
    fn new(n: Integer) -> Self {
        let n_squared = n.clone().square();
        Self { n, n_squared }
    }

    /// The modulus `N`. Plaintexts are integers in `[0, N)`.
    pub fn modulus(&self) -> &Integer {
        &self.n
    }

    /// A uniformly random plaintext that is invertible modulo `N`.
    pub fn random_unit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Integer {
        loop {
            let candidate = random_below(&self.n, rng);
            if candidate.clone().gcd(&self.n) == 1 {
                return candidate;
            }
        }
    }

    /// Homomorphically adds the plaintexts of `ciphertexts`. The sum of no
    /// ciphertexts is an encryption of zero.
    pub fn sum<'a>(&self, ciphertexts: impl ParallelIterator<Item = &'a Ciphertext>) -> Ciphertext {
        let mul = |a: Integer, b: &Integer| a * b % &self.n_squared;
        Ciphertext(
            ciphertexts
                .fold(|| Integer::from(1), |acc, ct| mul(acc, &ct.0))
                .reduce(|| Integer::from(1), |a, b| mul(a, &b)),
        )
    }
}

impl SecretKey {
    /// Generates a key whose modulus has exactly `modulus_bits` bits.
    pub fn generate<R: RngCore + CryptoRng>(modulus_bits: u32, rng: &mut R) -> Self {
        assert!(
            modulus_bits >= 16 && modulus_bits % 2 == 0,
            "modulus size must be even"
        );
        let p = random_prime(modulus_bits / 2, rng);
        let q = loop {
            let q = random_prime(modulus_bits / 2, rng);
            if q != p {
                break q;
            }
        };
        Self::from_primes(p, q)
    }

    /// `p` and `q` must be distinct primes of the same bit length, which makes
    /// `N` coprime to `phi(N)` as Paillier requires.
    fn from_primes(p: Integer, q: Integer) -> Self {
        let invert = |x: &Integer, modulus: &Integer| {
            x.clone()
                .invert(modulus)
                .expect("distinct primes are coprime")
        };
        let p_factor = Factor::new(&p, &q);
        let q_factor = Factor::new(&q, &p);
        Self {
            p_inv_q: invert(&p, &q),
            p_squared_inv_q_squared: invert(&p_factor.squared, &q_factor.squared),
            public: PublicKey::new(p * q),
            p: p_factor,
            q: q_factor,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Encrypts `plaintext`, which must lie in `[0, N)`.
    pub fn encrypt<R: RngCore + CryptoRng>(&self, plaintext: &Integer, rng: &mut R) -> Ciphertext {
        let PublicKey { n, n_squared } = &self.public;
        assert!(
            *plaintext >= 0 && plaintext < n,
            "plaintext out of range for the Paillier modulus"
        );
        // c = (1 + N)^m * r^N, where the N-th residue r^N is sampled per prime factor.
        let residue = garner(
            self.p.random_residue(rng),
            self.q.random_residue(rng),
            &self.p.squared,
            &self.q.squared,
            &self.p_squared_inv_q_squared,
        );
        Ciphertext((Integer::from(plaintext * n) + 1) * residue % n_squared)
    }

    /// Decrypts `ciphertext` to its plaintext in `[0, N)`. Fails if the
    /// ciphertext is not a unit of `Z_{N^2}`.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Integer> {
        let ct = &ciphertext.0;
        ensure!(
            *ct > 0 && ct < &self.public.n_squared,
            "Paillier ciphertext out of range"
        );
        let invalid = || anyhow!("Paillier ciphertext is not a unit");
        Ok(garner(
            self.p.decrypt(ct).ok_or_else(invalid)?,
            self.q.decrypt(ct).ok_or_else(invalid)?,
            &self.p.prime,
            &self.q.prime,
            &self.p_inv_q,
        ))
    }
}

impl Factor {
    fn new(prime: &Integer, cofactor: &Integer) -> Self {
        let decrypt_scale = Integer::from(-cofactor)
            .modulo(prime)
            .invert(prime)
            .expect("distinct primes are coprime");
        Self {
            prime: prime.clone(),
            squared: prime.clone().square(),
            decrypt_scale,
        }
    }

    /// A uniformly random `N`-th residue modulo `prime^2`.
    ///
    /// Those residues are the subgroup of order `prime - 1` (raising to the
    /// cofactor permutes it, as the cofactor is a prime too large to divide
    /// `prime - 1`), which is the image of the `prime`-th power map.
    fn random_residue<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Integer {
        let base = random_below(&Integer::from(&self.prime - 1), rng) + 1u32;
        base.secure_pow_mod(&self.prime, &self.squared)
    }

    /// The plaintext of `ct` modulo `prime`, or `None` if `ct` is not a unit.
    fn decrypt(&self, ct: &Integer) -> Option<Integer> {
        // (1 + N)^m * r^N raised to prime - 1 is 1 - m * cofactor * prime mod prime^2.
        let exponent = Integer::from(&self.prime - 1);
        let base = Integer::from(ct % &self.squared);
        if base.is_divisible(&self.prime) {
            return None;
        }
        let quotient = (base.secure_pow_mod(&exponent, &self.squared) - 1) / &self.prime;
        Some(quotient * &self.decrypt_scale % &self.prime)
    }
}

/// The integer in `[0, p * q)` that is `a_p` modulo `p` and `a_q` modulo `q`.
fn garner(a_p: Integer, a_q: Integer, p: &Integer, q: &Integer, p_inv_q: &Integer) -> Integer {
    let multiple = ((a_q - &a_p) * p_inv_q).modulo(q);
    a_p + multiple * p
}

/// A uniformly random integer in `[0, bound)`.
fn random_below<R: RngCore + CryptoRng>(bound: &Integer, rng: &mut R) -> Integer {
    // 64 surplus bits make the bias of the reduction negligible.
    let mut bytes = vec![0u8; bound.significant_bits() as usize / 8 + 9];
    rng.fill_bytes(&mut bytes);
    Integer::from_digits(&bytes, Order::Lsf) % bound
}

/// A random prime of exactly `bits` bits. Its two top bits are set, so the
/// product of two such primes has exactly `2 * bits` bits.
fn random_prime<R: RngCore + CryptoRng>(bits: u32, rng: &mut R) -> Integer {
    let top_bits = Integer::from(3) << (bits - 2);
    loop {
        let candidate = random_below(&(Integer::from(1) << (bits - 2)), rng) | &top_bits | 1u32;
        if candidate.is_probably_prime(PRIMALITY_REPS) != IsPrime::No {
            return candidate;
        }
    }
}

/// Serde adapter for non-negative integers, as little-endian bytes.
pub(crate) mod integer_serde {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &Integer,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&value.to_digits::<u8>(Order::Lsf))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Integer, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Integer::from_digits(&bytes, Order::Lsf))
    }
}

impl Serialize for Ciphertext {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        integer_serde::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        integer_serde::deserialize(deserializer).map(Self)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        integer_serde::serialize(&self.n, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = integer_serde::deserialize(deserializer)?;
        if n <= 1 {
            return Err(D::Error::custom("Paillier modulus must exceed 1"));
        }
        Ok(Self::new(n))
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let digits = |x: &Integer| x.to_digits::<u8>(Order::Lsf);
        (digits(&self.p.prime), digits(&self.q.prime)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (p, q) = <(Vec<u8>, Vec<u8>)>::deserialize(deserializer)?;
        let p = Integer::from_digits(&p, Order::Lsf);
        let q = Integer::from_digits(&q, Order::Lsf);
        let is_prime = |x: &Integer| x.is_probably_prime(PRIMALITY_REPS) != IsPrime::No;
        if p == q || p.significant_bits() != q.significant_bits() || !is_prime(&p) || !is_prime(&q)
        {
            return Err(D::Error::custom("invalid Paillier secret key"));
        }
        Ok(Self::from_primes(p, q))
    }
}

#[cfg(test)]
impl PublicKey {
    /// An encryption of `plaintext` with no randomness, as anyone can produce.
    pub(crate) fn encrypt_public(&self, plaintext: &Integer) -> Ciphertext {
        Ciphertext((Integer::from(plaintext * &self.n) + 1) % &self.n_squared)
    }

    /// Homomorphically multiplies the plaintext of `ciphertext` by `scalar`.
    pub(crate) fn scale(&self, ciphertext: &Ciphertext, scalar: &Integer) -> Ciphertext {
        let power = ciphertext.0.clone().pow_mod(scalar, &self.n_squared);
        Ciphertext(power.expect("ciphertext is a unit"))
    }
}

#[cfg(test)]
impl Ciphertext {
    pub(crate) fn from_integer(value: Integer) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const TEST_MODULUS_BITS: u32 = 1024;

    fn random_plaintext(sk: &SecretKey) -> Integer {
        random_below(sk.public_key().modulus(), &mut OsRng)
    }

    #[test]
    fn modulus_has_requested_size() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        assert_eq!(
            sk.public_key().modulus().significant_bits(),
            TEST_MODULUS_BITS
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let n = sk.public_key().modulus();
        let edge_cases = [Integer::from(0), Integer::from(1), Integer::from(n - 1)];
        let random_cases = (0..8).map(|_| random_plaintext(&sk));
        for plaintext in edge_cases.into_iter().chain(random_cases) {
            let ciphertext = sk.encrypt(&plaintext, &mut OsRng);
            assert_eq!(sk.decrypt(&ciphertext).unwrap(), plaintext);
        }
    }

    #[test]
    fn encryption_is_randomized() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let plaintext = random_plaintext(&sk);
        assert_ne!(
            sk.encrypt(&plaintext, &mut OsRng),
            sk.encrypt(&plaintext, &mut OsRng)
        );
    }

    /// The owner's encryption must produce textbook ciphertexts `(1 + N)^m r^N`:
    /// stripping the message leaves an `N`-th residue, whose order divides `phi(N)`.
    #[test]
    fn owner_encryption_matches_textbook_form() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let n_squared = &sk.public_key().n_squared;
        let plaintext = random_plaintext(&sk);
        let ciphertext = sk.encrypt(&plaintext, &mut OsRng);

        let message_part = sk.public_key().encrypt_public(&plaintext).0;
        let residue = ciphertext.0 * message_part.invert(n_squared).unwrap() % n_squared;
        let phi = Integer::from(&sk.p.prime - 1) * Integer::from(&sk.q.prime - 1);
        assert_eq!(residue.pow_mod(&phi, n_squared).unwrap(), 1);
    }

    #[test]
    fn sum_adds_plaintexts() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let pk = sk.public_key();
        let plaintexts: Vec<Integer> = (0..50).map(|_| random_plaintext(&sk)).collect();
        let ciphertexts: Vec<Ciphertext> = plaintexts
            .iter()
            .map(|m| sk.encrypt(m, &mut OsRng))
            .collect();

        let expected = plaintexts.iter().sum::<Integer>() % pk.modulus();
        let sum = pk.sum(ciphertexts.par_iter());
        assert_eq!(sk.decrypt(&sum).unwrap(), expected);

        // The empty sum encrypts zero.
        let empty = pk.sum(rayon::iter::empty());
        assert_eq!(sk.decrypt(&empty).unwrap(), 0);
    }

    #[test]
    fn decrypt_rejects_invalid_ciphertexts() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let PublicKey { n, n_squared } = sk.public_key();
        let invalid = [
            Integer::from(0),
            n.clone(),
            sk.p.prime.clone(),
            n_squared.clone(),
            Integer::from(n_squared + 1),
        ];
        for value in invalid {
            assert!(sk.decrypt(&Ciphertext(value)).is_err());
        }
    }

    #[test]
    fn keys_and_ciphertexts_serialize() {
        let sk = SecretKey::generate(TEST_MODULUS_BITS, &mut OsRng);
        let plaintext = random_plaintext(&sk);
        let ciphertext = sk.encrypt(&plaintext, &mut OsRng);

        let sk2: SecretKey = bincode::deserialize(&bincode::serialize(&sk).unwrap()).unwrap();
        let pk2: PublicKey =
            bincode::deserialize(&bincode::serialize(sk.public_key()).unwrap()).unwrap();
        let ct2: Ciphertext =
            bincode::deserialize(&bincode::serialize(&ciphertext).unwrap()).unwrap();

        assert_eq!(&pk2, sk.public_key());
        assert_eq!(ct2, ciphertext);
        assert_eq!(sk2.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn deserialization_rejects_bad_keys() {
        let composite = (vec![15u8], vec![13u8]);
        let equal = (vec![13u8], vec![13u8]);
        for primes in [composite, equal] {
            let bytes = bincode::serialize(&primes).unwrap();
            assert!(bincode::deserialize::<SecretKey>(&bytes).is_err());
        }
        let zero_modulus = bincode::serialize(&Vec::<u8>::new()).unwrap();
        assert!(bincode::deserialize::<PublicKey>(&zero_modulus).is_err());
    }
}
