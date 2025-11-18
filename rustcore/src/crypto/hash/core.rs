use super::backend::CryptoHasher;
use super::default::{DefaultHash, DefaultHasher};
use crate::U256;
use std::fmt;

/// Main Hash type that uses the default backend
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash(DefaultHash);

/// Trait for types that can be hashed
pub trait Hashable {
    fn hash_update(&self, hasher: &mut Hasher);
}

// Implement Hashable for common types
impl Hashable for &[u8] {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(self);
    }
}

impl Hashable for u8 {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&[*self]);
    }
}

impl Hashable for u32 {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&self.to_le_bytes());
    }
}

impl Hashable for u64 {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&self.to_le_bytes());
    }
}

impl Hashable for u128 {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&self.to_le_bytes());
    }
}

impl Hashable for usize {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&(*self as u64).to_le_bytes());
    }
}

impl<const N: usize> Hashable for [u8; N] {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(self);
    }
}

impl<const N: usize> Hashable for &[u8; N] {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(*self);
    }
}

impl Hashable for Vec<u8> {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(self);
    }
}

impl Hashable for &Vec<u8> {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(self);
    }
}

impl Hashable for Hash {
    fn hash_update(&self, hasher: &mut Hasher) {
        hasher.inner.update(&self.as_bytes());
    }
}

/// Hasher that uses the default backend
pub struct Hasher {
    inner: DefaultHasher,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            inner: DefaultHasher::new(),
        }
    }

    /// Universal input function - accepts any Hashable type
    pub fn input<T: Hashable>(&mut self, data: T) -> &mut Self {
        data.hash_update(self);
        self
    }

    pub fn finalize(self) -> Hash {
        Hash(self.inner.finalize())
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Hash {
    /// Create a hash from a 32-byte array directly (for transaction IDs)
    pub fn from_bytes_array(bytes: [u8; 32]) -> Self {
        Hash(DefaultHash::from_bytes_array(bytes))
    }

    /// Create a hash from a U256 value directly
    pub fn from_u256(value: U256) -> Self {
        Hash(DefaultHash::from_u256(value))
    }

    /// Check if hash meets target difficulty
    pub fn matches_target(&self, target: U256) -> bool {
        self.0.matches_target(target)
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Hash(DefaultHash::zero())
    }

    /// Get the inner U256 value
    pub fn as_u256(&self) -> U256 {
        self.0.as_u256()
    }

    /// Convert hash to bytes array
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.as_bytes()
    }

    /// Hash function base
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.input(data);
        hasher.finalize()
    }

    /// Hash with builder closure
    pub fn compute<F>(builder: F) -> Self
    where
        F: FnOnce(&mut Hasher),
    {
        let mut hasher = Hasher::new();
        builder(&mut hasher);
        hasher.finalize()
    }

    /// Hash of multiple data
    pub fn hash_parts(data_parts: &[&[u8]]) -> Self {
        let mut hasher = Hasher::new();
        for part in data_parts {
            hasher.input(*part);
        }
        hasher.finalize()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hasher_basic() {
        let mut hasher = Hasher::new();
        hasher.input(b"Hello, ");
        hasher.input(b"World!");
        let hash1 = hasher.finalize();

        let hash2 = Hash::hash(b"Hello, World!");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hasher_with_builder() {
        let hash1 = Hash::compute(|hasher| {
            hasher.input(b"test");
            hasher.input(42u32);
            hasher.input(1234567890u64);
        });

        let hash2 = Hash::compute(|hasher| {
            hasher.input(b"test");
            hasher.input(42u32);
            hasher.input(1234567890u64);
        });

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hasher_multiple_data() {
        let data_parts: &[&[u8]] = &[b"part1", b"part2", b"part3"];
        let hash1 = Hash::hash_parts(data_parts);

        let hash2 = Hash::compute(|hasher| {
            for part in data_parts {
                hasher.input(*part);
            }
        });

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hasher_number_methods() {
        let hash1 = Hash::compute(|hasher| {
            hasher.input(0xFFu8);
            hasher.input(0x12345678u32);
            hasher.input(0x123456789ABCDEF0u64);
        });

        let mut data = Vec::new();
        data.push(0xFF);
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        data.extend_from_slice(&0x123456789ABCDEF0u64.to_le_bytes());
        let hash2 = Hash::hash(&data);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"deterministic test data";

        let hash1 = Hash::hash(data);
        let hash2 = Hash::hash(data);
        let hash3 = Hash::compute(|hasher| {
            hasher.input(data);
        });

        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
        assert_eq!(hash2, hash3);
    }
}
