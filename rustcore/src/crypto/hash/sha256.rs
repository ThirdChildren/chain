use super::backend::{CryptoHash, CryptoHasher, HashBackend};
use crate::U256;
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::fmt;

/// SHA-256 hash output (256 bits)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sha256Hash(U256);

impl CryptoHash for Sha256Hash {
    fn output_size() -> usize {
        32
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        self.0.write_as_big_endian(&mut bytes);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != 32 {
            return Err("Sha256Hash requires exactly 32 bytes".into());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Sha256Hash(U256::from_big_endian(&array)))
    }
}

impl Sha256Hash {
    /// Create a hash from a 32-byte array directly
    pub fn from_bytes_array(bytes: [u8; 32]) -> Self {
        Sha256Hash(U256::from_big_endian(&bytes))
    }

    /// Create a hash from a U256 value directly
    pub fn from_u256(value: U256) -> Self {
        Sha256Hash(value)
    }

    /// Check if hash meets target difficulty
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Sha256Hash(U256::zero())
    }

    /// Get the inner U256 value
    pub fn as_u256(&self) -> U256 {
        self.0
    }

    /// Convert hash to bytes array
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = vec![0u8; 32];
        self.0.write_as_big_endian(&mut bytes);
        bytes.as_slice().try_into().unwrap()
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// SHA-256 hasher
pub struct Sha256CryptoHasher {
    inner: Sha256Hasher,
}

impl Default for Sha256CryptoHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoHasher for Sha256CryptoHasher {
    type Output = Sha256Hash;

    fn new() -> Self {
        Self {
            inner: Sha256Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        let hash = self.inner.finalize();
        let hash_array: [u8; 32] = hash.into();
        Sha256Hash(U256::from_big_endian(&hash_array))
    }

    fn reset(&mut self) {
        self.inner = Sha256Hasher::new();
    }
}

/// SHA-256 backend implementation
pub struct Sha256Backend;

impl HashBackend for Sha256Backend {
    type Hash = Sha256Hash;
    type Hasher = Sha256CryptoHasher;

    fn new_hasher() -> Self::Hasher {
        Sha256CryptoHasher::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_basic() {
        let mut hasher = Sha256CryptoHasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash1 = hasher.finalize();

        let hash2 = Sha256Backend::hash_data(b"Hello, World!");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"deterministic test data";

        let hash1 = Sha256Backend::hash_data(data);
        let hash2 = Sha256Backend::hash_data(data);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_bytes_conversion() {
        let data = b"test data";
        let hash = Sha256Backend::hash_data(data);
        let bytes = hash.to_bytes();
        let hash2 = Sha256Hash::from_bytes(&bytes).unwrap();

        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string should be:
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = Sha256Backend::hash_data(b"");
        let bytes = hash.as_bytes();

        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();

        assert_eq!(&bytes[..], &expected[..]);
    }

    #[test]
    fn test_sha256_reset() {
        let mut hasher = Sha256CryptoHasher::new();
        hasher.update(b"some data");
        hasher.reset();
        hasher.update(b"Hello, World!");
        let hash1 = hasher.finalize();

        let hash2 = Sha256Backend::hash_data(b"Hello, World!");

        assert_eq!(hash1, hash2);
    }
}
