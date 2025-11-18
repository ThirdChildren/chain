use super::backend::{CryptoHash, CryptoHasher, HashBackend};
use crate::U256;
use std::fmt;

/// Blake3 hash output (256 bits)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Blake3Hash(U256);

impl CryptoHash for Blake3Hash {
    fn output_size() -> usize {
        32
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        self.0.write_as_little_endian(&mut bytes);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != 32 {
            return Err("Blake3Hash requires exactly 32 bytes".into());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Blake3Hash(U256::from_little_endian(&array)))
    }
}

impl Blake3Hash {
    /// Create a hash from a 32-byte array directly
    pub fn from_bytes_array(bytes: [u8; 32]) -> Self {
        Blake3Hash(U256::from_little_endian(&bytes))
    }

    /// Create a hash from a U256 value directly
    pub fn from_u256(value: U256) -> Self {
        Blake3Hash(value)
    }

    /// Check if hash meets target difficulty
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Blake3Hash(U256::zero())
    }

    /// Get the inner U256 value
    pub fn as_u256(&self) -> U256 {
        self.0
    }

    /// Convert hash to bytes array
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = vec![0u8; 32];
        self.0.write_as_little_endian(&mut bytes);
        bytes.as_slice().try_into().unwrap()
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// Blake3 hasher
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoHasher for Blake3Hasher {
    type Output = Blake3Hash;

    fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        let hash = self.inner.finalize();
        let hash_bytes = hash.as_bytes();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Blake3Hash(U256::from_little_endian(&hash_array))
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Blake3Hasher {
    /// Create a hasher with a custom key (for HMAC-like usage)
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
        }
    }

    /// Create a hasher for key derivation
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            inner: blake3::Hasher::new_derive_key(context),
        }
    }

    /// Finalize and return raw bytes
    pub fn finalize_bytes(self) -> [u8; 32] {
        let hash = self.inner.finalize();
        *hash.as_bytes()
    }
}

/// Blake3 backend implementation
pub struct Blake3Backend;

impl HashBackend for Blake3Backend {
    type Hash = Blake3Hash;
    type Hasher = Blake3Hasher;

    fn new_hasher() -> Self::Hasher {
        Blake3Hasher::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash1 = hasher.finalize();

        let hash2 = Blake3Backend::hash_data(b"Hello, World!");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"deterministic test data";

        let hash1 = Blake3Backend::hash_data(data);
        let hash2 = Blake3Backend::hash_data(data);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; 32];
        let mut hasher1 = Blake3Hasher::new_keyed(&key);
        hasher1.update(b"authenticated data");
        let hash1 = hasher1.finalize();

        let mut hasher2 = Blake3Hasher::new_keyed(&key);
        hasher2.update(b"authenticated data");
        let hash2 = hasher2.finalize();

        assert_eq!(hash1, hash2);

        let different_key = [24u8; 32];
        let mut hasher3 = Blake3Hasher::new_keyed(&different_key);
        hasher3.update(b"authenticated data");
        let hash3 = hasher3.finalize();

        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake3_bytes_conversion() {
        let data = b"test data";
        let hash = Blake3Backend::hash_data(data);
        let bytes = hash.to_bytes();
        let hash2 = Blake3Hash::from_bytes(&bytes).unwrap();

        assert_eq!(hash, hash2);
    }
}
