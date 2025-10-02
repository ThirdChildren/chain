use crate::U256;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash(U256);

impl Hash {
    /// Create a hash from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let hash_bytes = hash.as_bytes();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Hash(U256::from_little_endian(&hash_array))
    }
    
    /// Create a hash from a U256 value directly
    pub fn from_u256(value: U256) -> Self {
        Hash(value)
    }

    /// Check if hash meets target difficulty
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Hash(U256::zero())
    }
    
    /// Get the inner U256 value
    pub fn as_u256(&self) -> U256 {
        self.0
    }

    /// Convert hash to bytes array
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes: Vec<u8> = vec![0; 32];
        self.0.write_as_little_endian(&mut bytes);
        bytes.as_slice().try_into().unwrap()
    }
    
    /// Simple hash method for basic compatibility
    /// For structured data, consider using a proper serialization method first
    pub fn hash(data: &[u8]) -> Self {
        Self::from_bytes(data)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}