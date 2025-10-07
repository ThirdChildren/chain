use crate::U256;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash(U256);

/// Blake3 Hasher wrapper per hashing incrementale
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Crea un nuovo hasher Blake3
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }
    
    /// Crea un hasher con una chiave personalizzata (per HMAC-like)
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
        }
    }
    
    /// Crea un hasher per key derivation
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            inner: blake3::Hasher::new_derive_key(context),
        }
    }
    
    /// Aggiunge dati all'hasher
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }
    
    /// Aggiunge un singolo byte
    pub fn update_byte(&mut self, byte: u8) -> &mut Self {
        self.inner.update(&[byte]);
        self
    }
    
    /// Aggiunge un u32 in little-endian
    pub fn update_u32_le(&mut self, value: u32) -> &mut Self {
        self.inner.update(&value.to_le_bytes());
        self
    }
    
    /// Aggiunge un u64 in little-endian
    pub fn update_u64_le(&mut self, value: u64) -> &mut Self {
        self.inner.update(&value.to_le_bytes());
        self
    }
    
    /// Finalizza l'hash e restituisce il risultato
    pub fn finalize(self) -> Hash {
        let hash = self.inner.finalize();
        let hash_bytes = hash.as_bytes();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Hash(U256::from_little_endian(&hash_array))
    }
    
    /// Finalizza e restituisce i bytes grezzi
    pub fn finalize_bytes(self) -> [u8; 32] {
        let hash = self.inner.finalize();
        *hash.as_bytes()
    }
    
    /// Reset dell'hasher per riutilizzo
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Hash {
    /// Create a hash from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let hash_bytes = hash.as_bytes();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Hash(U256::from_little_endian(&hash_array))
    }
    
    /// Create a hash from a 32-byte array directly (for transaction IDs)
    pub fn from_bytes_array(bytes: [u8; 32]) -> Self {
        Hash(U256::from_little_endian(&bytes))
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
    
    /// Hash incrementale usando l'Hasher per dati complessi
    pub fn hash_with_hasher<F>(builder: F) -> Self 
    where 
        F: FnOnce(&mut Hasher),
    {
        let mut hasher = Hasher::new();
        builder(&mut hasher);
        hasher.finalize()
    }
    
    /// Hash di dati multipli 
    pub fn hash_multiple(data_parts: &[&[u8]]) -> Self {
        let mut hasher = Hasher::new();
        for part in data_parts {
            hasher.update(part);
        }
        hasher.finalize()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hasher_basic() {
        let mut hasher = Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash1 = hasher.finalize();
        
        let hash2 = Hash::hash(b"Hello, World!");
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_hasher_with_builder() {
        let hash1 = Hash::hash_with_hasher(|hasher| {
            hasher.update(b"test");
            hasher.update_u32_le(42);
            hasher.update_u64_le(1234567890);
        });
        
        let hash2 = Hash::hash_with_hasher(|hasher| {
            hasher.update(b"test");
            hasher.update_u32_le(42);
            hasher.update_u64_le(1234567890);
        });
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_hasher_multiple_data() {
        let data_parts: &[&[u8]] = &[b"part1", b"part2", b"part3"];
        let hash1 = Hash::hash_multiple(data_parts);
        
        let hash2 = Hash::hash_with_hasher(|hasher| {
            for part in data_parts {
                hasher.update(part);
            }
        });
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_hasher_keyed() {
        let key = [42u8; 32];
        let mut hasher1 = Hasher::new_keyed(&key);
        hasher1.update(b"authenticated data");
        let hash1 = hasher1.finalize();
        
        let mut hasher2 = Hasher::new_keyed(&key);
        hasher2.update(b"authenticated data");
        let hash2 = hasher2.finalize();
        
        assert_eq!(hash1, hash2);
        
        // Hash con chiave diversa dovrebbe essere diverso
        let different_key = [24u8; 32];
        let mut hasher3 = Hasher::new_keyed(&different_key);
        hasher3.update(b"authenticated data");
        let hash3 = hasher3.finalize();
        
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_hasher_derive_key() {
        let mut hasher1 = Hasher::new_derive_key("context1");
        hasher1.update(b"input data");
        let derived1 = hasher1.finalize();
        
        let mut hasher2 = Hasher::new_derive_key("context1");
        hasher2.update(b"input data");
        let derived2 = hasher2.finalize();
        
        assert_eq!(derived1, derived2);
        
        // Contesto diverso dovrebbe produrre chiave diversa
        let mut hasher3 = Hasher::new_derive_key("context2");
        hasher3.update(b"input data");
        let derived3 = hasher3.finalize();
        
        assert_ne!(derived1, derived3);
    }
    
    #[test]
    fn test_hasher_finalize_bytes() {
        let mut hasher = Hasher::new();
        hasher.update(b"test data");
        let bytes = hasher.finalize_bytes();
        
        assert_eq!(bytes.len(), 32);
        
        let mut hasher2 = Hasher::new();
        hasher2.update(b"test data");
        let hash = hasher2.finalize();
        
        assert_eq!(bytes, hash.as_bytes());
    }
    
    #[test]
    fn test_hasher_number_methods() {
        let hash1 = Hash::hash_with_hasher(|hasher| {
            hasher.update_byte(0xFF);
            hasher.update_u32_le(0x12345678);
            hasher.update_u64_le(0x123456789ABCDEF0);
        });
        
        // Manuale equivalente
        let mut data = Vec::new();
        data.push(0xFF);
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        data.extend_from_slice(&0x123456789ABCDEF0u64.to_le_bytes());
        let hash2 = Hash::hash(&data);
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_hash_deterministic() {
        // Verifica che l'hashing sia sempre deterministico
        let data = b"deterministic test data";
        
        let hash1 = Hash::hash(data);
        let hash2 = Hash::hash(data);
        let hash3 = Hash::hash_with_hasher(|hasher| { hasher.update(data); });
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
        assert_eq!(hash2, hash3);
    }
}