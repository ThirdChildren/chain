/// Trait for hash backend implementations
pub trait CryptoHash: Clone + std::fmt::Debug {
    /// Get the hash output size in bytes
    fn output_size() -> usize;

    /// Convert hash to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create hash from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

/// Trait for hasher implementations
pub trait CryptoHasher: Default {
    type Output: CryptoHash;

    /// Create a new hasher instance
    fn new() -> Self;

    /// Update hasher with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and produce hash
    fn finalize(self) -> Self::Output;

    /// Reset hasher state
    fn reset(&mut self);
}

/// Trait for hash backend that ties together hash and hasher
pub trait HashBackend {
    type Hash: CryptoHash;
    type Hasher: CryptoHasher<Output = Self::Hash>;

    /// Create a new hasher
    fn new_hasher() -> Self::Hasher;

    /// Hash data in one step
    fn hash_data(data: &[u8]) -> Self::Hash {
        let mut hasher = Self::new_hasher();
        hasher.update(data);
        hasher.finalize()
    }
}
