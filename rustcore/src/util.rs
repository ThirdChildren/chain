use crate::crypto::Hash;
use std::io::Result as IoResult;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleRoot(Hash);

impl MerkleRoot {
    pub fn new(hash: Hash) -> Self {
        MerkleRoot(hash)
    }
    
    pub fn hash(&self) -> Hash {
        self.0
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.as_bytes()
    }
}

// Simplified trait without serialization dependencies
pub trait Saveable
where
    Self: Sized,
{
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> IoResult<Self>;
    
    fn save_to_file<P: AsRef<Path>>(&self, path: P) -> IoResult<()> {
        std::fs::write(path, self.to_bytes())
    }
    
    fn load_from_file<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }
}