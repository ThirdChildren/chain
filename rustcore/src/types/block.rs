use super::Transaction;
use crate::U256;
//use crate::error::{BtcError, Result};
use crate::crypto::Hash;
use crate::util::MerkleRoot;
use crate::util::Saveable;
use chrono::{DateTime, Utc};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};

#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub merkle_root: MerkleRoot,
    pub prev_block_hash: Hash,
    pub timestamp: DateTime<Utc>,
    pub nonce: u64,
    pub target: U256,
}

impl BlockHeader {
    pub fn new(
        merkle_root: MerkleRoot,
        prev_block_hash: Hash,
        timestamp: DateTime<Utc>,
        nonce: u64,
        target: U256,
    ) -> Self {
        BlockHeader {
            merkle_root,
            prev_block_hash,
            timestamp,
            nonce,
            target,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{:?}", self).into_bytes()
    }
    
    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new (header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block { header, transactions }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{:?}", self).into_bytes()
    }
    
    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}


impl Saveable for Block {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
    
    fn from_bytes(_bytes: &[u8]) -> IoResult<Self> {
        // Simple deserialization - in a real implementation you'd use a proper format
        Err(IoError::new(
            IoErrorKind::InvalidData,
            "Block deserialization not implemented in simplified version",
        ))
    }
}