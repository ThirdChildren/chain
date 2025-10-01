use super::{Transaction, TxOutput};
use crate::U256;
//use crate::error::{BtcError, Result};
use crate::crypto::Hash;
use crate::util::MerkleRoot;
use crate::util::Saveable;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};

#[derive(Serialize, Deserialize, Clone, Debug)]
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

    pub fn hash(&self) -> Hash {
        Hash::hash(&self)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new (header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block { header, transactions }
    }
    pub fn hash(&self) -> Hash {
        Hash::hash(&self)
    }
}


impl Saveable for Block {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        ciborium::de::from_reader(reader)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to deserialize Block"))
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        ciborium::ser::into_writer(self, writer)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to serialize Block"))
    }
}