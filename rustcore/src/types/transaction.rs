use crate::crypto::{PublicKey, Signature, Hash};
use crate::util::Saveable;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub prev_tx_out_hash: Hash,
    pub signature: Signature,
}
#[derive(Clone, Debug)]
pub struct TxOutput {
    pub value: u64,
    pub unique_id: Uuid,
    pub pub_key: PublicKey,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Transaction { inputs, outputs }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{:?}", self).into_bytes()
    }
    
    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}

impl Saveable for Transaction {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
    
    fn from_bytes(_bytes: &[u8]) -> IoResult<Self> {
        // Simple deserialization - in a real implementation you'd use a proper format
        Err(IoError::new(
            IoErrorKind::InvalidData,
            "Transaction deserialization not implemented in simplified version",
        ))
    }
}