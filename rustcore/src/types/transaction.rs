use crate::crypto::{PublicKey, Signature, Hash};
use crate::util::Saveable;
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxInput {
    pub prev_tx_out_hash: Hash,
    pub signature: Signature,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxOutput {
    pub value: u64,
    pub unique_id: Uuid,
    pub pub_key: PublicKey,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Transaction { inputs, outputs }
    }

    pub fn hash(&self) -> Hash {
        Hash::hash(self)
    }
}

impl Saveable for Transaction {
    fn load <I: Read>(reader: I) -> IoResult<Self> {
        ciborium::de::from_reader(reader).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to deserialize Transaction: {:?}", e),
            )
        })
    }
    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        ciborium::ser::into_writer(self, writer).map_err(|_| IoError::new(
            IoErrorKind::InvalidData,
            "Failed to serialize Transaction",
        ))
    }
}