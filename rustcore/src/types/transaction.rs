use crate::crypto::{PublicKey, Signature, Hash};

#[derive(Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub previous_tx_id: [u8; 32],
    pub output_index: u32,
    pub signature: Signature,
    pub public_key: PublicKey,
}
#[derive(Clone, Debug)]
pub struct TxOutput {
    pub amount: u64,
    pub recipient: [u8; 20],
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

