use crate::crypto::backend::{CryptoKey, CryptoSignature};
use crate::crypto::{Hash, PublicKey, Signature};
use crate::types::transaction::Transaction;

pub struct Block {
    pub index: u32,
    pub hash: Hash,
    pub prev_block_hash: Hash,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Block {
    /// Block hash
    pub fn hash(&self) -> Hash {
        Hash::compute(|hasher| {
            hasher.input(self.index);
            hasher.input(self.hash);
            hasher.input(self.prev_block_hash);
            hasher.input(self.timestamp);

            // Hash delle transazioni
            hasher.input(self.transactions.len() as u32);
            for tx in &self.transactions {
                hasher.input(tx.hash());
            }

            hasher.input(&self.author.to_bytes());
            hasher.input(&self.signature.to_bytes());
        })
    }
}
