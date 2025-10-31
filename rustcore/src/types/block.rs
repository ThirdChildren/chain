use crate::crypto::backend::{CryptoKey, CryptoSignature};
use crate::crypto::{Hash, PublicKey, Signature};
use crate::types::transaction::{Transaction, UTXOSet};
use std::collections::HashSet;

pub struct Block {
    pub index: u32,
    pub prev_block_hash: Hash,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Block {
    pub fn hash(&self) -> Hash {
        Hash::compute(|hasher| {
            hasher.input(self.index);
            hasher.input(self.prev_block_hash);
            hasher.input(self.timestamp);

            hasher.input(self.transactions.len() as u32);
            for tx in &self.transactions {
                hasher.input(tx.hash());
            }

            hasher.input(&self.author.to_bytes());
            hasher.input(&self.signature.to_bytes());
        })
    }

    /// Verify if the previous block hash matches the expected hash of the block
    pub fn has_prev_hash(&self, expected_hash: &Hash) -> bool {
        self.prev_block_hash == *expected_hash
    }

    /// Verify if all transactions in the block are valid
    pub fn are_valid_transactions(&self, utxo_set: &UTXOSet) -> bool {
        // Verify if the block is empty
        if self.transactions.is_empty() {
            return false;
        }

        // Set for tracking transaction hashes (to detect duplicates)
        let mut tx_hashes = HashSet::new();

        // Clone Utxo set for local validation
        let mut temp_utxo = utxo_set.clone();

        for tx in &self.transactions {
            // 1. Verify transaction validity against current UTXO set
            if tx.validate(&temp_utxo).is_err() {
                return false;
            }

            // 2. Verify transaction uniqueness
            let tx_hash = tx.hash();
            if !tx_hashes.insert(tx_hash) {
                return false;
            }

            // 3. Update UTXO set with this transaction
            if tx.apply_to_utxo_set(&mut temp_utxo).is_err() {
                return false;
            }
        }

        true
    }

    /// Verify that the hash of the block is valid
    pub fn verify_hash(&self, claimed_hash: &Hash) -> bool {
        let calculated_hash = self.hash();
        calculated_hash == *claimed_hash
    }

    /// Complete validation of the block
    pub fn is_valid_block(
        &self,
        expected_hash_prev: &Hash,
        utxo_set: &UTXOSet,
        claimed_hash: &Hash,
    ) -> bool {
        if !self.has_prev_hash(expected_hash_prev) {
            return false;
        }

        if !self.are_valid_transactions(utxo_set) {
            return false;
        }

        if !self.verify_hash(claimed_hash) {
            return false;
        }

        true
    }

    /// Genesis block validation
    pub fn is_valid_genesis(&self, utxo_set: &UTXOSet, claimed_hash: &Hash) -> bool {
        if self.index != 0 {
            return false;
        }

        if self.prev_block_hash != Hash::zero() {
            return false;
        }

        if !self.verify_hash(claimed_hash) {
            return false;
        }

        if !self.are_valid_transactions(utxo_set) {
            return false;
        }

        true
    }
}
