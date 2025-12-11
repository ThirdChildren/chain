// Blockchain module - Main state management
mod validator;
pub use validator::ValidationError;

use crate::BLOCK_REWARD;
use crate::crypto::{Hash, PrivateKey, PublicKey};
use crate::types::{Block, Mempool, Transaction, UTXOSet, UtxoRef};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Blockchain {
    pub id: String,
    pub mempool: Mempool,
    pub utxo_set: UTXOSet,
    pub blocks: Vec<Block>,
    pub block_by_hash: HashMap<Hash, usize>,
}

impl Blockchain {
    /// Creates a new blockchain with a genesis block
    pub fn new_blockchain(id: String, genesis_block: Block) -> Result<Self, ValidationError> {
        let mut blockchain = Blockchain {
            id,
            mempool: Mempool::new(),
            utxo_set: UTXOSet::new(),
            blocks: vec![],
            block_by_hash: HashMap::new(),
        };

        blockchain.validate_and_add_genesis(genesis_block)?;

        Ok(blockchain)
    }

    /// Validates and adds the genesis block
    fn validate_and_add_genesis(&mut self, block: Block) -> Result<(), ValidationError> {
        // Validate genesis block
        validator::validate_genesis_block(&block, &self.utxo_set)?;

        // Apply the genesis block
        self.apply_block(&block);

        // Add to chain
        let block_hash = block.hash();
        self.block_by_hash.insert(block_hash, 0);
        self.blocks.push(block);

        Ok(())
    }

    /// Validates a transaction against current blockchain state
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ValidationError> {
        validator::validate_transaction(tx, &self.utxo_set)
    }

    /// Validates a block against current blockchain state
    pub fn validate_block(&self, block: &Block) -> Result<(), ValidationError> {
        let expected_prev_hash = if self.blocks.is_empty() {
            Hash::zero()
        } else {
            self.blocks.last().unwrap().hash()
        };

        let block_index = self.blocks.len() as u32;

        validator::validate_block(block, &self.utxo_set, &expected_prev_hash, block_index)
    }

    /// Applies a block to the blockchain state
    fn apply_block(&mut self, block: &Block) {
        let block_index = self.blocks.len() as u32;

        for tx in &block.transactions {
            let tx_hash = tx.hash();

            // Mark inputs as spent (for non-coinbase transactions)
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                    self.utxo_set
                        .mark_spent(&utxo_ref, block_index)
                        .expect("UTXO must exist after validation");
                }
            }

            // Add new outputs to UTXO set (for all transactions)
            for (index, output) in tx.outputs.iter().enumerate() {
                let utxo_ref = UtxoRef::new(tx_hash, index as u32);
                let utxo = crate::types::utxo::Utxo::new(output.amount, output.recipient);
                self.utxo_set.add(utxo_ref, utxo);
            }
        }
    }

    /// Creates a new block from transactions in the mempool
    pub fn create_block(
        &self,
        miner_public_key: PublicKey,
        miner_private_key: &PrivateKey,
        max_transactions: usize,
    ) -> Block {
        // Get transactions from mempool ordered by fee (highest first)
        let candidates = self.mempool.get_transactions_by_fee();

        // Select valid transactions without conflicts
        let mut selected_transactions = Vec::new();
        let mut used_utxos = HashSet::new();

        for tx in candidates {
            if selected_transactions.len() >= max_transactions {
                break;
            }

            // Skip if transaction is no longer valid
            if self.validate_transaction(&tx).is_err() {
                continue;
            }

            // Check for conflicts with already selected transactions
            let tx_inputs: Vec<UtxoRef> = tx
                .inputs
                .iter()
                .map(|input| UtxoRef::from_bytes(input.previous_tx_id, input.output_index))
                .collect();

            let has_conflict = tx_inputs
                .iter()
                .any(|utxo_ref| used_utxos.contains(utxo_ref));

            if !has_conflict {
                // Mark UTXOs as used
                for utxo_ref in tx_inputs {
                    used_utxos.insert(utxo_ref);
                }
                selected_transactions.push(tx);
            }
        }

        // Calculate total fees from selected transactions
        let total_fees: u64 = selected_transactions
            .iter()
            .filter_map(|tx| self.utxo_set.calculate_transaction_fee(tx))
            .sum();

        // Create coinbase transaction (reward + fees)
        let miner_address = Transaction::public_key_to_address(&miner_public_key);
        let coinbase = Transaction::new_coinbase(miner_address, BLOCK_REWARD + total_fees);

        // Assemble all transactions (coinbase must be first)
        let mut all_transactions = vec![coinbase];
        all_transactions.extend(selected_transactions);

        // Determine block parameters
        let block_index = self.blocks.len() as u32;
        let prev_hash = if self.is_empty() {
            Hash::zero()
        } else {
            self.blocks.last().unwrap().hash()
        };

        // Create and sign the block
        Block::new_signed(
            block_index,
            prev_hash,
            Block::get_current_timestamp(),
            all_transactions,
            miner_public_key,
            miner_private_key,
        )
    }

    /// Adds a validated block to the blockchain
    pub fn add_block(&mut self, new_block: Block) -> Result<(), ValidationError> {
        let block_hash = new_block.hash();

        // Check if block already exists (idempotent)
        if self.block_by_hash.contains_key(&block_hash) {
            return Ok(());
        }

        // Validate the block
        self.validate_block(&new_block)?;

        // Apply the block (update UTXO set)
        self.apply_block(&new_block);

        // Remove transactions that are now in the block from mempool
        for tx in &new_block.transactions {
            if !tx.is_coinbase() {
                self.mempool.remove_entry(tx);
            }
        }

        // Clean up mempool: remove transactions that became invalid
        // (e.g., their inputs were spent by transactions in the new block)
        let invalid_txs: Vec<_> = self
            .mempool
            .entries
            .iter()
            .filter(|entry| self.validate_transaction(&entry.transaction).is_err())
            .map(|entry| entry.transaction.clone())
            .collect();

        for tx in invalid_txs {
            self.mempool.remove_entry(&tx);
        }

        // Add block to the chain
        self.block_by_hash.insert(block_hash, self.blocks.len());
        self.blocks.push(new_block);

        Ok(())
    }

    /// Submits a transaction to the mempool
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<(), ValidationError> {
        // Validate the transaction
        self.validate_transaction(&tx)?;

        // Calculate the fee
        let fee = self
            .utxo_set
            .calculate_transaction_fee(&tx)
            .ok_or(ValidationError::InvalidTransaction)?;

        // Add to mempool
        self.mempool.add_entry(tx, fee).map_err(|e| match e {
            crate::types::MempoolError::FeeTooLow { .. } => ValidationError::InvalidTransaction,
            crate::types::MempoolError::CoinbaseNotAllowed => ValidationError::InvalidTransaction,
            crate::types::MempoolError::InvalidTransaction(_) => {
                ValidationError::InvalidTransaction
            }
            crate::types::MempoolError::InvalidFee => ValidationError::InvalidTransaction,
        })?;

        Ok(())
    }

    // ========== Query Methods ==========

    /// Gets a block by its hash
    pub fn get_block_by_hash(&self, hash: Hash) -> Option<&Block> {
        self.block_by_hash
            .get(&hash)
            .map(|&index| &self.blocks[index])
    }

    /// Gets a block by its index (height)
    pub fn get_block_by_index(&self, index: usize) -> Option<&Block> {
        self.blocks.get(index)
    }

    /// Returns the height of the blockchain (number of blocks)
    pub fn height(&self) -> usize {
        self.blocks.len()
    }

    /// Checks if the blockchain is empty (no blocks)
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Gets the balance of an address
    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxo_set.get_balance(address)
    }
}

#[cfg(test)]
mod tests;
