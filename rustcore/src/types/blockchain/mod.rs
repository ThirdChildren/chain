use crate::BLOCK_REWARD;
use crate::crypto::{Hash, PrivateKey, PublicKey};
use crate::types::block::BlockValidationError;
use crate::types::{Block, Mempool, Transaction, UTXOSet, UtxoRef};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub enum ValidationError {
    InvalidBlock,
    InvalidGenesisBlock,
    InvalidTransaction,
    InputNotFound,
    InvalidSignature,
    InsufficientFunds,
    DoubleSpend,
    InvalidAmount,
    EmptyTransaction,
    BlockStructureError(BlockValidationError),
    MempoolError(crate::types::MempoolError),
}

#[derive(Debug, Clone)]
pub struct Blockchain {
    pub id: String,
    pub mempool: Mempool,
    pub utxo_set: UTXOSet,
    pub blocks: Vec<Block>,
    pub block_by_hash: HashMap<Hash, usize>,
}

impl Blockchain {
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

    fn validate_and_add_genesis(&mut self, block: Block) -> Result<(), ValidationError> {
        block
            .validate_genesis_structure()
            .map_err(ValidationError::BlockStructureError)?;

        Self::validate_block_transactions(&block, &self.utxo_set, 0)?;

        self.apply_block(&block);

        let block_hash = block.hash();
        self.block_by_hash.insert(block_hash, 0);
        self.blocks.push(block);

        Ok(())
    }

    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ValidationError> {
        if tx.outputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        if tx.is_coinbase() {
            for output in &tx.outputs {
                if output.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
            }
            return Ok(());
        }

        if tx.inputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        let mut total_input_amount = 0u64;
        let mut total_output_amount = 0u64;

        for (i, input) in tx.inputs.iter().enumerate() {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);

            let referenced_output = self
                .utxo_set
                .get_unspent(&utxo_ref)
                .ok_or(ValidationError::InputNotFound)?;

            let public_key_hash = Transaction::public_key_to_address(&input.public_key);
            if public_key_hash != referenced_output.recipient {
                return Err(ValidationError::InvalidSignature);
            }

            let sig_hash = tx.signature_hash(i);
            if !input.signature.verify(&sig_hash, &input.public_key) {
                return Err(ValidationError::InvalidSignature);
            }

            total_input_amount = total_input_amount
                .checked_add(referenced_output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        for output in &tx.outputs {
            if output.amount == 0 {
                return Err(ValidationError::InvalidAmount);
            }
            total_output_amount = total_output_amount
                .checked_add(output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        if total_input_amount < total_output_amount {
            return Err(ValidationError::InsufficientFunds);
        }

        Ok(())
    }

    pub fn validate_block(&self, block: &Block) -> Result<(), ValidationError> {
        let expected_prev_hash = if self.blocks.is_empty() {
            Hash::zero()
        } else {
            self.blocks.last().unwrap().hash()
        };

        block
            .validate_structure(&expected_prev_hash)
            .map_err(ValidationError::BlockStructureError)?;

        let block_index = self.blocks.len() as u32;
        Self::validate_block_transactions(block, &self.utxo_set, block_index)?;

        Ok(())
    }

    fn validate_block_transactions(
        block: &Block,
        utxo_set: &UTXOSet,
        block_index: u32,
    ) -> Result<(), ValidationError> {
        let mut spent_in_block = HashSet::new();

        for tx in block.transactions.iter() {
            Self::validate_transaction_in_block(tx, utxo_set, block_index, &spent_in_block)?;

            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                    spent_in_block.insert(utxo_ref);
                }
            }
        }
        Ok(())
    }

    fn validate_transaction_in_block(
        tx: &Transaction,
        utxo_set: &UTXOSet,
        block_index: u32,
        spent_in_block: &HashSet<UtxoRef>,
    ) -> Result<(), ValidationError> {
        if tx.outputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        if tx.is_coinbase() {
            for output in &tx.outputs {
                if output.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
            }
            return Ok(());
        }

        if tx.inputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        let mut total_input_amount = 0u64;
        let mut total_output_amount = 0u64;

        for (i, input) in tx.inputs.iter().enumerate() {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);

            if spent_in_block.contains(&utxo_ref) {
                return Err(ValidationError::DoubleSpend);
            }

            let referenced_output = utxo_set
                .get(&utxo_ref)
                .ok_or(ValidationError::InputNotFound)?;

            if let Some(spent_block) = referenced_output.spent_in_block {
                if spent_block == block_index {
                    return Err(ValidationError::DoubleSpend);
                }
                return Err(ValidationError::InputNotFound);
            }

            let public_key_hash = Transaction::public_key_to_address(&input.public_key);
            if public_key_hash != referenced_output.recipient {
                return Err(ValidationError::InvalidSignature);
            }

            let sig_hash = tx.signature_hash(i);
            if !input.signature.verify(&sig_hash, &input.public_key) {
                return Err(ValidationError::InvalidSignature);
            }

            total_input_amount = total_input_amount
                .checked_add(referenced_output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        for output in &tx.outputs {
            if output.amount == 0 {
                return Err(ValidationError::InvalidAmount);
            }
            total_output_amount = total_output_amount
                .checked_add(output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        if total_input_amount < total_output_amount {
            return Err(ValidationError::InsufficientFunds);
        }

        Ok(())
    }

    fn apply_block(&mut self, block: &Block) {
        let block_index = self.blocks.len() as u32;

        for tx in &block.transactions {
            let tx_hash = tx.hash();

            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                    self.utxo_set
                        .mark_spent(&utxo_ref, block_index)
                        .expect("UTXO must exist after validation");
                }
            }

            for (index, output) in tx.outputs.iter().enumerate() {
                let utxo_ref = UtxoRef::new(tx_hash, index as u32);
                let utxo = crate::types::utxo::Utxo::new(output.amount, output.recipient);
                self.utxo_set.add(utxo_ref, utxo);
            }
        }
    }

    /// Create a new block from transactions in the mempool
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

    pub fn add_block(&mut self, new_block: Block) -> Result<(), ValidationError> {
        let block_hash = new_block.hash();
        if self.block_by_hash.contains_key(&block_hash) {
            return Ok(());
        }

        self.validate_block(&new_block)?;

        self.apply_block(&new_block);

        // Remove transactions that are now in the block
        for tx in &new_block.transactions {
            if !tx.is_coinbase() {
                self.mempool.remove_entry(tx);
            }
        }

        // Collect transactions that are no longer valid with the new UTXO set
        let invalid_txs: Vec<_> = self
            .mempool
            .entries
            .iter()
            .filter(|entry| self.validate_transaction(&entry.transaction).is_err())
            .map(|entry| entry.transaction.clone())
            .collect();

        // Remove invalid transactions
        for tx in invalid_txs {
            self.mempool.remove_entry(&tx);
        }

        self.block_by_hash.insert(block_hash, self.blocks.len());
        self.blocks.push(new_block);

        Ok(())
    }

    pub fn get_block_by_hash(&self, hash: Hash) -> Option<&Block> {
        self.block_by_hash
            .get(&hash)
            .map(|&index| &self.blocks[index])
    }

    pub fn get_block_by_index(&self, index: usize) -> Option<&Block> {
        self.blocks.get(index)
    }

    pub fn height(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxo_set.get_balance(address)
    }

    /// Submit a transaction to the mempool
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<(), ValidationError> {
        self.validate_transaction(&tx)?;

        // Calculate the fee using the UTXO set
        let fee = self
            .utxo_set
            .calculate_transaction_fee(&tx)
            .ok_or(ValidationError::InvalidTransaction)?;

        // Add to mempool with the calculated fee
        self.mempool
            .add_entry(tx, fee)
            .map_err(ValidationError::MempoolError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
