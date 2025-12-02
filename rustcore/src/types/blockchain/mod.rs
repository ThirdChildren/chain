use crate::crypto::Hash;
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
    pub fn new(
        id: String,
        mempool: Mempool,
        utxo_set: UTXOSet,
        blocks: Vec<Block>,
        block_by_hash: HashMap<Hash, usize>,
    ) -> Self {
        Blockchain {
            id,
            mempool,
            utxo_set,
            blocks,
            block_by_hash,
        }
    }

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

    pub fn add_block(&mut self, new_block: Block) -> Result<(), ValidationError> {
        let block_hash = new_block.hash();
        if self.block_by_hash.contains_key(&block_hash) {
            return Ok(());
        }

        self.validate_block(&new_block)?;

        self.apply_block(&new_block);

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

    pub fn get_utxo_set(&self) -> &UTXOSet {
        &self.utxo_set
    }

    pub fn has_utxo(&self, tx_hash: Hash, output_index: u32) -> bool {
        let utxo_ref = UtxoRef::new(tx_hash, output_index);
        self.utxo_set.has_unspent(&utxo_ref)
    }

    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxo_set.get_balance(address)
    }
}

#[cfg(test)]
mod tests;
