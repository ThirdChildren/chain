// Validation module for blockchain transactions and blocks
use crate::BLOCK_REWARD;
use crate::crypto::Hash;
use crate::types::block::BlockValidationError;
use crate::types::{Block, Transaction, UTXOSet, UtxoRef};
use std::collections::HashSet;

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
    ExcessiveCoinbaseReward,
    BlockStructureError(BlockValidationError),
}

/// Validates a single transaction against the current UTXO set
pub fn validate_transaction(tx: &Transaction, utxo_set: &UTXOSet) -> Result<(), ValidationError> {
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

        let referenced_output = utxo_set
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

/// Validates a block's structure
pub fn validate_block(
    block: &Block,
    utxo_set: &UTXOSet,
    expected_prev_hash: &Hash,
    block_index: u32,
) -> Result<(), ValidationError> {
    // Validate block structure
    block
        .validate_structure(expected_prev_hash)
        .map_err(ValidationError::BlockStructureError)?;

    // Validate all transactions in the block
    validate_block_transactions(block, utxo_set, block_index)?;

    Ok(())
}

/// Validates all transactions within a block
pub fn validate_block_transactions(
    block: &Block,
    utxo_set: &UTXOSet,
    block_index: u32,
) -> Result<(), ValidationError> {
    let mut spent_in_block = HashSet::new();
    let mut total_fees = 0u64;

    for tx in block.transactions.iter() {
        validate_transaction_in_block(tx, utxo_set, block_index, &spent_in_block)?;

        if !tx.is_coinbase() {
            // Calculate fee for this transaction
            if let Some(fee) = utxo_set.calculate_transaction_fee(tx) {
                total_fees = total_fees
                    .checked_add(fee)
                    .ok_or(ValidationError::InvalidAmount)?;
            }

            for input in &tx.inputs {
                let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                spent_in_block.insert(utxo_ref);
            }
        }
    }

    // Validate coinbase reward (skip for genesis block)
    if block_index > 0 {
        if let Some(coinbase) = block.transactions.first() {
            if coinbase.is_coinbase() {
                let coinbase_amount: u64 = coinbase.outputs.iter().map(|o| o.amount).sum();

                let max_allowed = BLOCK_REWARD
                    .checked_add(total_fees)
                    .ok_or(ValidationError::InvalidAmount)?;

                if coinbase_amount > max_allowed {
                    return Err(ValidationError::ExcessiveCoinbaseReward);
                }
            }
        }
    }

    Ok(())
}

/// Validates a single transaction within a block context
pub fn validate_transaction_in_block(
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

        // Check for double-spend within the same block
        if spent_in_block.contains(&utxo_ref) {
            return Err(ValidationError::DoubleSpend);
        }

        let referenced_output = utxo_set
            .get(&utxo_ref)
            .ok_or(ValidationError::InputNotFound)?;

        // Check if UTXO was spent in this exact block
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

/// Validates genesis block structure and transactions
pub fn validate_genesis_block(block: &Block, utxo_set: &UTXOSet) -> Result<(), ValidationError> {
    block
        .validate_genesis_structure()
        .map_err(ValidationError::BlockStructureError)?;

    validate_block_transactions(block, utxo_set, 0)?;

    Ok(())
}
