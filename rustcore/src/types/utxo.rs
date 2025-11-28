use crate::crypto::Hash;
use crate::types::Transaction;
use std::collections::HashMap;

/// Reference to a specific UTXO (transaction hash + output index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UtxoRef {
    pub tx_hash: Hash,
    pub output_index: u32,
}

impl UtxoRef {
    pub fn new(tx_hash: Hash, output_index: u32) -> Self {
        UtxoRef {
            tx_hash,
            output_index,
        }
    }

    pub fn from_bytes(tx_hash_bytes: [u8; 32], output_index: u32) -> Self {
        UtxoRef {
            tx_hash: Hash::from_bytes_array(tx_hash_bytes),
            output_index,
        }
    }
}

/// Unspent Transaction Output
#[derive(Debug, Clone, PartialEq)]
pub struct Utxo {
    pub amount: u64,
    pub recipient: [u8; 20],
    pub spent_in_block: Option<u32>,
}

impl Utxo {
    pub fn new(amount: u64, recipient: [u8; 20]) -> Self {
        Utxo {
            amount,
            recipient,
            spent_in_block: None,
        }
    }

    pub fn is_spent(&self) -> bool {
        self.spent_in_block.is_some()
    }

    pub fn mark_as_spent(&mut self, block_number: u32) {
        self.spent_in_block = Some(block_number);
    }
}

/// Set of Unspent Transaction Outputs
#[derive(Debug, Clone)]
pub struct UTXOSet {
    utxos: HashMap<UtxoRef, Utxo>,
}

impl UTXOSet {
    /// Create a new empty UTXO set
    pub fn new() -> Self {
        UTXOSet {
            utxos: HashMap::new(),
        }
    }

    /// Get a UTXO by reference (returns even if spent)
    pub fn get(&self, utxo_ref: &UtxoRef) -> Option<&Utxo> {
        self.utxos.get(utxo_ref)
    }

    /// Get an unspent UTXO by reference (returns None if spent)
    pub fn get_unspent(&self, utxo_ref: &UtxoRef) -> Option<&Utxo> {
        self.utxos.get(utxo_ref).filter(|utxo| !utxo.is_spent())
    }

    /// Check if a UTXO exists (even if spent)
    pub fn has(&self, utxo_ref: &UtxoRef) -> bool {
        self.utxos.contains_key(utxo_ref)
    }

    /// Check if a UTXO exists and is unspent
    pub fn has_unspent(&self, utxo_ref: &UtxoRef) -> bool {
        self.utxos
            .get(utxo_ref)
            .map(|u| !u.is_spent())
            .unwrap_or(false)
    }

    /// Add a UTXO to the set
    pub fn add(&mut self, utxo_ref: UtxoRef, utxo: Utxo) {
        self.utxos.insert(utxo_ref, utxo);
    }

    /// Mark a UTXO as spent in a specific block
    pub fn mark_spent(
        &mut self,
        utxo_ref: &UtxoRef,
        block_number: u32,
    ) -> Result<(), &'static str> {
        if let Some(utxo) = self.utxos.get_mut(utxo_ref) {
            if utxo.is_spent() {
                return Err("UTXO already spent");
            }
            utxo.mark_as_spent(block_number);
            Ok(())
        } else {
            Err("UTXO not found")
        }
    }

    /// Get the number of UTXOs in the set
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Get all UTXOs for a specific address
    pub fn get_utxos_for_address(&self, address: &[u8; 20]) -> Vec<(UtxoRef, &Utxo)> {
        self.utxos
            .iter()
            .filter(|(_, utxo)| utxo.recipient == *address)
            .map(|(utxo_ref, utxo)| (*utxo_ref, utxo))
            .collect()
    }

    /// Calculate balance for an address (only unspent UTXOs)
    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxos
            .values()
            .filter(|utxo| utxo.recipient == *address && !utxo.is_spent())
            .map(|utxo| utxo.amount)
            .sum()
    }

    /// Apply a transaction to the UTXO set
    /// Marks spent inputs and adds new outputs
    /// Returns error if an input doesn't exist or is already spent
    pub fn apply_transaction(
        &mut self,
        tx: &Transaction,
        block_number: u32,
    ) -> Result<(), &'static str> {
        let tx_hash = tx.hash();

        // For regular transactions, mark spent inputs
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                self.mark_spent(&utxo_ref, block_number)?;
            }
        }

        // Add new outputs to UTXO set
        for (index, output) in tx.outputs.iter().enumerate() {
            let utxo_ref = UtxoRef::new(tx_hash, index as u32);
            let utxo = Utxo::new(output.amount, output.recipient);
            self.add(utxo_ref, utxo);
        }

        Ok(())
    }

    /// Check if a transaction can be applied without actually applying it
    /// This is useful for validating transactions before adding them to a block
    pub fn can_apply_transaction(&self, tx: &Transaction) -> Result<(), &'static str> {
        // Coinbase transactions can always be applied
        if tx.is_coinbase() {
            return Ok(());
        }

        // Check that all inputs exist and are unspent
        for input in &tx.inputs {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
            if !self.has_unspent(&utxo_ref) {
                return Err("Input UTXO not found or already spent");
            }
        }

        Ok(())
    }

    /// Get total value of inputs for a transaction
    /// Returns None if any input is not found or is spent
    pub fn get_transaction_input_value(&self, tx: &Transaction) -> Option<u64> {
        if tx.is_coinbase() {
            return Some(0);
        }

        let mut total = 0u64;
        for input in &tx.inputs {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
            let utxo = self.get_unspent(&utxo_ref)?;
            total = total.checked_add(utxo.amount)?;
        }
        Some(total)
    }

    /// Get total value of outputs for a transaction
    pub fn get_transaction_output_value(tx: &Transaction) -> Option<u64> {
        let mut total = 0u64;
        for output in &tx.outputs {
            total = total.checked_add(output.amount)?;
        }
        Some(total)
    }

    /// Calculate fee for a transaction
    /// Returns None if transaction is invalid or coinbase
    pub fn calculate_transaction_fee(&self, tx: &Transaction) -> Option<u64> {
        if tx.is_coinbase() {
            return Some(0);
        }

        let input_value = self.get_transaction_input_value(tx)?;
        let output_value = Self::get_transaction_output_value(tx)?;
        input_value.checked_sub(output_value)
    }

    /// Iterator over all UTXOs (including spent ones)
    pub fn iter(&self) -> impl Iterator<Item = (&UtxoRef, &Utxo)> {
        self.utxos.iter()
    }

    /// Iterator over only unspent UTXOs
    pub fn iter_unspent(&self) -> impl Iterator<Item = (&UtxoRef, &Utxo)> {
        self.utxos.iter().filter(|(_, utxo)| !utxo.is_spent())
    }
}
