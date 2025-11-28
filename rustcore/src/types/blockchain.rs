use crate::crypto::Hash;
use crate::types::block::BlockValidationError;
use crate::types::{Block, Transaction, UTXOSet, UtxoRef};
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
    pub utxo_set: UTXOSet,
    pub blocks: Vec<Block>,
    pub block_by_hash: HashMap<Hash, usize>,
}

impl Blockchain {
    pub fn new(
        id: String,
        utxo_set: UTXOSet,
        blocks: Vec<Block>,
        block_by_hash: HashMap<Hash, usize>,
    ) -> Self {
        Blockchain {
            id,
            utxo_set,
            blocks,
            block_by_hash,
        }
    }

    /// Create new blockchain with genesis block
    pub fn new_blockchain(id: String, genesis_block: Block) -> Result<Self, ValidationError> {
        let mut blockchain = Blockchain {
            id,
            utxo_set: UTXOSet::new(),
            blocks: vec![],
            block_by_hash: HashMap::new(),
        };

        // Validate and add genesis block
        blockchain.validate_and_add_genesis(genesis_block)?;

        Ok(blockchain)
    }

    /// Validate genesis block
    fn validate_and_add_genesis(&mut self, block: Block) -> Result<(), ValidationError> {
        block
            .validate_genesis_structure()
            .map_err(ValidationError::BlockStructureError)?;

        // Validate transactions semantics (against empty UTXO set)
        self.validate_block_transactions(&block)?;

        // Apply transactions to UTXO set
        self.apply_block_to_utxo(&block);

        // Add block
        let block_hash = block.hash();
        self.block_by_hash.insert(block_hash, 0);
        self.blocks.push(block);

        Ok(())
    }

    /// Validate a single transaction against the current blockchain state
    /// Used for mempool validation (single transactions)
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ValidationError> {
        // Use the full validation with empty block context
        let empty_spent = HashSet::new();
        let empty_created = HashMap::new();

        Self::validate_transaction_with_context(tx, &self.utxo_set, &empty_spent, &empty_created)
    }

    /// Validate all transactions in a block WITHOUT modifying UTXO set.
    /// This validates transaction semantics, not structure (structure is validated by Block).
    fn validate_block_transactions(&self, block: &Block) -> Result<(), ValidationError> {
        // Track spent and created UTXOs within this block
        let mut spent_utxos = HashSet::new();
        let mut created_utxos = HashMap::new();

        // Validate each transaction in order
        for tx in block.transactions.iter() {
            Self::validate_transaction_with_context(
                tx,
                &self.utxo_set,
                &spent_utxos,
                &created_utxos,
            )?;

            // Track spent UTXOs for subsequent transactions in this block
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                    spent_utxos.insert(utxo_ref);
                }
            }

            let tx_hash = tx.hash();
            for (index, output) in tx.outputs.iter().enumerate() {
                let utxo_ref = UtxoRef::new(tx_hash, index as u32);
                created_utxos.insert(utxo_ref, (output.amount, output.recipient));
            }
        }

        Ok(())
    }

    /// Core validation logic that considers block-local UTXO changes
    /// Used for both:
    /// - Single transaction validation (mempool): with empty context
    /// - Block transaction validation: with spent/created UTXOs from earlier transactions
    fn validate_transaction_with_context(
        tx: &Transaction,
        utxo_set: &UTXOSet,
        spent_in_block: &HashSet<UtxoRef>,
        created_in_block: &HashMap<UtxoRef, (u64, [u8; 20])>,
    ) -> Result<(), ValidationError> {
        if tx.outputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        // Validate coinbase transaction
        if tx.is_coinbase() {
            for output in &tx.outputs {
                if output.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
            }
            return Ok(());
        }

        // Regular transaction must have inputs
        if tx.inputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }

        let mut total_input_amount = 0u64;
        let mut total_output_amount = 0u64;

        // Validate each input
        for (i, input) in tx.inputs.iter().enumerate() {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);

            // Check if this UTXO was already spent in this block (double spend)
            if spent_in_block.contains(&utxo_ref) {
                return Err(ValidationError::InputNotFound);
            }

            // Get the referenced output, considering block-local changes
            let (amount, recipient) = if let Some(&(amt, rcpt)) = created_in_block.get(&utxo_ref) {
                // UTXO was created earlier in this block
                (amt, rcpt)
            } else {
                // UTXO should exist in main set
                let referenced_output = utxo_set
                    .get(&utxo_ref)
                    .ok_or(ValidationError::InputNotFound)?;
                (referenced_output.amount, referenced_output.recipient)
            };

            // Check that the recipient of the previous output matches the public key
            let public_key_hash = Transaction::public_key_to_address(&input.public_key);
            if public_key_hash != recipient {
                return Err(ValidationError::InvalidSignature);
            }

            // Check the signature
            let sig_hash = tx.signature_hash(i);
            if !input.signature.verify(&sig_hash, &input.public_key) {
                return Err(ValidationError::InvalidSignature);
            }

            total_input_amount = total_input_amount
                .checked_add(amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        // Validate outputs
        for output in &tx.outputs {
            if output.amount == 0 {
                return Err(ValidationError::InvalidAmount);
            }
            total_output_amount = total_output_amount
                .checked_add(output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }

        // Check that input >= output (fees go to the miner)
        if total_input_amount < total_output_amount {
            return Err(ValidationError::InsufficientFunds);
        }

        Ok(())
    }

    /// Apply all transactions in a block to the blockchain's UTXO set
    fn apply_block_to_utxo(&mut self, block: &Block) {
        for tx in &block.transactions {
            self.utxo_set
                .apply_transaction(tx)
                .expect("CRITICAL: apply_transaction failed after validation - this is a bug!");
        }
    }

    /// Add a new block to the blockchain (idempotent operation)
    ///
    /// This operation follows the VALIDATE-THEN-APPLY pattern:
    /// 1. Validate block structure and all transactions
    /// 2. Only if ALL validation passes, apply changes to UTXO set atomically
    /// 3. Add block to chain
    ///
    /// This ensures atomicity: either the entire block is accepted or rejected.
    /// Partial application is impossible.
    pub fn add_block(&mut self, new_block: Block) -> Result<(), ValidationError> {
        // Check if block already exists (idempotent)
        let block_hash = new_block.hash();
        if self.block_by_hash.contains_key(&block_hash) {
            return Ok(()); // Already added, no error
        }

        // Determine expected previous hash
        let expected_prev_hash = if self.blocks.is_empty() {
            Hash::zero()
        } else {
            self.blocks.last().unwrap().hash()
        };

        // PHASE 1: VALIDATION (no state changes)
        // Validate block structure (hash, prev_hash, transaction structure)
        new_block
            .validate_structure(&expected_prev_hash)
            .map_err(ValidationError::BlockStructureError)?;

        // Validate transaction semantics (against UTXO set)
        // This checks all transactions without modifying UTXO set
        self.validate_block_transactions(&new_block)?;

        // PHASE 2: APPLICATION (atomic - all or nothing)
        // Apply all transactions to UTXO set
        // This cannot fail if validation passed (otherwise it's a bug)
        self.apply_block_to_utxo(&new_block);

        // Add block to blockchain
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

    /// Get current UTXO set (read-only)
    pub fn get_utxo_set(&self) -> &UTXOSet {
        &self.utxo_set
    }

    /// Check if a specific UTXO exists
    pub fn has_utxo(&self, tx_hash: Hash, output_index: u32) -> bool {
        let utxo_ref = UtxoRef::new(tx_hash, output_index);
        self.utxo_set.has(&utxo_ref)
    }

    /// Get balance for an address
    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxo_set.get_balance(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Hash, KeyPair, Signature};
    use crate::types::{Block, Transaction, TxInput, TxOutput};

    #[test]
    fn test_create_blockchain() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let blockchain = Blockchain::new_blockchain(blockchain_id.clone(), genesis_block).unwrap();

        assert!(!blockchain.is_empty());
        assert_eq!(blockchain.height(), 1);
        assert_eq!(blockchain.id, blockchain_id);
    }

    #[test]
    fn test_adding_block() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let bob_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        // Genesis coinbase gives 100 coins to Alice
        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);

        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let mut blockchain =
            Blockchain::new_blockchain(blockchain_id.clone(), genesis_block).unwrap();

        // Create Transaction: Alice sends 30 to Bob, keeps 65 as change, 5 as fee
        let genesis_coinbase_hash = coinbase_tx.hash();
        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 30,
                    recipient: bob_address,
                },
                TxOutput {
                    amount: 65,
                    recipient: alice_address,
                },
            ],
        );
        tx1.sign_input(0, &alice_keypair.private_key)
            .expect("Failed to sign transaction");

        // Create Block 1 with coinbase + transaction
        let new_block_coinbase = Transaction::new_coinbase(miner_address, 55); // 50 reward + 5 fee

        let new_block = Block::new_signed(
            1,
            blockchain.get_block_by_index(0).unwrap().hash(),
            1000100,
            vec![new_block_coinbase.clone(), tx1.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        blockchain.add_block(new_block).unwrap();
        assert_eq!(blockchain.height(), 2);

        // Verify balances
        assert_eq!(blockchain.get_balance(&alice_address), 65);
        assert_eq!(blockchain.get_balance(&bob_address), 30);
        assert_eq!(blockchain.get_balance(&miner_address), 55);
    }

    #[test]
    fn test_idempotent_add_block() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain =
            Blockchain::new_blockchain("test".to_string(), genesis_block.clone()).unwrap();

        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 50);
        let block2 = Block::new_signed(
            1,
            genesis_block.hash(),
            1000100,
            vec![coinbase_tx2],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        // Add block first time
        blockchain.add_block(block2.clone()).unwrap();
        assert_eq!(blockchain.height(), 2);

        // Add same block again - should be idempotent
        blockchain.add_block(block2).unwrap();
        assert_eq!(blockchain.height(), 2); // Height should not change
    }

    #[test]
    fn test_double_spend_prevention() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
        let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let miner_keypair = KeyPair::generate();

        // Genesis: give Alice 100 coins
        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let genesis_coinbase_hash = coinbase_tx.hash();

        // Transaction 1: Alice tries to send 60 to Bob
        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 60,
                recipient: bob_address,
            }],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        // Transaction 2: Alice tries to send same 100 coins to Charlie (double spend!)
        let mut tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 60,
                recipient: charlie_address,
            }],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();

        let coinbase_tx2 = Transaction::new_coinbase(alice_address, 50);

        // Try to create a block with both transactions (should fail)
        let bad_block = Block::new_signed(
            1,
            blockchain.blocks[0].hash(),
            1000100,
            vec![coinbase_tx2, tx1, tx2],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        // Should fail with double spend error
        let result = blockchain.add_block(bad_block);
        assert!(matches!(result, Err(ValidationError::InputNotFound)));
    }

    #[test]
    fn test_validate_transaction() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
        let miner_keypair = KeyPair::generate();

        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        // Valid transaction
        let mut valid_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: coinbase_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );
        valid_tx.sign_input(0, &alice_keypair.private_key).unwrap();

        assert!(blockchain.validate_transaction(&valid_tx).is_ok());

        // Invalid transaction - spending more than available
        let mut invalid_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: coinbase_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 200,
                recipient: bob_address,
            }],
        );
        invalid_tx
            .sign_input(0, &alice_keypair.private_key)
            .unwrap();

        assert!(matches!(
            blockchain.validate_transaction(&invalid_tx),
            Err(ValidationError::InsufficientFunds)
        ));
    }

    #[test]
    fn test_get_balance() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        assert_eq!(blockchain.get_balance(&alice_address), 100);
        assert_eq!(blockchain.get_balance(&miner_address), 0);
    }
}
