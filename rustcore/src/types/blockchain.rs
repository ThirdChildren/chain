use crate::crypto::Hash;
use crate::types::{Block, UTXOSet};
use std::collections::HashMap;

#[derive(Debug)]
pub enum ValidationError {
    InvalidBlock,
    InvalidGenesisBlock,
    InvalidTransaction,
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

    // Create new blockchain with genesis block
    pub fn new_blockchain(id: String, genesis_block: Block) -> Result<Self, ValidationError> {
        if !genesis_block.is_valid_genesis(&UTXOSet::new(), &genesis_block.hash()) {
            return Err(ValidationError::InvalidGenesisBlock);
        }

        let mut utxo_set = UTXOSet::new();
        for tx in &genesis_block.transactions {
            tx.apply_to_utxo_set(&mut utxo_set)
                .map_err(|_| ValidationError::InvalidTransaction)?;
        }

        let mut block_by_hash = HashMap::new();
        block_by_hash.insert(genesis_block.hash(), 0);

        Ok(Blockchain {
            id,
            utxo_set,
            blocks: vec![genesis_block],
            block_by_hash,
        })
    }

    pub fn add_block(&mut self, new_block: Block) -> Result<(), ValidationError> {
        let prev_hash = if self.blocks.is_empty() {
            Hash::zero()
        } else {
            self.blocks.last().unwrap().hash()
        };

        if !new_block.is_valid_block(&prev_hash, &self.utxo_set, &new_block.hash()) {
            return Err(ValidationError::InvalidBlock);
        }

        let mut new_utxo_set = self.utxo_set.clone();
        for tx in &new_block.transactions {
            tx.apply_to_utxo_set(&mut new_utxo_set)
                .map_err(|_| ValidationError::InvalidTransaction)?;
        }

        self.utxo_set = new_utxo_set;
        let block_hash = new_block.hash();
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

        // Create a coinbase transaction for the genesis block
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        // Create genesis block
        let genesis_block = Block::new(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            miner_keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let new_blockchain =
            Blockchain::new_blockchain(blockchain_id.clone(), genesis_block).unwrap();
        assert!(!new_blockchain.is_empty());
        assert_eq!(new_blockchain.height(), 1);
        assert_eq!(new_blockchain.id, blockchain_id);
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

        let genesis_block = Block::new(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let mut new_blockchain =
            Blockchain::new_blockchain(blockchain_id.clone(), genesis_block.clone()).unwrap();

        // Create Transaction 1: Alice sends 30 to Bob, keeps 65 as change, 5 as fee
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

        let new_block = Block::new(
            1,
            genesis_block.hash(),
            1000100,
            vec![new_block_coinbase.clone(), tx1.clone()],
            miner_keypair.public_key.clone(),
            Signature::sign_output(&Hash::hash(b"new_block_data"), &miner_keypair.private_key),
        );

        new_blockchain.add_block(new_block).unwrap();
        assert_eq!(new_blockchain.height(), 2);
    }
}
