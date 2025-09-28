use rustcore::crypto::PrivateKey;
use rustcore::types::{Transaction, TxOutput};
use rustcore::util::Saveable;
use std::env;
use std::process::exit;
use uuid::Uuid;
fn main() {
    let path = if let Some(arg) = env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: tx_gen <tx_file>");
        exit(1);
    };
    let private_key = PrivateKey::new_key();
    let transaction = Transaction::new(
        vec![],
        vec![TxOutput {
            unique_id: Uuid::new_v4(),
            value: rustcore::INITIAL_REWARD * 10u64.pow(8),
            pub_key: private_key.public_key(),
        }],
    );
    transaction
        .save_to_file(path)
        .expect("Failed to save transaction");
}