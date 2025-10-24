use rustcore::crypto::{PrivateKey, CryptoKey};
use std::env;
use std::fs;

fn main() {
    let name = env::args().nth(1).expect("Please provide a name");
    let private_key = PrivateKey::new_key();
    let public_key = private_key.public_key();
    let public_key_file = name.clone() + ".pub.bytes";
    let private_key_file = name + ".priv.bytes";
    
    fs::write(&private_key_file, private_key.to_bytes()).unwrap();
    fs::write(&public_key_file, public_key.to_bytes()).unwrap();
    
    println!("Generated keys: {} and {}", private_key_file, public_key_file);
}