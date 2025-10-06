use rustcore::crypto::{PrivateKey, PublicKey, CryptoKey};
use std::env;
use std::fs;
use std::process::exit;

fn main() {
    let name = if let Some(arg) = env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: key_print <name>");
        eprintln!("This will read <name>.priv.bytes and <name>.pub.bytes");
        exit(1);
    };

    let private_key_file = format!("{}.priv.bytes", name);
    let public_key_file = format!("{}.pub.bytes", name);

    println!("🔑 Key Information for: {}", name);
    println!("{}", "=".repeat(50));

    // Read and display private key
    match fs::read(&private_key_file) {
        Ok(private_bytes) => {
            println!("\n🔒 Private Key:");
            println!("File: {}", private_key_file);
            println!("Size: {} bytes", private_bytes.len());
            println!("Hex: {}", hex::encode(&private_bytes));
            
            // Try to reconstruct the private key to verify it's valid
            match PrivateKey::from_bytes(&private_bytes) {
                Ok(private_key) => {
                    println!("✅ Private key is valid");
                    
                    // Generate the corresponding public key
                    let derived_public_key = private_key.public_key();
                    let derived_public_bytes = derived_public_key.to_bytes();
                    
                    println!("\n🔓 Derived Public Key (from private key):");
                    println!("Size: {} bytes", derived_public_bytes.len());
                    println!("Hex: {}", hex::encode(&derived_public_bytes));
                },
                Err(e) => {
                    println!("❌ Error reconstructing private key: {}", e);
                }
            }
        },
        Err(e) => {
            println!("❌ Error reading private key file {}: {}", private_key_file, e);
        }
    }

    // Read and display public key
    match fs::read(&public_key_file) {
        Ok(public_bytes) => {
            println!("\n🔓 Stored Public Key:");
            println!("File: {}", public_key_file);
            println!("Size: {} bytes", public_bytes.len());
            println!("Hex: {}", hex::encode(&public_bytes));
            
            // Try to reconstruct the public key to verify it's valid
            match PublicKey::from_bytes(&public_bytes) {
                Ok(_public_key) => {
                    println!("✅ Public key is valid");
                },
                Err(e) => {
                    println!("❌ Error reconstructing public key: {}", e);
                }
            }
        },
        Err(e) => {
            println!("❌ Error reading public key file {}: {}", public_key_file, e);
        }
    }

    println!("\n📝 Key Format Information:");
    println!("- Keys are stored as raw bytes (not PEM or other formats)");
    println!("- Private key: 32 bytes (secp256k1 scalar)");
    println!("- Public key: 65 bytes (uncompressed secp256k1 point)");
    println!("- Use hex representation for manual verification");
}