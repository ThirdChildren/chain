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

    println!("Key Information for: {}", name);
    println!("{}", "=".repeat(70));

    // Read and display private key
    match fs::read(&private_key_file) {
        Ok(private_bytes) => {
            println!("\nPrivate Key:");
            println!("File: {}", private_key_file);
            println!("Size: {} bytes", private_bytes.len());
            
            // Detect key type based on size
            #[cfg(feature = "mldsa")]
            let is_mldsa = private_bytes.len() > 1000;
            
            #[cfg(not(feature = "mldsa"))]
            let is_mldsa = false;
            
            if is_mldsa {
                println!("Type: ML-DSA (Post-Quantum)");
                println!("\nPrivate Key Structure:");
                
                // Parse ML-DSA structure
                if private_bytes.len() >= 4 {
                    let sk_len = u32::from_le_bytes([
                        private_bytes[0], 
                        private_bytes[1], 
                        private_bytes[2], 
                        private_bytes[3]
                    ]) as usize;
                    
                    println!("  - Header: 4 bytes");
                    println!("  - Secret key: {} bytes", sk_len);
                    println!("  - Embedded public key: {} bytes", private_bytes.len() - 4 - sk_len);
                    
                    if private_bytes.len() >= 4 + sk_len {
                        let secret_key_only = &private_bytes[4..4+sk_len];
                        
                        println!("\nSecret Key Only ({} bytes):", secret_key_only.len());
                        println!("{}", hex::encode(secret_key_only));
                    }
                }
                
                println!("\nFull Private Key (with embedded public) ({} bytes):", private_bytes.len());
                println!("{}", hex::encode(&private_bytes));
            } else {
                println!("Type: secp256k1 (Classical ECDSA)");
                println!("Hex: {}", hex::encode(&private_bytes));
            }
            
            // Try to reconstruct the private key to verify it's valid
            match PrivateKey::from_bytes(&private_bytes) {
                Ok(private_key) => {
                    println!("\nPrivate key is valid");
                    
                    // Generate the corresponding public key
                    let derived_public_key = private_key.public_key();
                    let derived_public_bytes = derived_public_key.to_bytes();
                    
                    println!("\nDerived Public Key (from private key):");
                    println!("Size: {} bytes", derived_public_bytes.len());
                    println!("Hex: {}", hex::encode(&derived_public_bytes));
                },
                Err(e) => {
                    println!("\nError reconstructing private key: {}", e);
                }
            }
        },
        Err(e) => {
            println!("\nError reading private key file {}: {}", private_key_file, e);
        }
    }

    // Read and display public key
    match fs::read(&public_key_file) {
        Ok(public_bytes) => {
            println!("\nStored Public Key:");
            println!("File: {}", public_key_file);
            println!("Size: {} bytes", public_bytes.len());
            println!("Hex: {}", hex::encode(&public_bytes));
            
            // Try to reconstruct the public key to verify it's valid
            match PublicKey::from_bytes(&public_bytes) {
                Ok(_public_key) => {
                    println!("Public key is valid");
                },
                Err(e) => {
                    println!("Error reconstructing public key: {}", e);
                }
            }
        },
        Err(e) => {
            println!("\nError reading public key file {}: {}", public_key_file, e);
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("Key Format Information:");
    #[cfg(feature = "mldsa")]
    println!("- Backend: ML-DSA (CRYSTALS-Dilithium5)");
    #[cfg(feature = "mldsa")]
    println!("- Secret key: 4896 bytes (pure Dilithium5)");
    #[cfg(feature = "mldsa")]
    println!("- Private key file: 7492 bytes (secret + embedded public)");
    #[cfg(feature = "mldsa")]
    println!("- Public key: 2592 bytes");
    #[cfg(feature = "mldsa")]
    println!("- Signature: 4595 bytes");
    #[cfg(feature = "mldsa")]
    println!("- Security: Post-quantum (NIST Level 5)");
    
    #[cfg(feature = "secp256k1")]
    println!("- Backend: secp256k1 (Classical ECDSA)");
    #[cfg(feature = "secp256k1")]
    println!("- Private key: 32 bytes");
    #[cfg(feature = "secp256k1")]
    println!("- Public key: 65 bytes (uncompressed)");
    #[cfg(feature = "secp256k1")]
    println!("- Signature: ~72 bytes");
    
    println!("- Keys are stored as raw bytes (not PEM or other formats)");
}
