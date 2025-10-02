// This example shows how easy it is to add a new crypto backend
// Note: This is a simplified mock implementation for demonstration purposes

use rustcore::crypto::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair, Hash};

// Mock Ed25519 implementation (simplified for demo)
pub struct Ed25519Backend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct Ed25519PrivateKey(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct Ed25519Signature(pub Vec<u8>);

impl Ed25519Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes.to_vec())
    }
    
    pub fn as_array(&self) -> Result<[u8; 64], Box<dyn std::error::Error>> {
        if self.0.len() != 64 {
            return Err("Invalid signature length".into());
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&self.0);
        Ok(array)
    }
}

impl CryptoKey for Ed25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != 32 {
            return Err("Invalid public key length".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Ed25519PublicKey(key))
    }
}

impl CryptoKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != 32 {
            return Err("Invalid private key length".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Ed25519PrivateKey(key))
    }
}

impl CryptoSignature for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != 64 {
            return Err("Invalid signature length".into());
        }
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}

impl CryptoBackend for Ed25519Backend {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;
    
    fn generate_keypair() -> KeyPair<Self::PublicKey, Self::PrivateKey> {
        // Mock implementation - in reality this would use proper Ed25519 key generation
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        
        let mut private_bytes = [0u8; 32];
        let mut public_bytes = [0u8; 32];
        
        rng.fill_bytes(&mut private_bytes);
        rng.fill_bytes(&mut public_bytes); // Mock - real implementation derives from private
        
        KeyPair::new(
            Ed25519PublicKey(public_bytes),
            Ed25519PrivateKey(private_bytes),
        )
    }
    
    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey {
        // Mock implementation - real Ed25519 would derive public from private
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(&private_key.0); // Simplified mock
        Ed25519PublicKey(public_bytes)
    }
    
    fn sign(data: &Hash, _private_key: &Self::PrivateKey) -> Self::Signature {
        // Mock implementation - real Ed25519 would perform actual signing
        let data_bytes = data.as_bytes();
        let mut sig_bytes = vec![0u8; 64];
        sig_bytes[..32].copy_from_slice(&data_bytes);
        // Fill the rest with mock data
        for i in 32..64 {
            sig_bytes[i] = (i as u8).wrapping_mul(2);
        }
        Ed25519Signature(sig_bytes)
    }
    
    fn verify(signature: &Self::Signature, data: &Hash, _public_key: &Self::PublicKey) -> bool {
        // Mock verification - real implementation would verify properly
        let data_bytes = data.as_bytes();
        signature.0.len() >= 32 && signature.0[..32] == data_bytes
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 Ed25519 Mock Backend Demo");
    
    // Generate Ed25519 key pair
    println!("\n📝 Generating Ed25519 key pair...");
    let keypair = Ed25519Backend::generate_keypair();
    println!("✅ Ed25519 key pair generated!");
    
    // Test data
    let test_data = "Test data for Ed25519";
    let data_hash = Hash::hash(test_data.as_bytes());
    println!("\n📊 Test data: {}", test_data);
    
    // Sign with Ed25519
    println!("\n✍️  Signing with Ed25519...");
    let signature = Ed25519Backend::sign(&data_hash, &keypair.private_key);
    println!("✅ Ed25519 signature created!");
    
    // Verify signature
    println!("\n🔍 Verifying Ed25519 signature...");
    let is_valid = Ed25519Backend::verify(&signature, &data_hash, &keypair.public_key);
    println!("✅ Ed25519 signature valid: {}", is_valid);
    
    // Show key sizes
    println!("\n📏 Ed25519 key sizes:");
    println!("Public key: {} bytes", keypair.public_key.to_bytes().len());
    println!("Private key: {} bytes", keypair.private_key.to_bytes().len());
    println!("Signature: {} bytes", signature.to_bytes().len());
    
    println!("\n💡 This demonstrates how easy it is to add new crypto backends!");
    println!("   Real Ed25519 implementation would use proper cryptographic libraries.");
    
    Ok(())
}