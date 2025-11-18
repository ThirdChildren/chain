use super::backend::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair};
use crate::crypto::hash::Hash;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, SignedMessage};

/// ML-DSA (CRYSTALS-Dilithium) implementation
/// Using Dilithium5 for maximum security (NIST Level 5)
pub struct MLDSABackend;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct MLDSAPublicKey(pub Vec<u8>);

/// ML-DSA Private Key
/// Note: Internally stores both secret and public keys together,
/// as ML-DSA doesn't support efficient public key derivation.
/// The serialization format includes both keys for full compatibility.
#[derive(Clone, Debug)]
pub struct MLDSAPrivateKey {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MLDSASignature(pub Vec<u8>);

impl CryptoKey for MLDSAPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        // Verify the length matches Dilithium5 public key size
        if bytes.len() != dilithium5::public_key_bytes() {
            return Err(format!(
                "Invalid ML-DSA public key length: expected {}, got {}",
                dilithium5::public_key_bytes(),
                bytes.len()
            )
            .into());
        }
        Ok(MLDSAPublicKey(bytes.to_vec()))
    }
}

impl CryptoKey for MLDSAPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Serialize both keys together
        // Format: [secret_key_len (4 bytes)][secret_key][public_key]
        let sk_len = self.secret_key.len() as u32;
        let mut bytes = Vec::with_capacity(4 + self.secret_key.len() + self.public_key.len());
        bytes.extend_from_slice(&sk_len.to_le_bytes());
        bytes.extend_from_slice(&self.secret_key);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() < 4 {
            return Err("Invalid ML-DSA private key: too short".into());
        }

        // Read the secret key length
        let sk_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + sk_len {
            return Err("Invalid ML-DSA private key: insufficient data".into());
        }

        let secret_key = bytes[4..4 + sk_len].to_vec();
        let public_key = bytes[4 + sk_len..].to_vec();

        // Verify lengths
        if secret_key.len() != dilithium5::secret_key_bytes() {
            return Err(format!(
                "Invalid ML-DSA secret key length: expected {}, got {}",
                dilithium5::secret_key_bytes(),
                secret_key.len()
            )
            .into());
        }

        if public_key.len() != dilithium5::public_key_bytes() {
            return Err(format!(
                "Invalid ML-DSA public key length: expected {}, got {}",
                dilithium5::public_key_bytes(),
                public_key.len()
            )
            .into());
        }

        Ok(MLDSAPrivateKey {
            secret_key,
            public_key,
        })
    }

    /// Extract only the secret key bytes
    fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// Extract the embedded public key bytes
    fn embedded_public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

impl CryptoSignature for MLDSASignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        // Verify the length matches Dilithium5 signature size
        if bytes.len() != dilithium5::signature_bytes() {
            return Err(format!(
                "Invalid ML-DSA signature length: expected {}, got {}",
                dilithium5::signature_bytes(),
                bytes.len()
            )
            .into());
        }
        Ok(MLDSASignature(bytes.to_vec()))
    }
}

impl CryptoBackend for MLDSABackend {
    type PublicKey = MLDSAPublicKey;
    type PrivateKey = MLDSAPrivateKey;
    type Signature = MLDSASignature;

    fn generate_keypair() -> KeyPair<Self::PublicKey, Self::PrivateKey> {
        let (pk, sk) = dilithium5::keypair();

        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();

        KeyPair::new(
            MLDSAPublicKey(pk_bytes.clone()),
            MLDSAPrivateKey {
                secret_key: sk_bytes,
                public_key: pk_bytes,
            },
        )
    }

    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey {
        // Extract the stored public key from the private key
        MLDSAPublicKey(private_key.public_key.clone())
    }

    fn sign(data: &Hash, private_key: &Self::PrivateKey) -> Self::Signature {
        let sk =
            dilithium5::SecretKey::from_bytes(&private_key.secret_key).expect("Invalid secret key");

        // Sign the hash bytes
        let signed_msg = dilithium5::sign(&data.as_bytes(), &sk);

        // Extract just the signature (without the message)
        // The signed message format includes both signature and message
        let sig_bytes = signed_msg.as_bytes();

        // In Dilithium, the signature is at the beginning of the signed message
        let sig_len = dilithium5::signature_bytes();
        let signature = sig_bytes[..sig_len].to_vec();

        MLDSASignature(signature)
    }

    fn verify(signature: &Self::Signature, data: &Hash, public_key: &Self::PublicKey) -> bool {
        let pk = match dilithium5::PublicKey::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Reconstruct the signed message (signature + message)
        let mut signed_msg_bytes = signature.0.clone();
        signed_msg_bytes.extend_from_slice(&data.as_bytes());

        // Create a SignedMessage from bytes
        let signed_msg = match dilithium5::SignedMessage::from_bytes(&signed_msg_bytes) {
            Ok(sm) => sm,
            Err(_) => return false,
        };

        // Verify the signature
        match dilithium5::open(&signed_msg, &pk) {
            Ok(recovered_msg) => {
                // Check that the recovered message matches the original
                recovered_msg == data.as_bytes()
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_sign_verify() {
        // Generate keypair
        let keypair = MLDSABackend::generate_keypair();

        // Create a test hash
        let data = Hash::hash(b"test message");

        // Sign
        let signature = MLDSABackend::sign(&data, &keypair.private_key);

        // Verify
        assert!(MLDSABackend::verify(&signature, &data, &keypair.public_key));

        // Verify with wrong data should fail
        let wrong_data = Hash::hash(b"wrong message");
        assert!(!MLDSABackend::verify(
            &signature,
            &wrong_data,
            &keypair.public_key
        ));
}

    #[test]
    fn test_mldsa_key_serialization() {
        let keypair = MLDSABackend::generate_keypair();

        // Test public key serialization
        let pk_bytes = keypair.public_key.to_bytes();
        let pk_restored = MLDSAPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(keypair.public_key, pk_restored);

        // Test private key serialization
        let sk_bytes = keypair.private_key.to_bytes();
        let sk_restored = MLDSAPrivateKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk_bytes, sk_restored.to_bytes());
    }

    #[test]
    fn test_mldsa_signature_serialization() {
        let keypair = MLDSABackend::generate_keypair();
        let data = Hash::hash(b"test");
        let signature = MLDSABackend::sign(&data, &keypair.private_key);

        // Serialize and deserialize
        let sig_bytes = signature.to_bytes();
        let sig_restored = MLDSASignature::from_bytes(&sig_bytes).unwrap();

        // Verify the restored signature works
        assert!(MLDSABackend::verify(
            &sig_restored,
            &data,
            &keypair.public_key
        ));
    }
}
