use rustcore::crypto::signatures::KeyPair;

use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};

#[test]
fn keygen_sign_verify_roundtrip_ok() {
    let kp = KeyPair::generate();
    let msg = b"hello blockchain";

    let sig: Signature = kp.sign_message(msg);

    assert!(kp.verify(msg, &sig), "sign/verify deve riuscire");

    assert_eq!(sig.to_bytes().len(), SIGNATURE_LENGTH);
    assert_eq!(kp.public_key.to_bytes().len(), PUBLIC_KEY_LENGTH);
}

#[test]
fn verify_fails_on_modified_message() {
    let kp = KeyPair::generate();
    let msg = b"immutabile";
    let sig = kp.sign_message(msg);

    // altera 1 byte del messaggio
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0x01;

    assert!(!kp.verify(&tampered, &sig), "verifica deve fallire se il messaggio cambia");
}

#[test]
fn verify_fails_on_modified_signature() {
    let kp = KeyPair::generate();
    let msg = b"firmo-questa";
    let sig = kp.sign_message(msg);

    // flip di 1 bit nella firma
    let mut bad = sig.to_bytes();
    bad[0] ^= 0x01;
    let bad_sig = Signature::from_bytes(&bad);
    assert!(!kp.verify(msg, &bad_sig), "verifica deve fallire se la firma cambia");
}

#[test]
fn rfc8032_test1_vector_verify_and_sign() {
    // RFC 8032 §7.1 - TEST 1 (messaggio vuoto), Ed25519
    // SECRET KEY (32B seed) e PUBLIC KEY (32B)
    // https://www.ietf.org/rfc/rfc8032.txt
    let sk_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let sig_hex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    // decode hex -> array
    use core::convert::TryInto;
    let sk_bytes: [u8; 32] = hex::decode(sk_hex).unwrap().try_into().unwrap();
    let pk_bytes: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

    let vk = VerifyingKey::from_bytes(&pk_bytes).expect("pk valida");
    let sig = Signature::from_bytes(&sig_bytes);

    // messaggio vuoto
    let msg: &[u8] = b"";
    assert!(vk.verify(msg, &sig).is_ok(), "RFC8032 TEST1 deve verificare"); 

    // Verifica anche che firmando con la SK di RFC si ottenga la stessa sig
    let sk = SigningKey::from_bytes(&sk_bytes);
    let produced = sk.sign(msg);
    assert_eq!(produced.to_bytes(), sig_bytes, "firma prodotta == firma RFC8032");
}

#[test]
fn verify_strict_behaviour_matches_verify_on_valid_data() {
    // Su firme e chiavi "buone" verify_strict deve passare come verify.
    // (verify_strict aggiunge check anti-malleability non richiesti dall'RFC ma utili nella pratica)
    // vedi docs ed25519-dalek
    // https://docs.rs/crate/ed25519-dalek/latest
    let kp = KeyPair::generate();
    let msg = b"strict-check";
    let sig = kp.sign_message(msg);

    // API strict è su VerifyingKey
    assert!(kp.public_key.verify(msg, &sig).is_ok());
    assert!(kp.public_key.verify_strict(msg, &sig).is_ok());
}
