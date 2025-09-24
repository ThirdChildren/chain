// Integration tests per rustcore::crypto::{hash, signature}

use rustcore::crypto::hash::Hash;
use rustcore::crypto::signature::{PrivateKey, PublicKey, Signature};
use rustcore::util::Saveable;
use std::io::Cursor;

use ecdsa::signature::Verifier;

#[test]
fn sign_and_verify_ok() {
    let sk: PrivateKey = PrivateKey::new_key();
    let pk: PublicKey = sk.public_key();

    let msg = "hello blockchain";
    let h = Hash::hash(&msg);

    let sig = Signature::sign_output(&h, &sk);
    assert!(sig.verify(&h, &pk), "verifica deve riuscire con stessa chiave e stesso hash");

    assert_eq!(sig.0.to_bytes().len(), 64);
}

#[test]
fn verify_fails_if_hash_changes() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();

    let h1 = Hash::hash(&"payload A");
    let h2 = Hash::hash(&"payload B"); // hash diverso

    let sig = Signature::sign_output(&h1, &sk);
    assert!(!sig.verify(&h2, &pk), "verifica deve fallire se l'hash cambia");
}

#[test]
fn verify_fails_with_wrong_public_key() {
    let sk1 = PrivateKey::new_key();
    let pk1 = sk1.public_key();

    let sk2 = PrivateKey::new_key();
    let pk2 = sk2.public_key();

    let h = Hash::hash(&"same payload");

    let sig = Signature::sign_output(&h, &sk1);

    // chiave sbagliata -> fallisce
    assert!(!sig.verify(&h, &pk2));
    // chiave giusta -> passa
    assert!(sig.verify(&h, &pk1));
}

#[test]
fn ecdsa_is_deterministic_rfc6979_for_same_key_and_message() {
    let sk = PrivateKey::new_key();
    let h = Hash::hash(&"deterministic message");

    // ECDSA via k256/ecdsa usa RFC6979: stessa SK + stesso msg -> stessa firma
    let s1 = Signature::sign_output(&h, &sk);
    let s2 = Signature::sign_output(&h, &sk);
    assert_eq!(s1.0.to_bytes(), s2.0.to_bytes(), "le firme devono essere identiche");
}

#[test]
fn wrapper_consistency_against_direct_verify() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();
    let h = Hash::hash(&"cross check");
    let sig = Signature::sign_output(&h, &sk);

    // Il nostro verify e quello diretto (trait Verifier) devono dare lo stesso esito
    let ours = sig.verify(&h, &pk);
    let direct = pk.0.verify(&h.as_bytes(), &sig.0).is_ok();
    assert_eq!(ours, direct, "wrapper Signature deve essere coerente con ecdsa::Verifier");
}

#[test]
fn public_key_pem_roundtrip() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();

    // salva PEM in memoria
    let mut buf = Vec::new();
    pk.save(&mut buf).expect("save PEM");

    // formato atteso
    assert!(std::str::from_utf8(&buf).unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));

    // ricarica da PEM
    let loaded = PublicKey::load(Cursor::new(buf)).expect("load PEM");

    // stessa chiave
    assert_eq!(loaded, pk);

    // verifica che la chiave funzioni dopo il roundtrip
    let h = Hash::hash(&"pem roundtrip");
    let sig = Signature::sign_output(&h, &sk);
    assert!(sig.verify(&h, &loaded));
}