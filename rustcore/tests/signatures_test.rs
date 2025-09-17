use rustcore::crypto::hash::Hash;
use rustcore::crypto::signature::{PrivateKey, Signature, Verifier};

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

#[test]
fn sign_and_verify_ok() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();

    let msg = b"hello blockchain";
    let h = Hash::new(msg);

    // firma e verifica attraverso il wrapper
    let sig = Signature::sign_output(&h, &sk.0);
    assert!(sig.verify(&h, &pk.0), "la verifica deve riuscire con stessa chiave e stesso hash");

    // sanity sulle lunghezze note di Ed25519
    assert_eq!(sig.0.to_bytes().len(), SIGNATURE_LENGTH, "firma Ed25519 = 64 byte");
    assert_eq!(pk.0.to_bytes().len(), PUBLIC_KEY_LENGTH, "pubkey Ed25519 = 32 byte");
}

#[test]
fn verify_fails_if_hash_changes() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();

    let h1 = Hash::new(b"payload A");
    let h2 = Hash::new(b"payload B"); 

    let sig = Signature::sign_output(&h1, &sk.0);
    assert!(!sig.verify(&h2, &pk.0), "verifica deve fallire se l'hash cambia");
}

#[test]
fn verify_fails_with_wrong_public_key() {
    let sk1 = PrivateKey::new_key();
    let pk1 = sk1.public_key();

    let sk2 = PrivateKey::new_key();
    let pk2 = sk2.public_key();

    let h = Hash::new(b"same payload");

    let sig = Signature::sign_output(&h, &sk1.0);

    // con la chiave pubblica sbagliata deve fallire
    assert!(!sig.verify(&h, &pk2.0), "verifica deve fallire con public key diversa");
    // con quella giusta deve passare (controllo incrociato)
    assert!(sig.verify(&h, &pk1.0));
}

#[test]
fn ed25519_is_deterministic_for_same_key_and_message() {
    let sk = PrivateKey::new_key();
    let h = Hash::new(b"deterministic message");

    // Ed25519 (pure) è deterministico: stessa SK + stesso msg -> stessa firma
    let sig1 = Signature::sign_output(&h, &sk.0);
    let sig2 = Signature::sign_output(&h, &sk.0);
    assert_eq!(sig1.0.to_bytes(), sig2.0.to_bytes(), "le firme devono essere identiche");
}

#[test]
fn wrapper_consistency_against_dalek_direct_verify() {
    let sk = PrivateKey::new_key();
    let pk = sk.public_key();

    let h = Hash::new(b"cross check");
    let sig = Signature::sign_output(&h, &sk.0);

    // Il nostro verify e quello diretto di dalek devono dare lo stesso esito
    let ours = sig.verify(&h, &pk.0);
    let dalek_direct = pk.0.verify(h.as_bytes(), &sig.0).is_ok();
    assert_eq!(ours, dalek_direct, "wrapper Signature deve essere coerente con dalek");
}
