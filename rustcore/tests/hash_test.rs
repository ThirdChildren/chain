use rustcore::crypto::hash::Hash;

// Usiamo blake3 direttamente per costruire il valore atteso
use blake3 as blake3_crate;

#[test]
fn blake3_empty_matches_crate() {
    let my = Hash::new(b"");
    let expected = blake3_crate::hash(b"");
    assert_eq!(my.as_bytes(), expected.as_bytes(), "hash(\"\") deve combaciare");
    // 32 byte di output (BLAKE3 default)
    assert_eq!(my.as_bytes().len(), 32);
}

#[test]
fn blake3_abc_matches_crate_and_hex_is_lowercase() {
    let data = b"abc";
    let my = Hash::new(data);
    let expected = blake3_crate::hash(data);

    // Confronto byte-to-byte
    assert_eq!(my.as_bytes(), expected.as_bytes());

    // Hex: minuscolo e lungo 64 caratteri (2 per byte)
    let hex = my.to_hex();
    assert_eq!(hex, hex::encode(expected.as_bytes()));
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn determinism_and_idempotence() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let h1 = Hash::new(data);
    let h2 = Hash::new(data);
    assert_eq!(h1.as_bytes(), h2.as_bytes(), "stesso input -> stesso output");
}

#[test]
fn hex_roundtrip_ok() {
    let data = b"roundtrip";
    let h = Hash::new(data);
    let hexval = h.to_hex();

    let parsed = Hash::from_hex(&hexval).expect("hex valido deve decodificare");
    assert_eq!(parsed.as_bytes(), h.as_bytes());
}

#[test]
fn from_hex_rejects_invalid_hex() {
    // 'zz' non è esadecimale valido
    assert!(Hash::from_hex("zz").is_none());
    // Stringa con lunghezza dispari -> hex non valido
    assert!(Hash::from_hex("abc").is_none());
}
