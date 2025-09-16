pub mod crypto;

fn main() {
    let data = b"Hello, world!";
    let hash = crypto::Hash::new(data);
    println!("Hash: {}", hash.to_hex());
}