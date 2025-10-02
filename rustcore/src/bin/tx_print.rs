use rustcore::types::Transaction;
use rustcore::util::Saveable;
use std::env;
use std::process::exit;

fn main() {
    let path = if let Some(arg) = env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: tx_print <tx_file>");
        exit(1);
    };
    
    match Transaction::load_from_file(&path) {
        Ok(tx) => println!("{:#?}", tx),
        Err(e) => {
            eprintln!("Note: Transaction loading not implemented in simplified version");
            eprintln!("Error: {}", e);
            eprintln!("This tool would require proper serialization format implementation");
        }
    }
}