mod lib;

use crate::lib::lib::sniffer;
use lib::*;

fn main() {
    match sniffer() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("Uscita dal main ... Errore: {}", error.to_string())
        },
    }
}
