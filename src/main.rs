mod lib;

use crate::lib::lib::sniffer;
use lib::*;

fn main() {
    match sniffer() {
        Ok(()) => {}
        Err(error) => panic!("{}", error.to_string()),
    }
}
