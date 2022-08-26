mod lib;

use crate::lib::lib::sniffer;
use lib::*;
use pcap::Error;

fn main() {
    match sniffer() {
        Ok(()) => {}
        Err(error) => panic!("{}", error.to_string()),
    }
}
