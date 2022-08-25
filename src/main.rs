mod lib;

use pcap::Error;
use lib::*;
use crate::lib::lib::sniffer;

fn main() {
    match sniffer() {
        Ok(()) => {},
        Err(error) => panic!("{}", error.to_string())
    }
}
