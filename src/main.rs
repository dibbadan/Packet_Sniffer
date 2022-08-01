extern crate core;

mod cli;
use clap::{Parser, Subcommand};
use cli::Cli;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use sniffer::Sniffer;

mod parser;
mod sniffer;

fn main() {
<<<<<<< HEAD
    let mut sniffer = Sniffer::new();
=======
    //push
    let cli = Cli::parse();


    

    
    let _passed_args = Cli::show_passed_args(&cli);
    //println!("PASSED ARGUMENTS = {:?}", passed_args);

    //let mut sniffer = Sniffer::new();

    /*
>>>>>>> 03f9c4b4cc5a283b2c23e335d80e28424289f829
    let _devices = sniffer.list_devices();
    sniffer.sniff(_devices[0].clone());
    sniffer.show_map();
}
