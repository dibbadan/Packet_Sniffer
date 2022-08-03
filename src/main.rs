extern crate core;

mod cli;
use clap::{Parser, Subcommand};
use cli::Cli;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use sniffer::Sniffer;

mod parser;
mod sniffer;

fn main() {
    let cli = Cli::parse();
    let (device,interval,report) = Cli::get_parameters(&cli);
    println!("PASSED ARGUMENTS = {:?}, {:?}, {:?}", device, interval, report);

    let mut sniffer = Sniffer::new();

    let _devices = sniffer.list_devices();
    sniffer.sniff(_devices[0].clone());
    sniffer.show_map();

}
