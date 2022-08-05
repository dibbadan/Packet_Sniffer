mod parser;
mod sniffer;
mod cli;

use clap::Parser;

use cli::Cli;

pub fn sniffer() {
    let cli = Cli::parse();
    let (device,interval,report_file) = Cli::get_parameters(&cli);
    println!("PASSED ARGUMENTS = {:?}, {:?}, {:?}", device, interval, report_file);

    let _devices = sniffer::list_devices();

    sniffer::sniff(_devices[0].clone(),interval,report_file);
}