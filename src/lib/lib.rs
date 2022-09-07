use clap::Parser;
use pcap::{Error};

use crate::lib::cli::Cli;
use crate::lib::inputs::get_device;
use crate::lib::sniffer;

pub fn sniffer() -> Result<(), Error> {
    let cli = Cli::parse();

    let (interval, report_file) = Cli::get_parameters(cli);

    let devices = sniffer::list_devices()?;

    let device = get_device(devices);

    sniffer::sniff(device, interval, report_file)?;

    Ok(())
}
