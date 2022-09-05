use clap::Parser;
use pcap::{Device, Error};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::lib::cli::Cli;
use crate::lib::executor::task;
use crate::lib::inputs::get_device;
use crate::lib::shared_data::{key, MapData, SharedData};
use crate::lib::sniffer;

pub fn sniffer() -> Result<(), Error> {

    let cli = Cli::parse();

    let (interval, report_file) = Cli::get_parameters(cli);

    let devices = sniffer::list_devices()?;

    let device = get_device(devices);

    sniffer::sniff(device, interval, report_file)?;

    Ok(())
}
