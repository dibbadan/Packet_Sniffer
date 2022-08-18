mod cli;
mod executor;
mod parser;
mod shared_data;
mod sniffer;
mod dns;
mod inputs;


use std::borrow::Borrow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::executor::task;
use crate::shared_data::{key, MapData, SharedData};
use cli::Cli;
use crate::inputs::get_device;

pub fn sniffer() {



    let cli = Cli::parse();
    let (interval, report_file) = Cli::get_parameters(&cli);
    
    println!(
        "PASSED ARGUMENTS = {:?}, {:?}",
        interval, report_file
    );

    
    let _devices = sniffer::list_devices().unwrap();


    let device = get_device(_devices);



    sniffer::sniff(device, interval, report_file);



}
