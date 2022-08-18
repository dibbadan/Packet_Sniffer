mod interface;
mod executor;
mod parser;
mod shared_data;
mod sniffer;
mod dns;



//use std::borrow::Borrow;
//use std::collections::HashMap;
//use std::net::{IpAddr, Ipv4Addr};

//use std::sync::{Arc, Mutex};
//use std::thread;


//use crate::shared_data::{key, MapData, SharedData};
// use interface::inputs::get_device;

use interface::{cli::Cli, inputs::get_device};
use crate::executor::task;
use clap::Parser;


pub fn sniffer() {



    let cli = Cli::parse();
    let (interval, report_file) = Cli::get_parameters(cli);
    
    println!(
        "PASSED ARGUMENTS = {:?}, {:?}",
        interval, report_file
    );

    
    let _devices = sniffer::list_devices().unwrap();


    let device = get_device(_devices);



    sniffer::sniff(device, interval, report_file);



}
