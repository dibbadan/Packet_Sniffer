mod cli;
mod executor;
mod parser;
mod shared_data;
mod sniffer;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::time::sleep;

use crate::executor::task;
use crate::shared_data::{key, MapData, SharedData};
use cli::Cli;

#[tokio::main]
pub async fn sniffer() {

    let mappa = SharedData::new();
    let mappa_clone = Arc::clone(&mappa);

    let cli = Cli::parse();
    let (device, interval, report_file) = Cli::get_parameters(&cli);
    println!(
        "PASSED ARGUMENTS = {:?}, {:?}, {:?}",
        device, interval, report_file
    );

    let _devices = sniffer::list_devices();


    tokio::spawn(async move {
        task(2, mappa).await;
    });



    sniffer::sniff(_devices[0].clone(), interval, report_file, mappa_clone);



}
