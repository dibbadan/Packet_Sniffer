use chrono::Timelike;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::shared_data::key;
use crate::SharedData;
use colored::Colorize;
use tokio::{
    select,
    task::spawn,
    time::{interval, sleep},
};



pub async fn task(secs: u64, shared_data: Arc<SharedData>) {


    let mut interval = interval(Duration::from_secs(secs));
    interval.tick().await; // skip first tick
    loop {
        interval.tick().await;

        let mut guard = shared_data.m.map.lock().unwrap();

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open("report.txt")
            .unwrap();

        let mut file = LineWriter::new(file);

        let generating_at = chrono::Local::now();

        let report_header = format!(
            "{} {}:{}:{}",
            generating_at.date(),
            generating_at.hour(),
            generating_at.minute(),
            generating_at.second()
        );

        file.write_all(report_header.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();

        // Convert the Hashmap struct to a JSON string.
        let json_string =
            serde_json::to_string(guard.deref()).expect("Error in serializing the data structure!");

        file.write_all(json_string.as_bytes()).unwrap();

        file.write_all(b"\n").unwrap();

        println!("{}", format!("Report generated!").red());
    }
}
