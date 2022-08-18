//use std::fmt::Debug;
use chrono::Timelike;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;


use crate::shared_data::{SharedData, SharedPause};
use colored::Colorize;
use tokio::{
    time::interval,
};



pub async fn task(secs: u64, report_file:String, shared_data: Arc<SharedData>, pause: Arc<SharedPause>) {

    
    
    let mut interval = interval(Duration::from_secs(secs));
    interval.tick().await; // skip first tick
    loop {


        interval.tick().await;

        let state = pause.lock.lock().unwrap();
        if *state != true {
                let file = OpenOptions::new()
                .write(true)
                .create(true)
                .append(false)
                .open(&report_file)
                .unwrap();

            let mut file = LineWriter::new(file);

            let generating_at = chrono::Local::now();

            let time_header = format!(
                "{} {}:{}:{}",
                generating_at.date(),
                generating_at.hour(),
                generating_at.minute(),
                generating_at.second()
            );
            let report_header = format!(
                "{0: <20} | {1: <20} | {2: <15} | {3: <15} | {4: <15} | {5: <30} | {6: <30} | {7: <30}",
                "SRC_ADDR", "DST_ADDR", "SRC_PORT", "DST_PORT", "Total_Bytes", "Start_ts", "End_ts", "Protocol"
            );

            file.write_all(time_header.as_bytes()).unwrap();
            file.write_all(b"\n").unwrap();
            file.write_all(report_header.as_bytes()).unwrap();
            file.write_all(b"\n").unwrap();

            
            
            let guard = shared_data.m.map.lock().unwrap();

            // Convert the Hashmap struct to a JSON string.
            // let json_string =
            //     serde_json::to_string(guard.deref()).expect("Error in serializing the data structure!");
            
            for (k,v) in guard.deref() {
                let my_str = format!("{}{}\n", k.to_string(), v.to_string());
                file.write_all(my_str.as_bytes()).unwrap();
            }


            //file.write_all(json_string.as_bytes()).unwrap();

            file.write_all(b"\n").unwrap();

            println!("{}", format!("Report generated!").red());

        
            

        }
        
        //state = pause.cv.wait_while(state, |s| *s == true).unwrap();
        
    }
}
