use chrono::Timelike;
//use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::{LineWriter, Write};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use crate::lib::shared_data::{SharedData, SharedEnd, SharedPause};
use colored::Colorize;
use tokio::time::interval;

pub async fn task(
    secs: u64,
    report_file: String,
    shared_data: Arc<SharedData>,
    pause: Arc<SharedPause>,
    end: Arc<SharedEnd>,
) {

    let mut interval = interval(Duration::from_secs(1));
    let mut passed = 0;
    interval.tick().await; // skip first tick
    loop {
        interval.tick().await;
        passed += 1;

        {
            let mut guard = end.lock.lock().unwrap();
            if guard.terminated > 0 {
                guard.terminated += 1;
                end.cv.notify_all();
                break;
            }
        }

        let mut state = pause.lock.lock().unwrap();

        if passed == secs {
            if *state != true {

                let file = match OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(false)
                    .open(&report_file)
                {
                    Ok(file) => file,
                    Err(err) => {
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        end.cv.notify_all();
                        panic! {"Error while opening file {}", err}
                    }
                };

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
                    "{0: <25} | {1: <25} | {2: <15} | {3: <15} | {4: <15} | {5: <30} | {6: <30} | {7: <10}",
                    "SRC_ADDR",
                    "DST_ADDR",
                    "SRC_PORT",
                    "DST_PORT",
                    "TOTAL_BYTES",
                    "START_TIMESTAMP",
                    "END_TIMESTAMP",
                    "PROTOCOL"
                );

                let text = time_header + "\n" + &report_header + "\n";

                match file.write_all(text.as_bytes()) {
                    Ok(()) => {}
                    Err(err) => {
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        panic! {"Error while writing {}",err};
                    }
                }


                let guard = shared_data.m.map.lock().unwrap();

                if !guard.deref().is_empty() {
                    for (k, v) in guard.deref() {
                        let my_str = format!("{}{}\n", k.to_string(), v.to_string());

                        match file.write_all(my_str.as_bytes()) {
                            Ok(()) => {}
                            Err(err) => {
                                let mut guard = end.lock.lock().unwrap();
                                guard.terminated += 1;
                                panic! {"Error while writing {}",err};
                            }
                        }
                    }

                    match file.write_all(b"\n") {
                        Ok(()) => {}
                        Err(err) => {
                            let mut guard = end.lock.lock().unwrap();
                            guard.terminated += 1;
                            panic! {"Error while writing {}",err};
                        }
                    }

                    println!("{}", format!("Report generated!").red());
                }

            }

            passed = 0;
        }
        state = pause.cv.wait_while(state, |s| *s == true).unwrap();
    }
}
