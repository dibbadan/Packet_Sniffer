use crate::lib::shared_data::SharedPause;
use crate::shared_data::{SharedEnd};
use pcap::{Device, Error};
//use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc};
use std::thread::sleep;
use std::{io,thread, time};
use pcap::Error::PcapError;

pub fn get_commands(pause: Arc<SharedPause>, end: Arc<SharedEnd>) -> Result<(),Error>{
    let end_clone = Arc::clone(&end);
    let thread = thread::Builder::new()
        .name("STDIN".to_string())
        .spawn(move || loop {
            let mut buffer = String::new();
            let r = io::stdin().read_line(&mut buffer);
            {
                let mut guard = end_clone.lock.lock().unwrap();
                guard.present = true;
                guard.buf = buffer;
                guard.result = r;
            }
            end_clone.cv.notify_all();
        });
    match thread {
        Ok(_) => {}
        Err(_error) => {
            let mut guard = end.lock.lock().unwrap();
            guard.terminated += 1;
            end.cv.notify_all();
        }
    }

    let mut active = true;
    loop {
        match active {
            true => println!("Please enter s to stop the sniffing or q to end the process"),
            false => println!("Please enter r to resume the sniffing or q to end the process"),
        }
        let mut state = end.lock.lock().unwrap();

        state = end
            .cv
            .wait_while(state, |s| s.present == false && s.terminated == 0)
            .unwrap();
        if state.terminated == 3 {
            sleep(time::Duration::from_millis(300));
            return Err(PcapError("Error in one of the thread".to_string()));
        }
        if state.terminated > 0 {
            println!("The program is shutting down ...");
            state = end.cv.wait_while(state, |s| s.terminated < 3).unwrap();
            sleep(time::Duration::from_millis(300));
            return Err(PcapError("Error in one of the thread".to_string()));//we need to terminate the thread STDIN
        }
        if state.present {
            state.present = false;
            match state.result {
                Ok(_) => {
                    let c = state.buf.chars().next();
                    match c {
                        Some(c) if active == true && c == 's' => {
                            active = false;
                            let mut state = pause.lock.lock().unwrap();
                            *state = true;
                        }
                        Some(c) if active == false && c == 'r' => {
                            active = true;
                            let mut state = pause.lock.lock().unwrap();
                            *state = false;
                            pause.cv.notify_all();
                        }
                        Some(c) if c == 'q' => {
                            state.terminated += 1;
                            println!("The program is shutting down ...");
                            state = end.cv.wait_while(state, |s| s.terminated < 4).unwrap();
                            sleep(time::Duration::from_millis(30));
                            return Ok(()); //we need to terminate the thread STDIN
                        }

                        _ => {
                            println!("Input non riconosciuto");
                        }
                    }
                }
                Err(_) => println!("Input non riconosciuto"),
            }
        }
    }
}

pub fn get_device(devices: Vec<Device>) -> Device {
    println!("\n");
    for (index, device) in devices.iter().enumerate() {
        let desc = match &device.desc {
            Some(desc) => desc.to_string(),
            None => "No description".to_string()
        };
        println!(
            "Device #{} | Name: {} | Description: {}",
            index, device.name, desc
        );
    }
    println!("Insert the number of the device you want to sniff on");
    loop {
        let mut buffer = String::new();
        let r = io::stdin().read_line(&mut buffer);
        match r {
            Ok(_) => {
                let num = buffer.trim().parse::<usize>();
                match num {
                    Ok(n) if n < devices.len() => {
                        return devices[n].clone();
                    }
                    _ => {
                        eprintln!("Input non riconosciuto");
                    }
                }
            }
            Err(_) => eprintln!("Input non riconosciuto"),
        }
    }
}
