use crate::lib::shared_data::SharedPause;
use crate::shared_data::SharedEnd;
use pcap::Device;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{mpsc, Arc};
use std::{io, process, thread};


pub fn get_commands(pause: Arc<SharedPause>, end: Arc<SharedEnd>) {
    let end_clone=Arc::clone(&end);
    thread::Builder::new()
        .name("STDIN".to_string())
        .spawn(move || loop {
            let mut buffer = String::new();
            let mut r = io::stdin().read_line(&mut buffer);
            {
                let mut guard = end_clone.lock.lock().unwrap();
                guard.present = true;
                guard.buf = buffer;
                guard.result = r;
            }
            end_clone.cv.notify_all();
        }).unwrap();
    let mut active = true;
    loop {
        match active {
            true => println!("Please enter s to stop the sniffing"),
            false => println!("Please enter r to resume the sniffing"),
        }
        let mut state = end.lock.lock().unwrap();

        state = end.cv.wait_while(state, |s| s.present == false && s.terminated == 0 ).unwrap();
        if state.terminated == 3 {
            //panic!("MAIN PANICKED!");
            process::exit(1); //we need to terminate the thread STDIN
        }
        if state.terminated > 0 {
            println!("the program is shutting down");
            state = pause.cv.wait_while(state, |s| s.terminated < 3 ).unwrap();
            process::exit(1); //we need to terminate the thread STDIN
        }
        if state.present {
            state.present = false;
            match state.result {
                Ok(_) => {
                    let mut c = state.buf.chars().next();
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
                        _ => {
                            println!("input non riconosciuto");
                        }
                    }
                }
                Err(_) => println!("input non riconosciuto"),
            }
        }

    }
}

pub fn get_device(devices: Vec<Device>) -> Device {
    println!("\n");
    for (index, device) in devices.iter().enumerate() {
        println!(
            "Device #{} | Name: {} | Description: {:?}",
            index, device.name, device.desc
        );
    }
    println!("Insert the number of the device you want to sniff on");
    loop {
        let mut buffer = String::new();
        let mut r = io::stdin().read_line(&mut buffer);
        match r {
            Ok(_) => {
                let mut num = buffer.trim().parse::<usize>();
                match num {
                    Ok(n) if n < devices.len() => {
                        return devices[n].clone();
                    }
                    _ => {
                        println!("input non riconosciuto");
                    }
                }
            }
            Err(_) => println!("input non riconosciuto"),
        }
    }
}
