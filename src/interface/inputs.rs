use std::io;
use std::sync::Arc;
use pcap::Device;
use crate::shared_data::SharedPause;

pub fn get_commands(pause: Arc<SharedPause>) {
    let mut active = true;
    loop {
        match active {
            true => println!("Please enter s to stop the sniffing"),
            false => println!("Please enter r to resume the sniffing")
        }
        let mut buffer = String::new();
        let r = io::stdin().read_line(&mut buffer);
        match r {
            Ok(_) => {
                let c = buffer.chars().next();
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
        let  r = io::stdin().read_line(&mut buffer);
        match r {
            Ok(_) => {
                let num = buffer.trim().parse::<usize>();
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