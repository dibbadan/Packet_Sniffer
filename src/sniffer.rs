use crate::parser::{PacketHeader, ParsedPacket};
use crate::{shared_data, task};
use crate::shared_data::{key, SharedData, SharedPause, value};
use colored::Colorize;
use pcap::{Active, Capture, Device, Error, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use std::{io, thread};
use pktparse::ip::IPProtocol;
use pktparse::tcp::TcpHeader;

const MAX_THREADS: usize = 10;

pub fn list_devices() -> Vec<Device> {
    let mut devices: Vec<Device> = vec![];
    devices = Device::list().unwrap();

    println!("\n");
    for (index, device) in devices.iter().enumerate() {
        println!(
            "Device #{} | Name: {} | Description: {:?}",
            index, device.name, device.desc
        );
    }

    devices
}

#[tokio::main]
pub async fn sniff(
    device: Device,
    interval: u32,
    report_file: &str,
) {
    let (tx, rx): (Sender<ParsedPacket>, Receiver<ParsedPacket>) = mpsc::channel();
    let mappa = SharedData::new();
    let mappa_clone = Arc::clone(&mappa);
    let pause = SharedPause::new();
    let pause_clone = Arc::clone(&pause);


    get_packets(tx, device, pause_clone);

    receive_packets(rx, interval, report_file, mappa_clone);

    tokio::spawn(async move {
        task(2, mappa).await;
    });

    //must be at the end
    get_commands(pause);
}

pub fn get_packets(tx: Sender<ParsedPacket>, device: Device, pause: Arc<SharedPause>) {
    //let cap_handle = Arc::new(Mutex::new(device.open().unwrap()));
    let mut cap_handle = device.open().unwrap();

    let parser = ParsedPacket::new();
    let tx = tx.clone();
    //let cap_handle = cap_handle.clone();

    thread::spawn(move || loop {
        //let mut cap_handle = cap_handle.lock().unwrap();
        //let mut state = pause.lock.lock().unwrap();
        //state = pause.cv.wait_while(state, |s| *s == true).unwrap();
        let mut packet = cap_handle.next();

        if let Ok(packet) = packet {
            let data = packet.data.to_owned();
            let len = packet.header.len;
            let ts: String = format!(
                "{}.{:06}",
                &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
            );

            let parsed_packet = parser.parse_packet(data, len, ts);

            match parsed_packet {
                Ok(parsed_packet) => {
                    //println!("{}", format!("Thread is sending packet to channel!").cyan());
                    tx.send(parsed_packet).unwrap();
                }
                Err(err) => {
                    println!("ERROR : {}", err);
                }
            }
        } else {
            dbg!("End of packet stream, shutting down reader thread!");
            break;
        }

    });
}


pub fn receive_packets(
    rx: Receiver<ParsedPacket>,
    interval: u32,
    report_file: &str,
    shared_data: Arc<SharedData>,
) {
    print_headers();
    thread::spawn(move || {
        for packet in rx.iter() {
            let mut guard = shared_data.m.map.lock().unwrap();

            match packet {
                packet => {
                    let addr_pair = get_addr(&packet);
                    //match guard.map.get_mut(&addr_pair) {
                    match guard.get_mut(&addr_pair) {
                        Some(v) => {
                            /*v.0 += packet.get_len();
                            v.2 = packet.get_ts().to_string();*/
                            v.add_to_bytes(packet.get_len());
                            v.set_end_ts(packet.get_ts().to_string())
                        }
                        None => {
                            guard.insert(
                                addr_pair,
                                /*(
                                    packet.get_len(),
                                    packet.get_ts().to_string(),
                                    packet.get_ts().to_string(),
                                ),*/
                                value::new(packet.get_len(), packet.get_ts().to_string(), packet.get_ts().to_string())
                            );
                        }
                    }

                    show_to_console(&packet);

                }
            }

        }
        dbg!("End of packet stream, shutting down receiver thread!");
    });
}

pub fn get_commands(pause: Arc<SharedPause>) {
    let mut active = true;
    loop {
        match active {
            true => println!("Please enter s to stop the sniffing"),
            false => println!("Please enter r to resume the sniffing")
        }
        let mut buffer = String::new();
        let mut r = io::stdin().read_line(&mut buffer);
        match r {
            Ok(_) => {
                let mut c = buffer.chars().next();
                match c {
                    Some(c) if active == true && c == 's' => {
                        active = false;
                        let mut state = pause.lock.lock().unwrap();
                        *state = true;

                    }
                    Some(c) if active == false && c == 'r' => {
                        active = true;
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

pub fn get_addr(parsed_packet: &ParsedPacket) -> key {


    let mut addr_pair: key = key::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
        0
    );

    let headers = parsed_packet.get_headers();


    let mut src_port= 0;
    let mut dst_port= 0;


    headers.iter().for_each(|h| match h {
        PacketHeader::Tcp(packet) => {
            src_port = packet.source_port;
            dst_port = packet.dest_port;
        }
        PacketHeader::Udp(packet) => {
            src_port = packet.source_port;
            dst_port = packet.dest_port
        }
        _ => {}
    });

    headers.iter().for_each(|h| match h {
        PacketHeader::Ipv4(packet) => {
            addr_pair = key::new(IpAddr::V4(packet.source_addr), IpAddr::V4(packet.dest_addr), src_port, dst_port);
        }
        PacketHeader::Ipv6(packet) => {
            addr_pair = key::new(IpAddr::V6(packet.source_addr), IpAddr::V6(packet.dest_addr), src_port, dst_port);
        }
        _ => {}
    });

    /*headers.iter().for_each(|h| match h {
        PacketHeader::Ipv4(packet) => {
            addr_pair = key::new(IpAddr::V4(packet.source_addr), IpAddr::V4(packet.dest_addr));
        }
        PacketHeader::Ipv6(packet) => {
            addr_pair = key::new(IpAddr::V6(packet.source_addr), IpAddr::V6(packet.dest_addr));
        }
        _ => {}
    });*/

    addr_pair
}

pub fn show_to_console(parsed_packet: &ParsedPacket) {
    let (src_addr, src_port, dst_addr, dst_port) = get_packet_meta(&parsed_packet);
    let protocol = &parsed_packet.get_headers()[0].to_string(); // Transport layer protocol (TCP or UDP)
    let length = &parsed_packet.get_len();
    let ts = &parsed_packet.get_ts();
    println!(
        "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}",
        src_addr, src_port, dst_addr, dst_port, protocol, length, ts
    );
}

pub fn get_packet_meta(
    parsed_packet: &ParsedPacket,
) -> (String, String, String, String) {
    let mut src_addr = "".to_string();
    let mut dst_addr = "".to_string();
    let mut src_port = "".to_string();
    let mut dst_port = "".to_string();

    let headers = parsed_packet.get_headers();

    headers.iter().for_each(|h| match h {
        PacketHeader::Tcp(packet) => {
            src_port = packet.source_port.to_string();
            dst_port = packet.dest_port.to_string();
        }
        PacketHeader::Udp(packet) => {
            src_port = packet.source_port.to_string();
            dst_port = packet.dest_port.to_string();
        }
        PacketHeader::Ipv4(packet) => {
            src_addr = IpAddr::V4(packet.source_addr).to_string();
            dst_addr = IpAddr::V4(packet.dest_addr).to_string();
        }
        PacketHeader::Ipv6(packet) => {
            src_addr = IpAddr::V6(packet.source_addr).to_string();
            dst_addr = IpAddr::V6(packet.dest_addr).to_string();
        }
        _ => {}
    });

    (src_addr, src_port, dst_addr, dst_port)
}

fn print_headers() {
    println!("\n");
    println!(
        "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
        "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Timestamp"
    );
    println!("{:-^1$}", "-", 165,);
}



/*
    pub fn get_packet_meta(
        &self,
        parsed_packet: &ParsedPacket,
    ) -> (String, String, String, String) {
        let mut src_addr = "".to_string();
        let mut dst_addr = "".to_string();
        let mut src_port = "".to_string();
        let mut dst_port = "".to_string();

        let headers = parsed_packet.get_headers();

        headers.iter().for_each(|h| match h {
            PacketHeader::Tcp(packet) => {
                src_port = packet.source_port.to_string();
                dst_port = packet.dest_port.to_string();
            }
            PacketHeader::Udp(packet) => {
                src_port = packet.source_port.to_string();
                dst_port = packet.dest_port.to_string();
            }
            PacketHeader::Ipv4(packet) => {
                src_addr = IpAddr::V4(packet.source_addr).to_string();
                dst_addr = IpAddr::V4(packet.dest_addr).to_string();
            }
            PacketHeader::Ipv6(packet) => {
                src_addr = IpAddr::V6(packet.source_addr).to_string();
                dst_addr = IpAddr::V6(packet.dest_addr).to_string();
            }
            _ => {}
        });

        (src_addr, src_port, dst_addr, dst_port)
    }

    fn print_headers(&self) {
        println!("\n");
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
            "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Timestamp"
        );
        println!("{:-^1$}", "-", 165,);
    }

    pub fn show_to_console(&self, parsed_packet: &ParsedPacket) {
        let (src_addr, src_port, dst_addr, dst_port) = self.get_packet_meta(&parsed_packet);
        let protocol = &parsed_packet.get_headers()[0].to_string(); // Transport layer protocol (TCP or UDP)
        let length = &parsed_packet.get_len();
        let ts = &parsed_packet.get_ts();
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}",
            src_addr, src_port, dst_addr, dst_port, protocol, length, ts
        );
    }

    pub fn get_addr(&self, parsed_packet: &ParsedPacket) -> (IpAddr, IpAddr) {
        let mut addr_pair: (IpAddr, IpAddr) = (
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        );

        let headers = parsed_packet.get_headers();

        headers.iter().for_each(|h| match h {
            PacketHeader::Ipv4(packet) => {
                addr_pair = (IpAddr::V4(packet.source_addr), IpAddr::V4(packet.dest_addr));
            }
            PacketHeader::Ipv6(packet) => {
                addr_pair = (IpAddr::V6(packet.source_addr), IpAddr::V6(packet.dest_addr));
            }
            _ => {}
        });

        addr_pair
    }

    pub fn show_map(&self) {
        println!("\n");
        println!("{:?}", self.map);
        println!("\n");
    }
}
*/
