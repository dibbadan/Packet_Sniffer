use crate::lib::parser::{PacketHeader, ParsedPacket};
use crate::lib::shared_data::{key, value, SharedData, SharedPause};
use crate::lib::{executor::task, inputs, shared_data};
use crate::shared_data::SharedEnd;
use colored::Colorize;
use pcap::Error::TimeoutExpired;
use pcap::{Active, Capture, Dead, Device, Error, Packet};
use pktparse::ip::IPProtocol;
use pktparse::tcp::TcpHeader;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::sync::mpsc::{Receiver, RecvError, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{current, sleep};
use std::time::Duration;
use std::{io, panic, thread};
use tokio::task::JoinHandle;

pub fn list_devices() -> Result<Vec<Device>, Error> {
    let mut devices = match Device::list() {
        Ok(devices) => devices,
        Err(error) => {
            eprintln!("{}", error.to_string());
            return Err(error);
        }
    };

    Ok(devices)
}

#[tokio::main]
pub async fn sniff(device: Device, interval: u64, report_file: String) -> Result<(), Error> {
    let (tx, rx): (Sender<ParsedPacket>, Receiver<ParsedPacket>) = mpsc::channel();

    let mappa = SharedData::new();
    let mappa_clone = Arc::clone(&mappa);

    let pause = SharedPause::new();
    let pause_clone = Arc::clone(&pause);
    let pausa_clone_task = Arc::clone(&pause);

    let end = SharedEnd::new();
    let end_clone1 = Arc::clone(&end);
    let end_clone2 = Arc::clone(&end);
    let end_clone3 = Arc::clone(&end);

    get_packets(tx, device, pause_clone, end_clone1)?;
    receive_packets(rx, mappa_clone, end_clone2)?;

    tokio::spawn(async move {
        task(interval, report_file, mappa, pausa_clone_task, end_clone3).await;
    });

    inputs::get_commands(pause, end)
}

pub fn get_packets(
    tx: Sender<ParsedPacket>,
    device: Device,
    pause: Arc<SharedPause>,
    end: Arc<SharedEnd>,
) -> Result<(), Error> {
    let mut cap_handle = match Capture::from_device(device) {
        Ok(capture) => match capture.promisc(true).timeout(1000).open() {
            Ok(cap_handle) => cap_handle,
            Err(error) => {
                eprintln!("{}", error.to_string());
                return Err(error);
            }
        },
        Err(error) => {
            eprintln!("{}", error.to_string());
            return Err(error);
        }
    };

    let parser = ParsedPacket::new();
    let tx = tx.clone();

    thread::Builder::new()
        .name("SENDER".to_string())
        .spawn(move || loop {
            {
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    end.cv.notify_all();
                    break;
                }
            }

            /*let mut propagation = false;

            {
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    propagation = true;
                    end.cv.notify_all();
                }
            }

            if propagation {
                panic!("GET PACKETS PANICKED DUE TO PANIC PROPAGATION!");
            }*/

            //let packet;

            let packet = match cap_handle.next() {
                Ok(packet) => packet,

                Err(error) => match error {
                    TimeoutExpired => {
                        let mut guard = end.lock.lock().unwrap();
                        if guard.terminated > 0 {
                            guard.terminated += 1;
                            end.cv.notify_all();
                            break;
                        }

                        continue;
                    }
                    _ => {
                        eprintln!("{}", error.to_string());
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        end.cv.notify_all();
                        panic!("GET PACKETS PANICKED!");
                    }
                },
            };

            let mut state = pause.lock.lock().unwrap();

            if *state != true {
                let data = packet.data.to_owned();
                let len = packet.header.len;
                let ts: String = format!(
                    "{}.{:06}",
                    &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
                );

                let parsed_packet = parser.parse_packet(data, len, ts);

                match parsed_packet {
                    Ok(parsed_packet) => {
                        /*tx.send(parsed_packet).unwrap();*/
                        match tx.send(parsed_packet) {
                            Ok(()) => {}
                            Err(error) => {
                                {
                                    eprintln!("{}", error);
                                    let mut guard = end.lock.lock().unwrap();
                                    guard.terminated += 1;
                                    end.cv.notify_all();
                                }
                                panic!("GET PACKETS PANICKED!");
                            }
                        }
                    }
                    Err(error) => {
                        {
                            eprintln!("{}", error);
                            let mut guard = end.lock.lock().unwrap();
                            guard.terminated += 1;
                            end.cv.notify_all();
                        }
                        panic!("GET PACKETS PANICKED!");
                    }
                }
            }

            state = pause.cv.wait_while(state, |s| *s == true).unwrap();
        })
        .unwrap();

    Ok(())
}

pub fn receive_packets(
    rx: Receiver<ParsedPacket>,
    shared_data: Arc<SharedData>,
    end: Arc<SharedEnd>,
) -> Result<(), Error> {
    print_headers();

    thread::Builder::new()
        .name("RECEIVER".to_string())
        .spawn(move || loop {


            let result = rx.recv();


            let packet = match result {
                Ok(packet) => packet,
                Err(error) => {
                    {
                        eprintln!("{}", error.to_string());
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        end.cv.notify_all();
                    }
                    panic!("RECEIVE PACKETS PANICKED!");
                }
            };

            let mut guard = shared_data.m.map.lock().unwrap();

            /*let addr_pair = match get_addr(&packet) {
                Ok(addr_pair) => addr_pair,
                Err(error) => {
                    //return Err(error);
                }
            };*/

            let addr_pair = get_addr(&packet);

            match guard.get_mut(&addr_pair) {
                Some(v) => {
                    v.add_to_bytes(packet.get_len());
                    v.set_end_ts(packet.get_ts().to_string())
                }
                None => {
                    guard.insert(
                        addr_pair,
                        value::new(
                            packet.get_len(),
                            packet.get_ts().to_string(),
                            packet.get_ts().to_string(),
                            packet.get_protocol().to_string(),
                        ),
                    );
                }
            }

            {
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    end.cv.notify_all();
                    break;
                }
            }

            show_to_console(&packet);



            /*let mut propagation = false;

            {
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    propagation = true;
                    end.cv.notify_all();
                }
            }

            if propagation {
                panic!("RECEIVE PACKETS PANICKED DUE TO PANIC PROPAGATION!");
            }*/

            /*{
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    end.cv.notify_all();
                    break;
                }
            }*/
        })
        .unwrap();

    Ok(())
}

pub fn get_addr(parsed_packet: &ParsedPacket) -> key {
    let mut addr_pair: key = key::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
        0,
    );

    let headers = parsed_packet.get_headers();

    let mut src_port = 0;
    let mut dst_port = 0;

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
            addr_pair = key::new(
                IpAddr::V4(packet.source_addr),
                IpAddr::V4(packet.dest_addr),
                src_port,
                dst_port,
            );
        }
        PacketHeader::Ipv6(packet) => {
            addr_pair = key::new(
                IpAddr::V6(packet.source_addr),
                IpAddr::V6(packet.dest_addr),
                src_port,
                dst_port,
            );
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
        //"{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}",
        "{0: <40} | {1: <10} | {2: <40} | {3: <10} | {4: <10} | {5: <10} | {6: <35}",
        src_addr, src_port, dst_addr, dst_port, protocol, length, ts
    );
}

pub fn get_packet_meta(parsed_packet: &ParsedPacket) -> (String, String, String, String) {
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
        //"{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
        "{0: <40} | {1: <10} | {2: <40} | {3: <10} | {4: <10} | {5: <10} | {6: <35} |",
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
