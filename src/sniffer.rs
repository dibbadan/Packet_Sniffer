use std::borrow::BorrowMut;
use crate::parser::{PacketHeader, ParsedPacket};
use colored::Colorize;
use pcap::Device;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::{fmt, thread};
use serde::ser::SerializeMap;
use serde_json::Error;

const MAX_THREADS: usize = 10;

#[derive(Debug, Clone)]
struct MapData {
    map: HashMap<key, (u32, String, String)>,
}
/*struct MapData {
    map: HashMap<(IpAddr, IpAddr), (u32, String, String)>,
}*/


#[derive(Clone, Hash, Debug, Eq, PartialEq)]
struct key(IpAddr, IpAddr);

impl Display for key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.0.to_string(), self.1.to_string())
    }
}

impl Serialize for key {

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {

        serializer.serialize_str(&format!("{}-{}", self.0.to_string(), self.1.to_string()))

    }
}


impl MapData {
    pub fn new() -> Self {
        MapData {
            map: HashMap::<key, (u32, String, String)>::new(),
        }
        /*MapData {
            map: HashMap::<(IpAddr, IpAddr), (u32, String, String)>::new(),
        }*/
    }
}




pub struct Sniffer {
    m: Mutex<MapData>,
    cv: Condvar,
}

impl Sniffer {
    
    pub fn new() -> Self {
        Sniffer {
            m: Mutex::new(MapData::new()),
            cv: Condvar::new(),
        }
    }

    pub fn list_devices(&self) -> Vec<Device> {
        let mut devices: Vec<Device> = vec![];
        devices = Device::list().unwrap();

        println!("\n");

        for (index, device) in devices.iter().enumerate() {
            println!(
                "Device #{} | Name: {} | Description: {}",
                index,
                device.name,
                device.desc.as_ref().unwrap()
            );
        }

        devices
    }

    pub fn sniff(&mut self, device: Device) {
        
        let (tx, rx): (Sender<ParsedPacket>, Receiver<ParsedPacket>) = mpsc::channel();
        let cap_handle = Arc::new(Mutex::new(device.open().unwrap()));
        let parser = ParsedPacket::new();

        let mut data:Vec<u8> = vec![];
        let mut len = 0;
        let mut ts = "".to_string();
        let mut handlers = vec![];

        for i in 0..1 {
            
            let parser = parser.clone();
            let tx = tx.clone();
            let cap_handle = cap_handle.clone();
            let mut data = data.clone();
            //let mut len = 0;
            let mut ts = ts.clone();

            let mut j = 0;

            handlers.push(thread::spawn(move || loop {

                let mut cap_handle = cap_handle.lock().unwrap();
                let mut packet = cap_handle.next();


                if let Ok(packet) = packet {
                    j+=1;
                    data = packet.data.to_owned();
                    len = packet.header.len;
                    ts = format!(
                        "{}.{:06}",
                        &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
                    );

                    let parsed_packet = parser.parse_packet(data, len, ts);

                    match parsed_packet {
                        Ok(parsed_packet) => {
                            println!(
                                "{}",
                                format!("Thread {i} is sending packet to channel!").cyan()
                            );
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

                if j==5 {
                    break;
                }

            }));


       }

        drop(tx);

        println!("\n");
        self.print_headers();

        for parsed_packet in rx.iter() {

            let addr_pair = self.get_addr(&parsed_packet);
            let mut guard = self.m.lock().unwrap();

            match guard.map.get_mut(&addr_pair) {
                Some(v) => {
                    v.0 += parsed_packet.get_len();
                    v.2 = parsed_packet.get_ts().to_string();
                }
                None => {
                    guard.map.insert(
                        addr_pair,
                        (
                            parsed_packet.get_len(),
                            parsed_packet.get_ts().to_string(),
                            parsed_packet.get_ts().to_string(),
                        ),
                    );
                }
            }

            self.show_to_console(&parsed_packet);



            /*match parsed_packet {
                Ok(parsed_packet) => {

                    let addr_pair = self.get_addr(&parsed_packet);
                    let mut guard = self.m.lock().unwrap();

                    match guard.map.get_mut(&addr_pair) {
                        Some(v) => {
                            v.0 += parsed_packet.get_len();
                            v.2 = parsed_packet.get_ts().to_string();
                        }
                        None => {
                            guard.map.insert(
                                addr_pair,
                                (
                                    parsed_packet.get_len(),
                                    parsed_packet.get_ts().to_string(),
                                    parsed_packet.get_ts().to_string(),
                                ),
                            );
                        }
                    }

                    self.show_to_console(&parsed_packet);
                }
                Err(err) => {
                    println!("ERROR : {}", err);
                }
            }*/

        }

        self.generate_report("report.txt").unwrap();
        // self.generate_report(Path::new("report.txt")).unwrap();
    }

    pub fn generate_report(&self, path:&str) -> Result<(), Error> {
        let mut guard = self.m.lock().unwrap();
        let mut file = File::create(path).unwrap();


        // TODO : Write headers information to file!


        // Convert the MapData struct to a JSON string.
        let json_string = serde_json::to_string(&guard.map).expect("Error in seralizing the data structure!");
        file.write_all(json_string.as_bytes()).unwrap();

        Ok(())
    }

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

    //pub fn get_addr(&self, parsed_packet: &ParsedPacket) -> (IpAddr, IpAddr) {
    pub fn get_addr(&self, parsed_packet: &ParsedPacket) -> key {
        /*let mut addr_pair: (IpAddr, IpAddr) = (
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        );*/

        let mut addr_pair: key = (
            key(IpAddr::V4(Ipv4Addr::new(0,0,0,0)),IpAddr::V4(Ipv4Addr::new(0,0,0,0)))
        );



        let headers = parsed_packet.get_headers();

        headers.iter().for_each(|h| match h {
            PacketHeader::Ipv4(packet) => {
                //addr_pair = (IpAddr::V4(packet.source_addr), IpAddr::V4(packet.dest_addr));
                addr_pair.0 = IpAddr::V4(packet.source_addr);
                addr_pair.1 = IpAddr::V4(packet.dest_addr);
            }
            PacketHeader::Ipv6(packet) => {
                //addr_pair = (IpAddr::V6(packet.source_addr), IpAddr::V6(packet.dest_addr));
                addr_pair.0 = IpAddr::V6(packet.source_addr);
                addr_pair.1 = IpAddr::V6(packet.dest_addr);
            }
            _ => {}
        });

        addr_pair
    }

    /*pub fn show_map(&self) {
        println!("\n");
        println!("{:?}", self.map);
        println!("\n");
    }*/
}

/*self.print_headers();
let mut i = 0;
self.print_headers();

let mut cap_handle = device.open().unwrap();
while let Ok(packet) = cap_handle.next() {
    let data = packet.data.to_owned();
    let len = packet.header.len;
    let ts: String = format!(
        "{}.{:06}",
        &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
    );

    let parser = ParsedPacket::new();
    let parsed_packet = parser.parse_packet(data, len, ts);
    match parsed_packet {
        Ok(parsed_packet) => {
            let addr_pair = self.get_addr(&parsed_packet);
            match self.map.get_mut(&addr_pair) {
                Some(v) => {
                    v.0 += parsed_packet.get_len();
                    v.2 = parsed_packet.get_ts().to_string();
                }
                None => {
                    self.map.insert(
                        addr_pair,
                        (
                            parsed_packet.get_len(),
                            parsed_packet.get_ts().to_string(),
                            parsed_packet.get_ts().to_string(),
                        ),
                    );
                }
            }
            self.show_to_console(&parsed_packet);
        }
        Err(err) => {
            println!("ERROR : {}", err);
        }
    }
    i += 1;
    if i == 10 {
        break;
    }
}*/
