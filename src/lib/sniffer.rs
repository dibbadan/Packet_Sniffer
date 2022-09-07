use crate::lib::parser::{PacketHeader, ParsedPacket};
use crate::lib::shared_data::{Key, Value, SharedData, SharedPause};
use crate::lib::{executor::task, inputs};
use crate::shared_data::SharedEnd;
use pcap::Error::TimeoutExpired;
use pcap::{Capture, Device, Error};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc};
use std::{panic, thread};

pub fn list_devices() -> Result<Vec<Device>, Error> {
    let devices = match Device::list() {
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


    match get_packets(tx, device, pause_clone, end_clone1) {
        Ok(()) => (),
        Err(error) => return Err(error)
    }

    receive_packets(rx, mappa_clone, end_clone2);

    tokio::spawn(async move {
        task(interval, report_file, mappa, pausa_clone_task, end_clone3).await;
    });

    match inputs::get_commands(pause, end) {
        Ok(()) => (),
        Err(error) => return Err(error)
    }

    Ok(())
}

pub fn get_packets(
    tx: Sender<ParsedPacket>,
    device: Device,
    pause: Arc<SharedPause>,
    end: Arc<SharedEnd>,
) -> Result<(), Error> {

    let mut cap_handle = match Capture::from_device(device) {
        Ok(capture) => match capture.promisc(true)
            .timeout(1000).open() {
            Ok(cap_handle) => cap_handle,
            Err(error) => {
                return Err(error);
            }
        },
        Err(error) => {
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

            let packet = match cap_handle.next() {

                Ok(packet) => packet,

                Err(error) => match error {
                    TimeoutExpired => {
                        continue;
                    }
                    _ => {
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        end.cv.notify_all();
                        panic!("Problema riscontrato durante lo sniffing dei pacchetti!");
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
                        match tx.send(parsed_packet) {
                            Ok(()) => {}
                            Err(_error) => {
                                {
                                    let mut guard = end.lock.lock().unwrap();
                                    guard.terminated += 1;
                                    end.cv.notify_all();
                                }
                                panic!("Errore interno!");
                            }
                        }
                    }
                    Err(_error) => {
                        println!("ERRORE = {}", _error);
                        {
                            let mut guard = end.lock.lock().unwrap();
                            guard.terminated += 1;
                            end.cv.notify_all();
                        }
                        panic!("Errore nel parsing del pacchetto!");
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
) {

    print_headers();

    thread::Builder::new()
        .name("RECEIVER".to_string())
        .spawn(move || loop {


            let result = rx.recv();

            {
                let mut guard = end.lock.lock().unwrap();
                if guard.terminated > 0 {
                    guard.terminated += 1;
                    end.cv.notify_all();
                    break;
                }
            }


            let packet = match result {
                Ok(packet) => packet,
                Err(_error) => {
                    {
                        let mut guard = end.lock.lock().unwrap();
                        guard.terminated += 1;
                        end.cv.notify_all();
                    }
                    panic!("Errore interno!");
                }
            };

            let mut guard = shared_data.m.map.lock().unwrap();

            let addr_pair = get_addr(&packet);

            match guard.get_mut(&addr_pair) {
                Some(v) => {
                    v.add_to_bytes(packet.get_len());
                    v.set_end_ts(packet.get_ts().to_string())
                }
                None => {
                    guard.insert(
                        addr_pair,
                        Value::new(
                            packet.get_len(),
                            packet.get_ts().to_string(),
                            packet.get_ts().to_string(),
                            packet.get_protocol().to_string(),
                        ),
                    );
                }
            }



            show_to_console(&packet);

        })
        .unwrap();

}

pub fn get_addr(parsed_packet: &ParsedPacket) -> Key {

    let mut addr_pair: Key = Key::new(
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
            addr_pair = Key::new(
                IpAddr::V4(packet.source_addr),
                IpAddr::V4(packet.dest_addr),
                src_port,
                dst_port,
            );
        }
        PacketHeader::Ipv6(packet) => {
            addr_pair = Key::new(
                IpAddr::V6(packet.source_addr),
                IpAddr::V6(packet.dest_addr),
                src_port,
                dst_port,
            );
        }
        _ => {}
    });

    addr_pair
}

pub fn show_to_console(parsed_packet: &ParsedPacket) {
    let (src_addr, src_port, dst_addr, dst_port) = get_packet_meta(&parsed_packet);
    let protocol = &parsed_packet.get_headers()[0].to_string(); // Transport layer protocol (TCP or UDP)
    let length = &parsed_packet.get_len();
    let ts = &parsed_packet.get_ts();
    println!(
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
        "{0: <40} | {1: <10} | {2: <40} | {3: <10} | {4: <10} | {5: <10} | {6: <35} |",
        "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Timestamp"
    );
    println!("{:-^1$}", "-", 165,);
}
