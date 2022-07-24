use std::net::IpAddr;
use pcap::Device;
use crate::parser::{PacketHeader, ParsedPacket};

pub struct Sniffer {}

impl Sniffer {
    pub fn new() -> Sniffer {
        Sniffer {}
    }

    pub fn list_devices(&self) -> Vec<Device> {

        let mut devices: Vec<Device> = vec![];
        devices = Device::list().unwrap();

        for (index, device) in devices.iter().enumerate() {
            println!("Device #{} | Name: {} | Description: {}", index, device.name, device.desc.as_ref().unwrap());
        }

        devices
    }

    pub fn sniff(&self, device: Device) {

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
                    self.show_to_console(&parsed_packet);
                },
                Err(err) => {
                    println!("ERROR : {}", err);
                }
            }
        }
    }

    pub fn get_packet_meta(&self, parsed_packet: &ParsedPacket) -> (String, String, String, String) {
        let mut src_addr = "".to_string();
        let mut dst_addr = "".to_string();
        let mut src_port = "".to_string();
        let mut dst_port = "".to_string();

        let headers = parsed_packet.get_headers();

        headers.iter().for_each(|h| {

            match h {
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
                },
                _ => {}
            }
        });

        (src_addr, dst_addr, src_port, dst_port)

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
        let protocol = &parsed_packet.get_headers()[0].to_string();
        let length = &parsed_packet.get_len();
        let ts = &parsed_packet.get_ts();
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}",
            src_addr, src_port, dst_addr, dst_port, protocol, length, ts
        );
    }

}
