use crate::lib::dns::DnsPacket;
use pktparse::ethernet::{EtherType, EthernetFrame};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::IPv4Header;
use pktparse::ipv6::IPv6Header;
use pktparse::tcp::TcpHeader;
use pktparse::udp::UdpHeader;
use pktparse::*;
use std::string::ToString;

#[derive(Debug)]
pub enum PacketHeader {
    Ethernet(EthernetFrame),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Dns(DnsPacket),
}

impl ToString for PacketHeader {
    fn to_string(&self) -> String {
        match self {
            PacketHeader::Ethernet(_) => String::from("Ethernet"),
            PacketHeader::Ipv4(_) => String::from("Ipv4"),
            PacketHeader::Ipv6(_) => String::from("Ipv6"),
            PacketHeader::Tcp(_) => String::from("Tcp"),
            PacketHeader::Udp(_) => String::from("Udp"),
            PacketHeader::Dns(_) => String::from("Dns"),
        }
    }
}

#[derive(Debug)]
pub struct ParsedPacket {
    len: u32,
    timestamp: String,
    headers: Vec<PacketHeader>,
    remaining: Vec<u8>,
}

impl ParsedPacket {
    pub fn new() -> ParsedPacket {
        ParsedPacket {
            len: 0,
            timestamp: "".to_string(),
            headers: vec![],
            remaining: vec![],
        }
    }

    pub fn get_len(&self) -> u32 {
        self.len
    }

    pub fn get_ts(&self) -> &String {
        &self.timestamp
    }

    pub fn get_protocol(&self) -> String {
        let mut protocol = "".to_string();

        self.headers.iter().for_each(|h| match h {
            PacketHeader::Tcp(_packet) => {
                protocol = "TCP".to_string();
            }
            PacketHeader::Udp(_packet) => {
                protocol = "UDP".to_string();
            }
            _ => {}
        });

        protocol
    }

    pub fn get_headers(&self) -> &Vec<PacketHeader> {
        &self.headers
    }

    pub fn parse_packet(
        &self,
        data: Vec<u8>,
        len: u32,
        ts: String,
    ) -> Result<ParsedPacket, String> {

        let mut parsed_packet = match self.parse_link_layer(&data) {
            Ok(parsed_packet) => parsed_packet,
            Err(error) => return Err(error)
        };

        parsed_packet.len = len;
        parsed_packet.timestamp = ts;
        Ok(parsed_packet)
    }

    pub fn parse_link_layer(&self, content: &[u8]) -> Result<ParsedPacket, String> {

        let mut parsed_packet = ParsedPacket::new();

        match ethernet::parse_ethernet_frame(content) {
            Ok((content, headers)) => {

                match headers.ethertype {
                    EtherType::IPv4 => {
                        self.parse_ipv4(content, &mut parsed_packet)?;
                    }
                    EtherType::IPv6 => {
                        self.parse_ipv6(content, &mut parsed_packet)?;
                    }
                    _ => {
                        parsed_packet.remaining = content.to_owned();
                    }
                }

                parsed_packet.headers.push(PacketHeader::Ethernet(headers));
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
            }
        }

        Ok(parsed_packet)
    }

    pub fn parse_ipv4(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match ipv4::parse_ipv4_header(content) {
            Ok((content, ipv4_header)) => {
                match self.parse_transport_layer(&ipv4_header.protocol, content, parsed_packet) {
                    Ok(()) => {
                        parsed_packet.headers.push(PacketHeader::Ipv4(ipv4_header));
                        Ok(())
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(_error) => {
                parsed_packet.remaining = content.to_owned();
                //Err("Error parsing IPv4Header".to_string())
                Ok(())
            }
        }
    }

    pub fn parse_ipv6(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match ipv6::parse_ipv6_header(content) {
            Ok((content, ipv6_header)) => {
                match self.parse_transport_layer(&ipv6_header.next_header, content, parsed_packet) {
                    Ok(()) => {
                        parsed_packet.headers.push(PacketHeader::Ipv6(ipv6_header));
                        Ok(())
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(_error) => {
                parsed_packet.remaining = content.to_owned();
                Ok(())
                //Err("Error parsing IPv6Header".to_string())
            }
        }
    }

    pub fn parse_transport_layer(
        &self,
        protocol_type: &IPProtocol,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match protocol_type {
            IPProtocol::TCP => {
                match self.parse_tcp(content, parsed_packet) {
                    Ok(()) => Ok(()),
                    Err(error) => return Err(error)
                }
            }
            IPProtocol::UDP => {
                match self.parse_udp(content, parsed_packet) {
                    Ok(()) => Ok(()),
                    Err(error) => return Err(error)
                }
            }
            _ => {
                parsed_packet.remaining = content.to_owned();
                Ok(())
                //Err("Error parsing transport layer".to_string())
            }
        }
    }

    pub fn parse_tcp(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match tcp::parse_tcp_header(content) {
            Ok((_content, tcp_header)) => {
                parsed_packet.headers.push(PacketHeader::Tcp(tcp_header));
                Ok(())
            }
            Err(_err) => {
                parsed_packet.remaining = content.to_owned();
                Ok(())
                //Err("Error parsing TCP".to_string())
            }
        }
    }

    pub fn parse_udp(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match udp::parse_udp_header(content) {
            Ok((content, udp_header)) => {

                match self.parse_dns(content, parsed_packet) {
                    Ok(()) => (),
                    Err(error) => ()
                }

                parsed_packet.headers.push(PacketHeader::Udp(udp_header));
                Ok(())

            }
            Err(_error) => {
                parsed_packet.remaining = content.to_owned();
                Ok(())
                //Err("Error parsing UDP".to_string())
            }
        }
    }

    fn parse_dns(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(), String> {
        match dns_parser::Packet::parse(content) {
            Ok(packet) => {
                parsed_packet
                    .headers
                    .push(PacketHeader::Dns(DnsPacket::from(packet)));
                Ok(())
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
                Ok(())
                //Err("Error parsing DNS".to_string())
            }
        }
    }
}
