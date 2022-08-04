use pcap::{Error, Packet};
use pktparse::arp::ArpPacket;
use pktparse::ethernet::{EtherType, EthernetFrame};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::IPv4Header;
use pktparse::ipv6::IPv6Header;
use pktparse::tcp::TcpHeader;
use pktparse::udp::UdpHeader;
use pktparse::*;
use std::string::ToString;



#[derive(Debug, Clone)]
pub enum PacketHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ethernet(EthernetFrame),
}

impl ToString for PacketHeader {
    fn to_string(&self) -> String {
        match self {
            PacketHeader::Ipv4(_) => String::from("Ipv4"),
            PacketHeader::Ipv6(_) => String::from("Ipv6"),
            PacketHeader::Tcp(_) => String::from("Tcp"),
            PacketHeader::Udp(_) => String::from("Udp"),
            PacketHeader::Ethernet(_) => String::from("Ether"),
        }
    }
}

#[derive(Debug, Clone)]
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

    pub fn get_headers(&self) -> &Vec<PacketHeader> {
        &self.headers
    }

    pub fn parse_packet(
        &self,
        data: Vec<u8>,
        len: u32,
        ts: String,
    ) -> Result<ParsedPacket, String> {
        let mut parsed_packet = self.parse_link_layer(&data)?;
        parsed_packet.len = len;
        parsed_packet.timestamp = ts.to_string();
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
                    /*EtherType::ARP => {
                        self.parse_arp(content, &mut parsed_packet)?;
                    }*/
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
            Ok((content, IPv4Header)) => {
                self.parse_transport_layer(&IPv4Header.protocol, content, parsed_packet)?;
                parsed_packet.headers.push(PacketHeader::Ipv4(IPv4Header));
                Ok(())
            }
            Err(err) => {
                parsed_packet.remaining = content.to_owned();
                Err("Error".to_string())
            }
        }
    }

    pub fn parse_ipv6(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match ipv6::parse_ipv6_header(content) {
            Ok((content, IPv6Header)) => {
                self.parse_transport_layer(&IPv6Header.next_header, content, parsed_packet)?;
                parsed_packet.headers.push(PacketHeader::Ipv6(IPv6Header));
                Ok(())
            }
            Err(err) => {
                parsed_packet.remaining = content.to_owned();
                Err("Error".to_string())
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
                self.parse_tcp(content, parsed_packet);
                Ok(())
            }
            IPProtocol::UDP => {
                self.parse_udp(content, parsed_packet);
                Ok(())
            }
            _ => {
                parsed_packet.remaining = content.to_owned();
                Err("Error parsing Transport Layer".to_string())
            }
        }
    }

    pub fn parse_tcp(
        &self,
        content: &[u8],
        parsed_packet: &mut ParsedPacket,
    ) -> Result<(), String> {
        match tcp::parse_tcp_header(content) {
            Ok((content, tcp_header)) => {
                parsed_packet.headers.push(PacketHeader::Tcp(tcp_header));
                Ok(())
            }
            Err(err) => {
                parsed_packet.remaining = content.to_owned();
                Err("Error parsing TCP".to_string())
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
                parsed_packet.headers.push(PacketHeader::Udp(udp_header));
                Ok(())
            }
            Err(err) => {
                parsed_packet.remaining = content.to_owned();
                Err("Error parsing UDP".to_string())
            }
        }
    }
}
