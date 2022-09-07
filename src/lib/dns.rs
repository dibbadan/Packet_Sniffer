#[derive(Debug)]
pub struct DnsPacket {
    _questions: Vec<String>,
    _answers: Vec<String>,
}

impl From<dns_parser::Packet<'_>> for DnsPacket {
    fn from(dns_packet: dns_parser::Packet) -> Self {
        let questions: Vec<String> = dns_packet
            .questions
            .iter()
            .map(|q| q.qname.to_string())
            .collect();

        let answers: Vec<String> = dns_packet
            .answers
            .iter()
            .map(|a| a.name.to_string())
            .collect();

        Self { _questions: questions, _answers: answers }
    }
}
