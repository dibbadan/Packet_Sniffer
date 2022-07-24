use crate::sniffer::Sniffer;

mod sniffer;
mod parser;


fn main() {
    let sniffer = Sniffer::new();
    let _devices = sniffer.list_devices();
    sniffer.sniff(_devices[0].clone());
}
