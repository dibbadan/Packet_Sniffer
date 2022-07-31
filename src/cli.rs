use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "Network Packets Sniffer")]
#[clap(author = "Student_1, Student_2, Student_3")]
#[clap(version = "1.0")]
#[clap(about = "Simple network packets sniffer", long_about = None)]
pub struct Cli {
    /// The network device to sniff on
    #[clap(short = 'd', long = "device")]
    device_id:u8,
    /// Time interval ( in seconds ) after wich a new report will be generated
    #[clap(short = 'i', long = "interval")]
    interval:u32,
    /// Report file to be generated
    #[clap(short = 'o', long = "output")]
    report:String
}

impl Cli {
    pub fn show_passed_args(&self) -> (u8, u32, &str) {
        (self.device_id, self.interval, &self.report)
    }
}