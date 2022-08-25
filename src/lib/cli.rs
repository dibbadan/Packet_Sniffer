use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "Network Packets Sniffer")]
#[clap(author = "Student_1, Student_2, Student_3")]
#[clap(version = "1.0")]
#[clap(
    about = "Simple network packets sniffer",
    long_about = "TODO specific info about the limits of the library and its correct use"
)]

pub struct Cli {
    /// Time interval ( in seconds ) after which a new report will be generated; Default is 10
    #[clap(short = 'i', long = "interval")]
    interval: Option<u64>,
    /// Report file to be generated; Default is report.txt
    #[clap(short = 'o', long = "output")]
    report: Option<String>,
}

impl Cli {
    pub fn get_parameters(self) -> (u64, String) {
        (
            match self.interval {
                Some(s) => s,
                None => 10,
            },
            match self.report {
                Some(s) => s,
                None => "report.txt".to_string(),
            },
        )
    }
}
