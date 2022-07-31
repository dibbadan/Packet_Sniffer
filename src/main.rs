mod cli;
use cli::Cli;
use clap::Parser;

fn main() {

    let cli = Cli::parse();

    let _passed_args = Cli::show_passed_args(&cli);
    //println!("PASSED ARGUMENTS = {:?}", passed_args);

    //let mut sniffer = Sniffer::new();

    /*
    let _devices = sniffer.list_devices();
    sniffer.sniff(_devices[0].clone());
    sniffer.show_map();*/
}
