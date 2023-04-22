use std::env;

use clap::{Parser, Subcommand};
use log::info;
use types::BaseConfig;
use env_logger;
use network::ping;

use crate::{network::arp, types::ArpConfig};

/**
 * Modules
 */
mod utils;
mod types;
mod network;


#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Command
    #[command(subcommand)]
    cmd: Command, 
    /// log level = debug, info, warn, error
    #[arg(short, long, default_value_t = String::from("info"))]
    log_level: String,
}

#[allow(unused, non_camel_case_types)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Check ping
    ping {
        /// Target ip
        ip: String
    },
    /// Check Arp
    arp {
        /// dest_ip is used by finding mac address
        dest_ip: String,
        /// Network interface name
        interface_name: String
    }
}

fn main() {
    let args = Args::parse();

    env::set_var("RUST_LOG", args.log_level.as_str());
    env_logger::init();

    info!("Args : {:?}", &args.cmd);

    // Command
    match &args.cmd {
        Command::ping { ip } => { 
            let config = BaseConfig { ip: ip.to_string() };
            ping::ping(config)
        }
        Command::arp { dest_ip , interface_name } => {
            let config = ArpConfig 
                { dest_ip: dest_ip.to_string(), interface_name: interface_name.to_string() };
            arp::arp(config);
        }
    }
}