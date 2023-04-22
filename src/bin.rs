use std::env;

use clap::{Parser, Subcommand};
use log::info;
use types::BaseConfig;
use env_logger;

mod types;
mod ping;

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
    }
}