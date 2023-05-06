use clap::builder::Str;


/**
 * Command base config
 */
pub struct BaseConfig {
    pub ip: String
}

/**
 * Arp config
 */
pub struct ArpConfig {
    pub dest_ip: String,
    pub interface_name: String
}

pub struct DnsConfig {
    pub domain: String,
    pub interface_name: String
}

pub struct EchoConfig {
    pub ip: String,
    pub interface_name: String
}