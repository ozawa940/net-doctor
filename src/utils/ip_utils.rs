use std::net::IpAddr;

use pnet::datalink::NetworkInterface;


/**
 * Get Ip from network interface
 */
pub fn get_ip_from_nic(nic: &NetworkInterface) -> IpAddr {
    nic.clone().ips.into_iter()
        .filter(|ip| ip.is_ipv4())
        .next()
        .unwrap()
        .ip()
}