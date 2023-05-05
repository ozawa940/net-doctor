use std::{net::{Ipv4Addr, IpAddr}, str::FromStr, vec, time::Duration};
use log::error;
use log::debug;

use pnet::{transport::{transport_channel, udp_packet_iter}, packet::{ip::IpNextHeaderProtocols, udp::{MutableUdpPacket, ipv4_checksum}, ipv4::{MutableIpv4Packet, Ipv4Packet}, Packet}};
use rand::Rng;

use crate::{types::DnsConfig, utils::{os_utils::get_active_interface, ip_utils::get_ip_from_nic}};

use super::types::{dns_packet::{DnsPacket, DnsHeader, DnsQueryData}};

const MAX_PACKET_SIZE: usize = 36;
const DNS_SERVER: &str = "8.8.8.8";

/**
 * Check Dns
 */
pub fn dns(config: DnsConfig) {

    let mut dns_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE];

    let mut dns_packet = DnsPacket::new();
    make_dns_packet(&mut dns_packet, &config.domain);

    debug!("DNS: dns_packet {:?}", &dns_packet);

    let mut ip_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE + 20];
    let mut ip_packet: MutableIpv4Packet = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    make_ip_packet(&mut ip_packet);

    let interface = get_active_interface(&config.interface_name); 
    let src_ip = Ipv4Addr::from_str(get_ip_from_nic(&interface).to_string().as_str()).unwrap();
    let dest_ip = Ipv4Addr::from_str(DNS_SERVER).unwrap();

    debug!("DNS: src {:?} dest {:?}", &src_ip, &dest_ip);
    let mut udp_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE];
    let mut udp_packet: MutableUdpPacket = MutableUdpPacket::new(&mut udp_buff).unwrap();
    make_udp_packet(&mut udp_packet);

    udp_packet.set_payload(dns_packet.packet());
    debug!("DNS: ip {:?}", &src_ip);
    udp_packet.set_checksum(ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dest_ip));
    debug!("DNS: udp_packet {:?}", &udp_packet);

    ip_packet.set_payload(udp_packet.packet());

    let (mut tx, mut rx) = transport_channel(512, pnet::transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Udp)).unwrap();
    let mut rx = udp_packet_iter(&mut rx);

    let send_packet = Ipv4Packet::new(&ip_packet.packet()).unwrap();
    debug!("DNS: send_packet {:?}", &send_packet);
    tx.send_to(send_packet, IpAddr::V4(ip_packet.get_destination())).unwrap();

    match rx.next_with_timeout(Duration::from_millis(5000)) {
        Ok(ip_response) => {
            debug!("DNS: ip_response {:?}", ip_response);
            let tmp_p = ip_response.unwrap_or_else(|| {
                error!("DNS: Error");
                panic!();
            });
            let res_packet = Ipv4Packet::new(tmp_p.0.packet()).unwrap();
            debug!("DNS: res_packet {:?}", &res_packet);
        }
        Err(e) => {
            error!("DNS: {:?}", e);
            panic!("{:?}", e);
        }
    }
}

/**
 * Set param to dsn packet
 */
fn make_dns_packet(packet: &mut DnsPacket, domain: &str) {
    let id = rand::thread_rng().gen();
    packet.transaction_id = id;

    let header = DnsHeader {
        qr_code: 0,
        ope_code: 0,
        trunc: 0,
        recursion: 1,
        z_code: 0,
        dns_sec: 1,
        auth_code: 0
    };
    packet.flags = header;
    packet.question_count = 1;
    packet.answer_count = 0;
    packet.authority_count = 0;
    packet.additional_count = 0;
    packet.query = DnsQueryData {
        name: domain.to_string(),
        dns_type: 1,
        dns_class: 1
    }
}

/**
 * Set param to udp packet
 */
fn make_udp_packet(packet: &mut MutableUdpPacket) {
    let port = rand::thread_rng().gen();
    packet.set_length(packet.packet().len() as u16);
    packet.set_source(port);
    packet.set_destination(53);
}

/**
 * Set param to ip packet
 */
fn make_ip_packet(packet: &mut MutableIpv4Packet) {
    let id = rand::thread_rng().gen();
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(packet.packet().len() as u16);
    packet.set_identification(id);
    packet.set_ttl(64);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    packet.set_destination(Ipv4Addr::from_str(DNS_SERVER).unwrap());
}