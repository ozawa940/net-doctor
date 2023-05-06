use std::{net::{Ipv4Addr, IpAddr, UdpSocket, SocketAddr, SocketAddrV4}, str::FromStr, vec, time::Duration};
use log::{error, info};
use log::debug;

use pnet::{transport::{transport_channel, udp_packet_iter, ipv4_packet_iter}, packet::{ip::IpNextHeaderProtocols, udp::{MutableUdpPacket, ipv4_checksum, UdpPacket}, ipv4::{MutableIpv4Packet, Ipv4Packet}, Packet}, datalink::{channel, Channel}};
use rand::Rng;

use crate::{types::DnsConfig, utils::{os_utils::get_active_interface, ip_utils::get_ip_from_nic}};

use super::types::{dns_packet::{DnsPacket, DnsHeader, DnsQueryData}};

const MAX_PACKET_SIZE: usize = 64;
const DNS_SERVER: &str = "8.8.8.8";
const DNS_TIMEOUT: u64 = 3000;
const DNS_PORT: u16 = 53;

/**
 * Check Dns
 */
pub fn dns(config: DnsConfig) {

    let interface = get_active_interface(&config.interface_name); 
    let src_str_ip = get_ip_from_nic(&interface).to_string(); 
    let dest_ip = Ipv4Addr::from_str(DNS_SERVER).unwrap();

    let mut dns_packet = DnsPacket::new();
    make_dns_packet(&mut dns_packet, &config.domain);
    dns_packet.make_packet();

    debug!("DNS: dns_packet {:?}", &dns_packet);

    let bind_port: u16 = rand::thread_rng().gen();
    let bind_addr = src_str_ip + ":" + bind_port.to_string().as_str();
    let socket = UdpSocket::bind(bind_addr).unwrap();

    let mut is_reach = false;

    socket.set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT)));
    loop {
        let send_packet = Ipv4Packet::new(dns_packet.packet()).unwrap();
        debug!("DNS: send_packet: {:?}", &send_packet);
        let addr = SocketAddr::V4(SocketAddrV4::new(dest_ip, DNS_PORT));
        socket.send_to(send_packet.packet(), addr).unwrap();
        let mut res_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE * 2];
        match socket.recv_from(&mut res_buff) {
            Ok(_) => {
                match DnsPacket::get_answar(res_buff) {
                    Some(ans) => {
                        for a in ans {
                            info!("DNS: answer name={} addr={}", a.name, a.address);
                            break;
                        }
                    }
                    None => {
                        error!("DNS: no answer");
                        break;
                    }
                };
                is_reach = true;
            }
            Err(e) => {
                error!("DNS: {:?}", e);
                panic!("{:?}", e);
            }

        };

        if is_reach {
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));

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