extern crate pnet;

use log::debug;
use log::error;
use log::info;
use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::checksum;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::time_exceeded;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::transport::ipv4_packet_iter;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType;
use rand::Rng;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use crate::types::BaseConfig;

const MAX_PACKET_SIZE: usize = 44;

/**
 * Send icmp packet
 */
pub fn ping(config: BaseConfig) {

    // Create icmp packet
    let mut icmp_buf: Vec<u8> = vec![0; MAX_PACKET_SIZE];
    let mut icmp_packet: MutableEchoRequestPacket = MutableEchoRequestPacket::new(&mut icmp_buf).unwrap();
    make_icmp_packet(&mut icmp_packet);

    // Send icmp packet, and receive packet
    let (mut tx, mut rx) = transport_channel(512,
             TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)).unwrap();
    let mut rx = ipv4_packet_iter(&mut rx);

    // Receive packet
    let mut is_reach = false;

    // Create Ipv4 packet
    let mut ip_buf: Vec<u8> = vec![0; MAX_PACKET_SIZE * 2];
    let mut ip_packet: MutableIpv4Packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    make_ip_packet(&mut ip_packet, &config);
    ip_packet.set_payload(&icmp_packet.packet());

    loop {

        ip_packet.set_ttl(ip_packet.get_ttl() + 1);
        let src_ip = ip_packet.get_source();
        let dest_ip = ip_packet.get_destination();

        let send_packet = Ipv4Packet::new(&ip_packet.packet()).unwrap();
        tx.send_to(send_packet, IpAddr::V4(dest_ip)).unwrap();

        match rx.next_with_timeout(Duration::from_millis(3000)) {
            Ok(ip_response) => {
                // Check icmp response
                let tmp_p = ip_response.unwrap_or_else(|| {
                    error!("Icmp: send Timeout");
                    panic!();
                });

                let res_packet = Ipv4Packet::new(tmp_p.0.packet()).unwrap();
                debug!("Icmp: res_packet {:?}", &res_packet);
                match res_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Icmp => {
                        let res_icmp_packet = EchoReplyPacket::new(&mut res_packet.payload()).unwrap();
                        debug!("Icmp: res_icmp_packet {:?}", &res_icmp_packet);
                        match res_icmp_packet.get_icmp_type() {
                            IcmpTypes::EchoReply => {
                                debug!("Icmp: Reach from {} to {}", res_packet.get_source(), res_packet.get_destination());
                                is_reach = true;
                            }
                            IcmpTypes::TimeExceeded => match res_icmp_packet.get_icmp_code() {
                                time_exceeded::IcmpCodes::TimeToLiveExceededInTransit => {
                                    debug!("Icmp: Timeout from {} to {}", res_packet.get_source(), res_packet.get_destination());
                                }
                                _ => {
                                    error!("Icmp: TimeExceeded");
                                    panic!();
                                } 
                            }
                            _ => {
                            }
                        }
                    }
                    _ => {
                        error!("Protocol: {:?}", res_packet.get_next_level_protocol());
                    }
                }
            }
            Err(e) => {
                error!("Icmp: {:?}", e);
                panic!("{:?}", e);
            }
        }

        if is_reach {
            info!("Ping: Reach from {} to {}", src_ip, dest_ip);
            break;
        } else {
            icmp_packet.set_sequence_number(icmp_packet.get_sequence_number() + 1);
        }
    }



}

/**
 * Set param to icmp packet
 */
fn make_icmp_packet(packet: &mut MutableEchoRequestPacket) {
    let id = rand::thread_rng().gen();
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_identifier(id);
    packet.set_sequence_number(0);
    let sum = checksum(&IcmpPacket::new(packet.packet()).unwrap());
    packet.set_checksum(sum);
}

/**
 * Set param to ip packet
 */
fn make_ip_packet(packet: &mut MutableIpv4Packet, config: &BaseConfig) {
    let id = rand::thread_rng().gen();
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(packet.packet().len() as u16);
    packet.set_identification(id);
    packet.set_ttl(1);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    packet.set_destination(Ipv4Addr::from_str(config.ip.as_str()).unwrap());
}