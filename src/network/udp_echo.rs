use std::{net::{IpAddr, Ipv4Addr, UdpSocket, SocketAddr, SocketAddrV4}, str::FromStr, vec, time::Duration, os::fd::{FromRawFd, AsRawFd}, char::MAX};
use log::{error, debug};

use pnet::{packet::{ipv4::{MutableIpv4Packet, Ipv4Packet}, Packet, ip::IpNextHeaderProtocols, udp::{MutableUdpPacket, UdpPacket, ipv4_checksum}, ethernet::{MutableEthernetPacket, EtherTypes}}, transport::{transport_channel, udp_packet_iter, ipv4_packet_iter}};
use rand::Rng;

use crate::{types::{BaseConfig, EchoConfig}, utils::{os_utils, ip_utils::get_ip_from_nic}};

const MAX_PACKET_SIZE: usize = 64;
const UDP_ECHO_PORT: u16 = 7;

/**
 * send Udp echo
 */
pub fn udp_echo(config: BaseConfig) {

    let mut ip_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE + 20];
    let mut ip_packet: MutableIpv4Packet = MutableIpv4Packet::new(&mut ip_buff).unwrap();
    make_ip_packet(&mut ip_packet, &config);

    let port: u16 = rand::thread_rng().gen();
    let socket = UdpSocket::bind("127.0.0.1:".to_string() + port.to_string().as_str()).unwrap();
    let addr = socket.local_addr().unwrap();
    let mut udp_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE];
    let mut udp_packet: MutableUdpPacket = MutableUdpPacket::new(&mut udp_buff).unwrap();
    make_udp_packet(&mut udp_packet, &addr);
    udp_packet.set_checksum(ipv4_checksum(&udp_packet.to_immutable(), &ip_packet.get_source(), &ip_packet.get_destination()));

    ip_packet.set_payload(udp_packet.packet());

    socket.set_read_timeout(Some(Duration::from_millis(3000)));

    rayon::join(|| {
        for i in 1..5 {
            let send_packet = Ipv4Packet::new(ip_packet.packet()).unwrap();
            debug!("ECHO: send_packet {:?}", i);
            let dest_ip = config.ip.clone() + ":7";
            socket.send_to(send_packet.packet(), SocketAddr::V4(SocketAddrV4::from_str(&dest_ip).unwrap())).unwrap();
            std::thread::sleep(Duration::from_millis(1000));
        }
    },
     || {

        loop {
            let mut buff: Vec<u8> = vec![0; MAX_PACKET_SIZE];
            match socket.recv_from(&mut buff) {
                Ok(_) => {
                    let packet = Ipv4Packet::new(&buff);
                    debug!("ECHO: {:?}", packet.unwrap());
                }
                Err(e) => {
                    error!("ECHO: {:?}", e);
                }
            }
        }
    });




}

fn make_ip_packet(packet: &mut MutableIpv4Packet, config: &BaseConfig) {
    let id = rand::thread_rng().gen();
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(packet.packet().len() as u16);
    packet.set_identification(id);
    packet.set_ttl(64);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    packet.set_destination(Ipv4Addr::from_str(&config.ip).unwrap());
}

fn make_udp_packet(packet: &mut MutableUdpPacket, addr: &SocketAddr) {
    packet.set_source(addr.port());
    packet.set_destination(UDP_ECHO_PORT);
    packet.set_length(packet.packet().len()  as u16);
}