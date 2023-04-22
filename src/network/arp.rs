use std::{vec, net::Ipv4Addr, str::FromStr, thread, time::Duration};
use log::{error, info, debug};

use pnet::{packet::{ethernet::{MutableEthernetPacket, EtherTypes, EthernetPacket}, arp::{MutableArpPacket, ArpHardwareType, ArpOperation, ArpPacket, ArpOperations}, Packet}, datalink::{NetworkInterface, channel, Channel}, util::MacAddr};

use crate::{utils::{os_utils, ip_utils::get_ip_from_nic}, types::ArpConfig};

const MAX_PACKET_SIZE: usize = 28;
const MAX_TIME_OUT_COUNT: usize = 10;

/**
 * Check Arp
 */
pub fn arp(config: ArpConfig) {
    let nic = os_utils::get_active_interface(&config.interface_name);
    let src_ip = get_ip_from_nic(&nic);
    let src_mac = nic.mac.unwrap();
    let broadcast = MacAddr::new(255, 255, 255, 255, 255, 255);

    // Arp packet
    let mut a_packet_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE];
    let mut a_packet = MutableArpPacket::new(&mut a_packet_buff).unwrap();
    make_arp_packet(&mut a_packet);
    a_packet.set_sender_hw_addr(src_mac);
    a_packet.set_sender_proto_addr(Ipv4Addr::from_str(src_ip.to_string().as_str()).unwrap());
    a_packet.set_target_hw_addr(MacAddr::new(0,0,0,0,0,0));
    a_packet.set_target_proto_addr(Ipv4Addr::from_str(config.dest_ip.as_str()).unwrap());

    // Ethernet packet
    let mut e_packet_buff: Vec<u8> = vec![0; MAX_PACKET_SIZE * 2];
    let mut e_packet = MutableEthernetPacket::new(&mut e_packet_buff).unwrap();
    e_packet.set_ethertype(EtherTypes::Arp);
    e_packet.set_source(src_mac);
    e_packet.set_destination(broadcast);
    e_packet.set_payload(&a_packet.packet());

    let channel = channel(&nic, Default::default());
    let (mut tx, mut rx) =  match channel {
        Ok(Channel::Ethernet(tx, rx)) => {
            (tx, rx)
        }
        Ok(_) => {
            error!("Arp: Failed channel");
            panic!();
        }
        Err(e) => {
            error!("Arp: {:?}", e);
            panic!();
        }
    };

    // Send Arp
    debug!("Arp: Send packet {:?}", e_packet);
    tx.send_to(&e_packet.packet(), None);

    // receive Arp
    let mut timeout_count= 0;
    loop {
        match rx.next() {
            Ok(res_packet) => {
                let e_res_packet = EthernetPacket::new(res_packet).unwrap();
                debug!("Arp: Response packet {:?}", e_res_packet);
                match e_res_packet.get_ethertype() {
                    EtherTypes::Arp => {
                        let a_res_packet = ArpPacket::new(&e_res_packet.payload()).unwrap();
                        if a_res_packet.get_operation() != ArpOperations::Reply {
                            thread::sleep(Duration::from_millis(1000));
                            continue;
                        }
                        debug!("Arp: Response arp packet {:?}", a_res_packet);
                        info!("Arp: Target Ip {}, Target Mac Address {}"
                            , a_res_packet.get_sender_proto_addr(), a_res_packet.get_sender_hw_addr());
                        break;
                    }
                    _ => {
                        debug!("Arp: Not arp packet, {}", e_res_packet.get_ethertype());
                    }
                };

                if timeout_count > MAX_TIME_OUT_COUNT {
                    info!("Arp: Getting arp packet is TimeOut");
                    break;
                }
                timeout_count += 1;
            }
            Err(e) => {
                error!("Arp: Failed Receive {:?}", e);
                panic!();
            }
        }
        
    }
}


/**
 * Set param to packet
 */
fn make_arp_packet(packet: &mut MutableArpPacket) {
    packet.set_hardware_type(ArpHardwareType::new(1));
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperation::new(1));
}