use std::ops::Deref;
use log::error;

use clap::builder::Str;
use log::debug;

use crate::utils::byte_utils::range_byte_replace;

const MAX_PACKET_SIZE: usize = 128;
const DNS_OFFSET: u8 = 192;

/**
 * Dns Paket
 */
#[derive(Debug)]
pub struct DnsPacket {
    pub transaction_id: u16,
    // qr, ope code, ...etc
    pub flags: DnsHeader,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query: DnsQueryData,
    _packet: Vec<u8>
}

/**
 * Dns Query Data
 */
#[derive(Debug)]
pub struct DnsQueryData {
    // dns
    pub name: String,
    pub dns_type: u16,
    pub dns_class: u16
}

impl DnsQueryData {
    pub fn get_query(&self) -> Vec<u8> {
        let mut buff: Vec<u8> = Vec::new();
        let name_sp = self.name.split(".");
        name_sp.for_each(|name| {
            // domain size
            buff.push(name.len() as u8);
            buff.append(&mut name.as_bytes().to_vec());
        });
        // domain end
        buff.push(0);

        buff.append(&mut self.dns_type.to_be_bytes().to_vec());
        buff.append(&mut self.dns_class.to_be_bytes().to_vec());
        buff
    }
}

/**
 * DnsHeader
 */
#[derive(Debug)]
pub struct DnsHeader {
    pub qr_code: u8,
    pub ope_code: u8,
    pub trunc: u8,
    pub recursion: u8,
    pub z_code: u8,
    pub dns_sec: u8,
    pub auth_code: u8
}

/**
 * DnsHeader
 */
#[allow(unused)]
impl DnsHeader {
    fn get_flags(&self) -> Vec<u8> {
        let mut buff: Vec<u8> = Vec::new();
        buff.push(self.qr_code + self.ope_code + self.trunc + self.recursion);
        buff.push(self.z_code + self.auth_code);
        buff
    }
}

#[derive(Default)]
pub struct DnsAnswer {
    // dns
    pub name: String,
    pub dns_type: u16,
    pub dns_class: u16,
    pub time: u32,
    pub date_size: u16,
    pub address: String
}

impl DnsAnswer {
    pub fn get_answer(buff: &Vec<u8>) -> Vec<DnsAnswer> {
        let buff_size = buff.len();
        let mut i = 0;
        let mut answers: Vec<DnsAnswer> = Vec::new();
        debug!("DNS: dns packet size={} buff={:?}", buff.len(), &buff);

        // check answer section start position
        i = DnsAnswer::get_answer_position(buff);
        debug!("DNS: aws pos={} buff_size={}", i, buff_size);
        while i < buff_size {
            let mut ans = DnsAnswer {..Default::default()};
            // name
            let mut name = String::new();
            let answer_offset = buff[i];
            debug!("DNS: answer offset={}", answer_offset);
            if answer_offset != DNS_OFFSET {
                break;
            }
            i += 1;
            let mut offset = buff[i] as usize;
            loop {
                // get name from query section
                // TODO: shoud be refactor
                if offset == 0 {
                    break;
                }

                let name_size: usize = buff[offset] as usize;
                debug!("DNS: name_size={} name_offset={}", name_size, offset);
                if name_size == 0 {
                    // domain end
                    i += 1;
                    break;
                } else {
                    if name.len() != 0 {
                        name += ".";
                    }
                }
                let name_part_end = offset + name_size as usize;
                let name_bytes = &buff[ (offset + 1)..(name_part_end + 1)];
                debug!("DNS: name bytes={:?} name_part_end={}", name_bytes, name_part_end);
                // name load
                name += std::str::from_utf8(name_bytes).unwrap();
                offset = name_part_end + 1;
            }
            // answer code end
            if name.len() == 0 {
                break;
            }
            // name end
            debug!("DNS: name={}", name);
            ans.name = name;

            // dns type
            ans.dns_type = u16::from_be_bytes([buff[i], buff[i+1]]);
            i += 2;

            // class 
            ans.dns_class = u16::from_be_bytes([buff[i], buff[i+1]]);
            i += 2;

            // time
            ans.time = u32::from_be_bytes([buff[i], buff[i+1], buff[i+2], buff[i+3]]);
            i += 4;

            // data length
            ans.date_size = u16::from_be_bytes([buff[i], buff[i+1]]);
            i += 2;

            // address
            ans.address = buff[i].to_string() + "." + buff[i+1].to_string().as_str() 
                + "." + buff[i+2].to_string().as_str() + "." + buff[i+3].to_string().as_str();
            i += 4;
            answers.push(ans);
        }

        answers
    }

    fn get_answer_position(buff: &Vec<u8>) -> usize {
        let mut i: usize = 0;
        // skip header
        i += 12;
        loop {
            // skip domain
            let name_size = buff[i];
            i += 1;
            if name_size == 0 {
                break;
            }
        }
        debug!("DNS: query domain pos={}", i);

        // skip type and class 
        i += 4;

        i
    }
}

/**
 * DnsPacket of implemention for Packet
 */
impl DnsPacket {
    pub fn new() -> Self{
        DnsPacket {
            transaction_id: 0,
            flags: DnsHeader { qr_code: 0, ope_code: 0, trunc: 0, recursion: 0, z_code: 0, dns_sec: 0, auth_code: 0 },
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            query: DnsQueryData { name: "".to_string(), dns_type: 0, dns_class: 0 },
            _packet: Vec::new()
        }
    }
    
    /**
     * Get answer by different request and response.
     */
    pub fn get_answar(res: Vec<u8>) -> Option<Vec<DnsAnswer>> {
        let answers = DnsAnswer::get_answer(&res);
        if answers.len() == 0 {
            return None;
        } else {
            return Some(answers);
        }
    }

    pub fn make_packet(&mut self) {

        let mut buff = &mut self._packet;
        // transaction_id
        buff.append(&mut self.transaction_id.to_be_bytes().to_vec());

        // flags
        buff.append(&mut self.flags.get_flags());

        // question
        buff.append(&mut self.question_count.to_be_bytes().to_vec());

        // answer
        buff.append(&mut self.answer_count.to_be_bytes().to_vec());

        //authority
        buff.append(&mut self.authority_count.to_be_bytes().to_vec());

        // additional
        buff.append(&mut self.additional_count.to_be_bytes().to_vec());

        // query
        buff.append(&mut self.query.get_query());

    }

    pub fn packet(&self) -> &[u8] {
        &self._packet
    }
}