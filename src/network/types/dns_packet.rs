use std::ops::Deref;

use log::debug;

use crate::utils::byte_utils::range_byte_replace;

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

    pub fn packet(&mut self) -> &[u8] {
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

        buff
    }
}