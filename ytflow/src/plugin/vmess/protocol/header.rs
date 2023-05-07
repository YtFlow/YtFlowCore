use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use md5::{Digest, Md5};

use crate::flow::HostName;

pub(crate) const DATA_KEY_LEN: usize = 16;
pub(crate) const DATA_IV_LEN: usize = 16;
pub(crate) const MAX_RANDOM_LEN: usize = 15;
pub(crate) const CHECKSUM_LEN: usize = 4;
pub(crate) const VMESS_HEADER_OPT_STD: u8 = 0b001;
pub(crate) const VMESS_HEADER_OPT_SHAKE: u8 = 0b100;
// TODO: global padding
pub(crate) const VMESS_HEADER_ENC_AES_CFB: u8 = 1;
pub(crate) const VMESS_HEADER_ENC_AES_GCM: u8 = 3;
pub(crate) const VMESS_HEADER_ENC_CHACHA_POLY: u8 = 4;
pub(crate) const VMESS_HEADER_ENC_NONE: u8 = 5;
pub(crate) const VMESS_HEADER_CMD_TCP: u8 = 1;
pub(crate) const VMESS_HEADER_CMD_UDP: u8 = 2;

#[derive(Debug, Clone)]
pub enum Addr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(usize, [u8; 255]),
}

impl Default for Addr {
    fn default() -> Self {
        Self::Ipv4([0; 4].into())
    }
}

impl<'a> From<&'a HostName> for Addr {
    fn from(host: &'a HostName) -> Self {
        match host {
            HostName::Ip(IpAddr::V4(v4)) => Self::Ipv4(*v4),
            HostName::Ip(IpAddr::V6(v6)) => Self::Ipv6(*v6),
            HostName::DomainName(domain) => {
                let mut buf = [0; 255];
                let len = domain.as_bytes().len().min(255);
                buf[..len].copy_from_slice(domain.as_bytes());
                Self::Domain(len, buf)
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestHeader {
    pub ver: u8,
    pub data_iv: [u8; DATA_IV_LEN],
    pub data_key: [u8; DATA_KEY_LEN],
    pub res_auth: u8,
    pub opt: u8,
    pub padding_len_and_enc: u8,
    pub reserved1: u8,
    pub cmd: u8,
    pub port: u16,
    pub addr: Addr,
    pub random: [u8; MAX_RANDOM_LEN],
    pub checksum: [u8; CHECKSUM_LEN],
}

#[derive(Debug, Clone, Default)]
pub struct ResponseHeader {
    pub res_auth: u8,
    pub opt: u8,
    pub cmd: u8,
    pub cmd_len: u8,
    // TODO: cmd bytes
}

impl RequestHeader {
    pub fn padding_len(&self) -> u8 {
        self.padding_len_and_enc >> 4
    }
    pub fn set_padding_len(&mut self, len: u8) {
        self.padding_len_and_enc = (self.padding_len_and_enc & 0b0000_1111) | (len << 4);
    }
    pub fn set_encryption(&mut self, enc: u8) {
        self.padding_len_and_enc = (self.padding_len_and_enc & 0b1111_0000) | (enc & 0b0000_1111);
    }
    pub fn padding_mut(&mut self) -> &mut [u8] {
        let padding_len = self.padding_len() as usize;
        &mut self.random[..padding_len]
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Option<usize> {
        // Before addr
        if buf.len() < 40 {
            return None;
        }
        buf[0] = self.ver;
        buf[1..17].copy_from_slice(&self.data_iv);
        buf[17..33].copy_from_slice(&self.data_key);
        buf[33] = self.res_auth;
        buf[34] = self.opt;
        buf[35] = self.padding_len_and_enc;
        buf[36] = self.reserved1;
        buf[37] = self.cmd;
        buf[38..40].copy_from_slice(&self.port.to_be_bytes());
        let mut offset = 40;
        match self.addr {
            Addr::Ipv4(addr) => {
                if buf.len() < offset + 4 + 1 {
                    return None;
                }
                buf[offset] = 1;
                offset += 1;
                buf[offset..offset + 4].copy_from_slice(&addr.octets());
                offset += 4;
            }
            Addr::Ipv6(addr) => {
                if buf.len() < offset + 16 + 1 {
                    return None;
                }
                buf[offset] = 3;
                offset += 1;
                buf[offset..offset + 16].copy_from_slice(&addr.octets());
                offset += 16;
            }
            Addr::Domain(len, ref domain) => {
                if buf.len() < offset + 1 + len + 1 {
                    return None;
                }
                buf[offset] = 2;
                offset += 1;
                buf[offset] = len as u8;
                offset += 1;
                buf[offset..offset + len].copy_from_slice(&domain[..len]);
                offset += len;
            }
        }
        // After addr
        let random_len = self.padding_len() as usize;
        if buf.len() < offset + random_len + 4 {
            return None;
        }
        buf[offset..offset + random_len].copy_from_slice(&self.random[..random_len]);
        offset += random_len;

        let hash = const_fnv1a_hash::fnv1a_hash_32(&buf[..offset], None);
        buf[offset..offset + 4].copy_from_slice(&hash.to_be_bytes());
        Some(offset + 4)
    }
    pub fn derive_res_key_aes_cfb(&self) -> [u8; DATA_KEY_LEN] {
        let mut res_key = [0; DATA_KEY_LEN];
        let mut res_key_hash = Md5::new();
        res_key_hash.update(&self.data_key);
        let res = res_key_hash.finalize();
        res_key[..].copy_from_slice(&res[..]);
        res_key
    }
    pub fn derive_res_iv_aes_cfb(&self) -> [u8; DATA_IV_LEN] {
        let mut res_iv = [0; DATA_IV_LEN];
        let mut res_iv_hash = Md5::new();
        res_iv_hash.update(&self.data_iv);
        let res = res_iv_hash.finalize();
        res_iv[..].copy_from_slice(&res[..]);
        res_iv
    }
}
