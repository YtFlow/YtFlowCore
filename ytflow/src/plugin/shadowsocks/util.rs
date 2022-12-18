use std::net::IpAddr;

use crate::flow::{DestinationAddr, HostName};

pub fn write_dest(w: &mut Vec<u8>, remote_peer: &DestinationAddr) {
    match &remote_peer.host {
        HostName::DomainName(domain) => {
            w.push(0x03);
            let domain = domain.trim_end_matches('.').as_bytes();
            w.push(domain.len() as u8);
            w.extend_from_slice(domain);
        }
        HostName::Ip(IpAddr::V4(ipv4)) => {
            w.push(0x01);
            w.extend_from_slice(&ipv4.octets()[..]);
        }
        HostName::Ip(IpAddr::V6(ipv6)) => {
            w.push(0x04);
            w.extend_from_slice(&ipv6.octets());
        }
    }
    w.extend_from_slice(&remote_peer.port.to_be_bytes());
}

pub fn parse_dest(w: &[u8]) -> Option<DestinationAddr> {
    if w.len() < 2 {
        return None;
    }
    let dest_type = w[0];
    let (dest_addr, port_offset) = match dest_type {
        0x01 if w.len() >= 7 => {
            let mut ipv4 = [0u8; 4];
            ipv4.copy_from_slice(&w[1..5]);
            (HostName::Ip(IpAddr::V4(ipv4.into())), 5)
        }
        0x04 if w.len() >= 19 => {
            let mut ipv6 = [0u8; 16];
            ipv6.copy_from_slice(&w[1..17]);
            (HostName::Ip(IpAddr::V6(ipv6.into())), 17)
        }
        0x03 if w.len() >= w[1] as usize + 4 => {
            let domain_end = w[1] as usize + 2;
            let domain = String::from_utf8_lossy(&w[2..domain_end]).to_string();
            (HostName::from_domain_name(domain).ok()?, domain_end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([w[port_offset], w[port_offset + 1]]);
    Some(DestinationAddr {
        host: dest_addr,
        port,
    })
}

/// https://github.com/shadowsocks/shadowsocks-crypto/blob/bf3c3f0cdf3ebce6a19ce15a96248ccd94a82848/src/v1/cipher.rs#LL33-L58C2
/// Key derivation of OpenSSL's [EVP_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
pub fn openssl_bytes_to_key<const K: usize>(password: &[u8]) -> [u8; K] {
    use md5::{Digest, Md5};

    let mut key = [0u8; K];

    let mut last_digest = None;

    let mut offset = 0usize;
    while offset < K {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(K - offset, digest.len());
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += amt;
        last_digest = Some(digest);
    }
    key
}

pub fn increase_num_buf(buf: &mut [u8]) {
    let mut c = buf[0] as u16 + 1;
    buf[0] = c as u8;
    c >>= 8;
    let mut n = 1;
    while n < buf.len() {
        c += buf[n] as u16;
        buf[n] = c as u8;
        c >>= 8;
        n += 1;
    }
}
