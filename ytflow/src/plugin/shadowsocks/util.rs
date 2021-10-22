use std::net::IpAddr;

use crypto2::hash::Md5;

use crate::flow::{Destination, FlowContext};

pub fn write_dest(w: &mut Vec<u8>, context: &FlowContext) {
    match &context.remote_peer.dest {
        Destination::DomainName(domain) => {
            w.push(0x03);
            w.push(domain.len() as u8);
            w.extend_from_slice(domain.as_bytes());
        }
        Destination::Ip(IpAddr::V4(ipv4)) => {
            w.push(0x01);
            w.extend_from_slice(&ipv4.octets()[..]);
        }
        Destination::Ip(IpAddr::V6(ipv6)) => {
            w.push(0x04);
            w.extend_from_slice(&ipv6.octets());
        }
    }
    w.extend_from_slice(&context.remote_peer.port.to_be_bytes());
}

/// Key derivation of OpenSSL's [EVP_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
///
/// See [shadowsocks_crypto::openssl_bytes_to_key](https://github.com/shadowsocks/shadowsocks-crypto/blob/cb54882c7db80200be34ef98e73dbb80fd236097/src/v1/cipher.rs#L140-L163).
pub fn openssl_bytes_to_key<const K: usize>(password: &[u8]) -> [u8; K] {
    let mut key = [0u8; K];

    let mut last_digest: Option<[u8; Md5::DIGEST_LEN]> = None;

    let mut offset = 0usize;
    while offset < K {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(K - offset, Md5::DIGEST_LEN);
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += Md5::DIGEST_LEN;
        last_digest = Some(digest);
    }

    key
}

pub fn increase_num_buf<const N: usize>(buf: &mut [u8; N]) {
    let mut c = buf[0] as u16 + 1;
    buf[0] = c as u8;
    c >>= 8;
    let mut n = 1;
    while n < N {
        c += buf[n] as u16;
        buf[n] = c as u8;
        c >>= 8;
        n += 1;
    }
}
