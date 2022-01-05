use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "dest")]
pub enum Destination {
    DomainName(String),
    Ip(IpAddr),
}

impl ToString for Destination {
    fn to_string(&self) -> String {
        match self {
            Destination::DomainName(s) => s.clone(),
            Destination::Ip(ip) => ip.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationAddr {
    pub dest: Destination,
    pub port: u16,
}

impl Destination {
    pub fn set_domain_name(&mut self, mut domain_name: String) -> Result<(), ()> {
        use trust_dns_resolver::Name;
        domain_name.make_ascii_lowercase();
        *self = Destination::DomainName(Name::from_utf8(domain_name).map_err(|_| ())?.to_ascii());
        Ok(())
    }
    pub fn from_domain_name(domain_name: String) -> Result<Self, ()> {
        let mut res = Destination::DomainName(String::new());
        res.set_domain_name(domain_name)?;
        Ok(res)
    }
}

impl From<SocketAddr> for DestinationAddr {
    fn from(socket: SocketAddr) -> Self {
        Self {
            dest: Destination::Ip(socket.ip()),
            port: socket.port(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub local_peer: SocketAddr,
    pub remote_peer: DestinationAddr,
}
