use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub enum Destination {
    DomainName(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
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
