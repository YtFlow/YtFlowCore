use ytflow::flow::DestinationAddr;

pub mod obfs;
pub mod protocol;
pub mod tls;

#[derive(Debug, Clone)]
pub struct Proxy {
    pub name: String,
    pub legs: Vec<ProxyLeg>,
    pub udp_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLeg {
    pub protocol: protocol::ProxyProtocolType,
    pub dest: DestinationAddr,
    pub obfs: Option<obfs::ProxyObfsType>,
    pub tls: Option<tls::ProxyTlsLayer>,
}
