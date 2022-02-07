use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use serde::{de, Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone)]
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
    pub fn set_domain_name(&mut self, mut domain_name: String) -> Result<(), String> {
        use trust_dns_resolver::Name;
        domain_name.make_ascii_lowercase();
        *self = Destination::DomainName(
            Name::from_utf8(&domain_name)
                .map_err(|_| domain_name)?
                .to_ascii(),
        );
        Ok(())
    }
    pub fn from_domain_name(domain_name: String) -> Result<Self, String> {
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

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Cow<str> = Deserialize::deserialize(deserializer)?;
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Destination::Ip(ip));
        }
        let mut ret = Destination::DomainName(String::new());
        ret.set_domain_name(s.into_owned()).map_err(|s| {
            de::Error::invalid_type(
                de::Unexpected::Str(&s),
                &"a valid IP address of domain name",
            )
        })?;
        Ok(ret)
    }
}

impl Serialize for Destination {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Destination::DomainName(s) => serializer.serialize_str(s),
            Destination::Ip(ip) => serializer.serialize_str(&ip.to_string()),
        }
    }
}
