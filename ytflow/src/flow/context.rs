use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use serde::{de, Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostName {
    DomainName(String),
    Ip(IpAddr),
}

impl ToString for HostName {
    fn to_string(&self) -> String {
        match self {
            HostName::DomainName(s) => s.clone(),
            HostName::Ip(ip) => ip.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationAddr {
    pub host: HostName,
    pub port: u16,
}

impl HostName {
    pub fn set_domain_name(&mut self, mut domain_name: String) -> Result<(), String> {
        use trust_dns_resolver::Name;
        domain_name.make_ascii_lowercase();
        *self = HostName::DomainName(
            Name::from_utf8(&domain_name)
                .map_err(|_| domain_name)?
                .to_ascii(),
        );
        Ok(())
    }
    pub fn from_domain_name(domain_name: String) -> Result<Self, String> {
        let mut res = HostName::DomainName(String::new());
        res.set_domain_name(domain_name)?;
        Ok(res)
    }
}

impl ToString for DestinationAddr {
    fn to_string(&self) -> String {
        format!("{}:{}", self.host.to_string(), self.port)
    }
}

impl From<SocketAddr> for DestinationAddr {
    fn from(socket: SocketAddr) -> Self {
        Self {
            host: HostName::Ip(socket.ip()),
            port: socket.port(),
        }
    }
}

#[derive(Debug)]
pub struct FlowContext {
    pub local_peer: SocketAddr,
    pub remote_peer: DestinationAddr,
    pub af_sensitive: bool,
}

impl<'de> Deserialize<'de> for HostName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Cow<str> = Deserialize::deserialize(deserializer)?;
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(HostName::Ip(ip));
        }
        let mut ret = HostName::DomainName(String::new());
        ret.set_domain_name(s.into_owned()).map_err(|s| {
            de::Error::invalid_type(
                de::Unexpected::Str(&s),
                &"a valid IP address of domain name",
            )
        })?;
        Ok(ret)
    }
}

impl Serialize for HostName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            HostName::DomainName(s) => serializer.serialize_str(s),
            HostName::Ip(ip) => serializer.serialize_str(&ip.to_string()),
        }
    }
}
