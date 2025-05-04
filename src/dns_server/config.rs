use anyhow::Result;
use reqwest::dns::Name;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::ConfigMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "UDP" => Ok(Protocol::Udp),
            "TCP" => Ok(Protocol::Tcp),
            "TLS" | "DOT" => Ok(Protocol::Tls),
            "HTTPS" | "DOH" => Ok(Protocol::Https),
            _ => Err(format!("Invalid protocol name: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyType {
    None,
    Socks5,
    Http,
}

impl FromStr for ProxyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "NONE" => Ok(ProxyType::None),
            "SOCKS5" => Ok(ProxyType::Socks5),
            "HTTP" => Ok(ProxyType::Http),
            _ => Err(format!("Invalid proxy type: {}", s)),
        }
    }
}

pub struct Config {
    // DNS server IP
    addr: SocketAddr,
    // protocol info
    protocol: Protocol,
    hostname: Option<Name>,
    doh_path: Option<String>,
    verify_cert: bool,
    // proxy info
    proxy_type: ProxyType,
    proxy_addr: Option<SocketAddr>,
    // optional info
    timeout: Duration,
    max_retry: u8,
    reuse_tcp_connection: bool,
}

impl Config {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: Protocol::Udp,
            hostname: None,
            doh_path: None,
            verify_cert: true,
            proxy_type: ProxyType::None,
            proxy_addr: None,
            timeout: Duration::from_secs(2),
            max_retry: 2,
            reuse_tcp_connection: false,
        }
    }

    pub fn from_config_map(map: &mut ConfigMap, prefix: &str) -> Result<Self> {
        let addr = map.get_required(&format!("{prefix}-addr"))?;
        let mut cfg = crate::dns_server::Config::new(addr);

        if let Some(protocol) = map.get_optional(&format!("{prefix}-protocol"))? {
            match protocol {
                Protocol::Udp => {
                    cfg.set_protocol_udp();
                }
                Protocol::Tcp => {
                    cfg.set_protocol_tcp();
                }
                Protocol::Tls => {
                    let hn = map.get_required(&format!("{prefix}-hostname"))?;
                    cfg.set_protocol_tls(hn);
                    if let Some(ok) = map.get_optional(&format!("{prefix}-verify-cert"))? {
                        cfg.set_verify_cert(ok);
                    }
                }
                Protocol::Https => {
                    let hn = map.get_required(&format!("{prefix}-hostname"))?;
                    let doh = map.get_required(&format!("{prefix}-doh-path"))?;
                    cfg.set_protocol_https(hn, doh);
                    if let Some(ok) = map.get_optional(&format!("{prefix}-verify-cert"))? {
                        cfg.set_verify_cert(ok);
                    }
                }
            }
        }

        if let Some(proxy_type) = map.get_optional(&format!("{prefix}-proxy-type"))? {
            match proxy_type {
                ProxyType::None => {
                    cfg.set_proxy_none();
                }
                ProxyType::Http => {
                    let pa: SocketAddr = map.get_required(&format!("{prefix}-proxy-addr"))?;
                    cfg.set_proxy_http(pa);
                }
                ProxyType::Socks5 => {
                    let pa: SocketAddr = map.get_required(&format!("{prefix}-proxy-addr"))?;
                    cfg.set_proxy_socks5(pa);
                }
            }
        }

        if let Some(secs) = map.get_optional(&format!("{prefix}-timeout"))? {
            cfg.set_timeout(Duration::from_millis(secs));
        }

        if let Some(cnt) = map.get_optional(&format!("{prefix}-max-retry"))? {
            cfg.set_max_retry(cnt);
        }

        if let Some(ok) = map.get_optional(&format!("{prefix}-reuse-tcp-connection"))? {
            cfg.set_reuse_tcp_connection(ok);
        }

        Ok(cfg)
    }

    // Getters
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn protocol_type(&self) -> Protocol {
        self.protocol.clone()
    }

    pub fn proxy_type(&self) -> ProxyType {
        self.proxy_type.clone()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn retry_count(&self) -> u8 {
        self.max_retry
    }

    pub fn reuse_tcp_connection(&self) -> bool {
        self.reuse_tcp_connection
    }

    pub fn hostname(&self) -> &Name {
        self.hostname.as_ref().unwrap()
    }

    pub fn doh_path(&self) -> &String {
        self.doh_path.as_ref().unwrap()
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr.unwrap()
    }

    pub fn verify_cert(&self) -> bool {
        self.verify_cert
    }

    // Setters
    #[allow(dead_code)]
    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = addr;
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn set_max_retry(&mut self, max_retry: u8) {
        self.max_retry = max_retry;
    }

    pub fn set_reuse_tcp_connection(&mut self, reuse_tcp_connection: bool) {
        self.reuse_tcp_connection = reuse_tcp_connection;
    }

    pub fn set_verify_cert(&mut self, verify_cert: bool) {
        self.verify_cert = verify_cert;
    }

    pub fn set_protocol_udp(&mut self) {
        self.protocol = Protocol::Udp;
        self.hostname = None;
        self.set_reuse_tcp_connection(false);
    }

    pub fn set_protocol_tcp(&mut self) {
        self.protocol = Protocol::Tcp;
        self.hostname = None;
        self.set_reuse_tcp_connection(false);
    }

    pub fn set_protocol_tls(&mut self, hostname: Name) {
        self.protocol = Protocol::Tls;
        self.hostname = Some(hostname);
        self.set_reuse_tcp_connection(true);
    }

    pub fn set_protocol_https(&mut self, hostname: Name, doh_path: String) {
        self.protocol = Protocol::Https;
        self.hostname = Some(hostname);
        self.doh_path = Some(doh_path);
        self.set_reuse_tcp_connection(true);
    }

    pub fn set_proxy_none(&mut self) {
        self.proxy_type = ProxyType::None;
        self.proxy_addr = None;
    }

    pub fn set_proxy_http(&mut self, proxy_addr: SocketAddr) {
        self.proxy_type = ProxyType::Http;
        self.proxy_addr = Some(proxy_addr);
    }

    pub fn set_proxy_socks5(&mut self, proxy_addr: SocketAddr) {
        self.proxy_type = ProxyType::Socks5;
        self.proxy_addr = Some(proxy_addr);
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Config {{")?;
        write!(f, "{}", self.addr)?;
        if self.protocol != Protocol::Udp {
            write!(f, ",{:?}", self.protocol)?;
        }
        if self.proxy_type != ProxyType::None {
            write!(f, ",{:?}", self.proxy_type)?;
        }
        writeln!(f, "}}")
    }
}
