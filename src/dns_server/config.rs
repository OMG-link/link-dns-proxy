use anyhow::Result;
use reqwest::dns::Name;
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct ConfigYaml {
    pub addr: SocketAddr,
    pub protocol: Option<Protocol>,
    pub hostname: Option<String>,
    pub doh_path: Option<String>,
    pub verify_cert: Option<bool>,
    pub proxy_type: Option<ProxyType>,
    pub proxy_addr: Option<SocketAddr>,
    pub timeout: Option<u64>,
    pub max_retry: Option<u8>,
    pub reuse_tcp_connection: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProxyType {
    None,
    Socks5,
    Http,
}

#[derive(Debug)]
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

    pub fn from_yaml(yaml: ConfigYaml) -> Result<Self> {
        let mut cfg = Config::new(yaml.addr);

        if let Some(proto) = yaml.protocol {
            match proto {
                Protocol::Udp => cfg.set_protocol_udp(),
                Protocol::Tcp => cfg.set_protocol_tcp(),
                Protocol::Tls => {
                    let hn = yaml
                        .hostname
                        .ok_or_else(|| anyhow::anyhow!("hostname required for TLS"))?;
                    let name = Name::from_str(&hn)?;
                    cfg.set_protocol_tls(name);

                    if let Some(v) = yaml.verify_cert {
                        cfg.set_verify_cert(v);
                    }
                }
                Protocol::Https => {
                    let hn = yaml
                        .hostname
                        .ok_or_else(|| anyhow::anyhow!("hostname required for HTTPS"))?;
                    let path = yaml
                        .doh_path
                        .ok_or_else(|| anyhow::anyhow!("doh_path required for HTTPS"))?;
                    let name = Name::from_str(&hn)?;
                    cfg.set_protocol_https(name, path);

                    if let Some(v) = yaml.verify_cert {
                        cfg.set_verify_cert(v);
                    }
                }
            }
        }

        if let Some(pt) = yaml.proxy_type {
            match pt {
                ProxyType::None => cfg.set_proxy_none(),
                ProxyType::Http => {
                    let pa = yaml
                        .proxy_addr
                        .ok_or_else(|| anyhow::anyhow!("proxy_addr required for HTTP proxy"))?;
                    cfg.set_proxy_http(pa);
                }
                ProxyType::Socks5 => {
                    let pa = yaml
                        .proxy_addr
                        .ok_or_else(|| anyhow::anyhow!("proxy_addr required for SOCKS5 proxy"))?;
                    cfg.set_proxy_socks5(pa);
                }
            }
        }

        if let Some(ms) = yaml.timeout {
            cfg.set_timeout(Duration::from_millis(ms));
        }
        if let Some(r) = yaml.max_retry {
            cfg.set_max_retry(r);
        }
        if let Some(flag) = yaml.reuse_tcp_connection {
            cfg.set_reuse_tcp_connection(flag);
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
