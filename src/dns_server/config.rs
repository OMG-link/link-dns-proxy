use anyhow::Result;
use reqwest::dns::Name as ReqwestName;
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;
use trust_dns_proto::rr::Name as TrustName;

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
    pub filters: Option<Vec<String>>,
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
    hostname: Option<ReqwestName>,
    doh_path: Option<String>,
    verify_cert: bool,
    // proxy info
    proxy_type: ProxyType,
    proxy_addr: Option<SocketAddr>,
    // optional info
    timeout: Duration,
    max_retry: u8,
    reuse_tcp_connection: bool,
    // filter info
    filters: Vec<String>,
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
            filters: vec![String::from("*")],
        }
    }

    pub fn from_yaml(yaml: ConfigYaml) -> Result<Self> {
        let ConfigYaml {
            addr,
            protocol,
            hostname,
            doh_path,
            verify_cert,
            proxy_type,
            proxy_addr,
            timeout,
            max_retry,
            reuse_tcp_connection,
            filters,
        } = yaml;
        let mut cfg = Config::new(addr);

        if let Some(protocol) = protocol {
            match protocol {
                Protocol::Udp => cfg.set_protocol_udp(),
                Protocol::Tcp => cfg.set_protocol_tcp(),
                Protocol::Tls => {
                    let hn =
                        hostname.ok_or_else(|| anyhow::anyhow!("hostname required for TLS"))?;
                    let name = ReqwestName::from_str(&hn)?;
                    cfg.set_protocol_tls(name);

                    if let Some(v) = verify_cert {
                        cfg.set_verify_cert(v);
                    }
                }
                Protocol::Https => {
                    let hn =
                        hostname.ok_or_else(|| anyhow::anyhow!("hostname required for HTTPS"))?;
                    let path =
                        doh_path.ok_or_else(|| anyhow::anyhow!("doh_path required for HTTPS"))?;
                    let name = ReqwestName::from_str(&hn)?;
                    cfg.set_protocol_https(name, path);

                    if let Some(v) = verify_cert {
                        cfg.set_verify_cert(v);
                    }
                }
            }
        }

        if let Some(pt) = proxy_type {
            match pt {
                ProxyType::None => cfg.set_proxy_none(),
                ProxyType::Http => {
                    let pa = proxy_addr
                        .ok_or_else(|| anyhow::anyhow!("proxy_addr required for HTTP proxy"))?;
                    cfg.set_proxy_http(pa);
                }
                ProxyType::Socks5 => {
                    let pa = proxy_addr
                        .ok_or_else(|| anyhow::anyhow!("proxy_addr required for SOCKS5 proxy"))?;
                    cfg.set_proxy_socks5(pa);
                }
            }
        }

        if let Some(ms) = timeout {
            cfg.set_timeout(Duration::from_millis(ms));
        }
        if let Some(r) = max_retry {
            cfg.set_max_retry(r);
        }
        if let Some(flag) = reuse_tcp_connection {
            cfg.set_reuse_tcp_connection(flag);
        }
        if let Some(filters) = filters {
            let cleaned: Vec<String> = filters
                .into_iter()
                .filter_map(|f| {
                    if f.is_empty() {
                        warn!("Skipping empty filter");
                        return None;
                    }
                    let encoded = match TrustName::from_utf8(&f) {
                        Ok(name) => name.to_ascii(),
                        Err(e) => {
                            warn!("Skipping '{}': invalid domain ({})", f, e);
                            return None;
                        }
                    };
                    if encoded.len() > 1 && encoded[1..].contains('*') {
                        warn!(
                            "Skipping '{}': '*' can only appear at the very beginning",
                            f
                        );
                        return None;
                    }
                    Some(encoded)
                })
                .collect();
            cfg.set_filters(cleaned);
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

    pub fn hostname(&self) -> &ReqwestName {
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

    pub fn filters(&self) -> &Vec<String> {
        &self.filters
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

    pub fn set_filters(&mut self, filters: Vec<String>) {
        self.filters = filters;
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

    pub fn set_protocol_tls(&mut self, hostname: ReqwestName) {
        self.protocol = Protocol::Tls;
        self.hostname = Some(hostname);
        self.set_reuse_tcp_connection(true);
    }

    pub fn set_protocol_https(&mut self, hostname: ReqwestName, doh_path: String) {
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
