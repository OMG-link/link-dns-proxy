use anyhow::Result;
use reqwest::dns::Name as ReqwestName;
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;
use trust_dns_proto::rr::Name as TrustName;

#[derive(Debug, Deserialize)]
pub struct ConfigYaml {
    pub address: SocketAddr,
    pub protocol: Option<Protocol>,
    pub hostname: Option<String>,
    pub doh_path: Option<String>,
    pub verify_cert: Option<bool>,
    pub proxy_type: Option<ProxyType>,
    pub proxy_address: Option<SocketAddr>,
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
    address: SocketAddr,
    // protocol info
    protocol: Protocol,
    hostname: Option<ReqwestName>,
    doh_path: Option<String>,
    verify_cert: bool,
    // proxy info
    proxy_type: ProxyType,
    proxy_address: Option<SocketAddr>,
    // optional info
    timeout: Duration,
    max_retry: u8,
    reuse_tcp_connection: bool,
    // filter info
    filters: Vec<String>,
}

impl Config {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            protocol: Protocol::Udp,
            hostname: None,
            doh_path: None,
            verify_cert: true,
            proxy_type: ProxyType::None,
            proxy_address: None,
            timeout: Duration::from_secs(2),
            max_retry: 2,
            reuse_tcp_connection: false,
            filters: vec![String::from("*")],
        }
    }

    pub fn from_yaml(yaml: ConfigYaml) -> Result<Self> {
        let ConfigYaml {
            address,
            protocol,
            hostname,
            doh_path,
            verify_cert,
            proxy_type,
            proxy_address,
            timeout,
            max_retry,
            reuse_tcp_connection,
            filters,
        } = yaml;
        let mut cfg = Config::new(address);

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
                    let pa = proxy_address
                        .ok_or_else(|| anyhow::anyhow!("proxy_address required for HTTP proxy"))?;
                    cfg.set_proxy_http(pa);
                }
                ProxyType::Socks5 => {
                    let pa = proxy_address.ok_or_else(|| {
                        anyhow::anyhow!("proxy_address required for SOCKS5 proxy")
                    })?;
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
            cfg.set_filters(
                filters
                    .into_iter()
                    .flat_map(expand_filter)
                    .filter_map(format_filter_rule)
                    .collect(),
            );
        }

        Ok(cfg)
    }

    // Getters
    pub fn address(&self) -> SocketAddr {
        self.address
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

    pub fn proxy_address(&self) -> SocketAddr {
        self.proxy_address.unwrap()
    }

    pub fn verify_cert(&self) -> bool {
        self.verify_cert
    }

    pub fn filters(&self) -> &Vec<String> {
        &self.filters
    }

    // Setters
    #[allow(dead_code)]
    pub fn set_address(&mut self, address: SocketAddr) {
        self.address = address;
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
        self.proxy_address = None;
    }

    pub fn set_proxy_http(&mut self, proxy_address: SocketAddr) {
        self.proxy_type = ProxyType::Http;
        self.proxy_address = Some(proxy_address);
    }

    pub fn set_proxy_socks5(&mut self, proxy_address: SocketAddr) {
        self.proxy_type = ProxyType::Socks5;
        self.proxy_address = Some(proxy_address);
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Config {{")?;
        write!(f, "{}", self.address)?;
        if self.protocol != Protocol::Udp {
            write!(f, ",{:?}", self.protocol)?;
        }
        if self.proxy_type != ProxyType::None {
            write!(f, ",{:?}", self.proxy_type)?;
        }
        writeln!(f, "}}")
    }
}

fn expand_filter(f: String) -> Vec<String> {
    if let Some(path_str) = f.strip_prefix('@') {
        let path = Path::new(path_str);
        match File::open(path) {
            Ok(fh) => BufReader::new(fh)
                .lines()
                .filter_map(|line| line.ok())
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<String>>(),
            Err(e) => {
                warn!("Could not open filter file '{path_str}': {e}");
                vec![]
            }
        }
    } else {
        vec![f]
    }
}

fn format_filter_rule(f: String) -> Option<String> {
    if f.is_empty() {
        warn!("Skipping invalid filter: empty string");
        return None;
    }
    let encoded = match TrustName::from_utf8(&f) {
        Ok(name) => name.to_ascii(),
        Err(e) => {
            warn!("Skipping invalid filter '{}': invalid domain ({})", f, e);
            return None;
        }
    };
    if encoded.len() > 1 && encoded[1..].contains('*') {
        warn!(
            "Skipping invalid filter '{}': '*' can only appear at the very beginning",
            f
        );
        return None;
    }
    Some(encoded)
}
