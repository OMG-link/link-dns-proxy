use anyhow::Result;
use reqwest::dns::Name;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::ConfigMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptType {
    NONE,
    TLS,
    HTTPS,
}

impl FromStr for EncryptType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "NONE" => Ok(EncryptType::NONE),
            "TLS" => Ok(EncryptType::TLS),
            "HTTPS" => Ok(EncryptType::HTTPS),
            _ => Err(format!("Invalid encrypt type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyType {
    NONE,
    SOCKS5,
    HTTP,
}

impl FromStr for ProxyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "NONE" => Ok(ProxyType::NONE),
            "SOCKS5" => Ok(ProxyType::SOCKS5),
            "HTTP" => Ok(ProxyType::HTTP),
            _ => Err(format!("Invalid proxy type: {}", s)),
        }
    }
}

pub struct Config {
    // DNS server IP
    addr: SocketAddr,
    // encrypt info
    encrypt_type: EncryptType,
    hostname: Option<Name>,
    doh_template: Option<String>,
    verify_cert: bool,
    // proxy info
    proxy_type: ProxyType,
    proxy_addr: Option<SocketAddr>,
    // optional info
    timeout: Duration,
    retry_count: u8,
    reuse_tcp_connection: bool,
}

impl Config {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            encrypt_type: EncryptType::NONE,
            hostname: None,
            doh_template: None,
            verify_cert: true,
            proxy_type: ProxyType::NONE,
            proxy_addr: None,
            timeout: Duration::from_secs(2),
            retry_count: 2,
            reuse_tcp_connection: false,
        }
    }

    pub fn from_config_map(map: &mut ConfigMap, prefix: &str) -> Result<Self> {
        let addr = map.get_required(&format!("{prefix}-addr"))?;
        let mut cfg = crate::dns_server::Config::new(addr);

        if let Some(encrypt_type) = map.get_optional(&format!("{prefix}-encrypt-type"))? {
            match encrypt_type {
                EncryptType::NONE => {
                    cfg.set_encrypt_none();
                }
                EncryptType::TLS => {
                    let hn = map.get_required(&format!("{prefix}-hostname"))?;
                    cfg.set_encrypt_tls(hn);
                    if let Some(ok) = map.get_optional(&format!("{prefix}-verify-cert"))? {
                        cfg.set_verify_cert(ok);
                    }
                }
                EncryptType::HTTPS => {
                    let hn = map.get_required(&format!("{prefix}-hostname"))?;
                    let doh = map.get_required(&format!("{prefix}-doh-template"))?;
                    cfg.set_encrypt_https(hn, doh);
                    if let Some(ok) = map.get_optional(&format!("{prefix}-verify-cert"))? {
                        cfg.set_verify_cert(ok);
                    }
                }
            }
        }

        if let Some(proxy_type) = map.get_optional(&format!("{prefix}-proxy-type"))? {
            match proxy_type {
                ProxyType::NONE => {
                    cfg.set_proxy_none();
                }
                ProxyType::HTTP => {
                    let pa: SocketAddr = map.get_required(&format!("{prefix}-proxy-addr"))?;
                    cfg.set_proxy_http(pa);
                }
                ProxyType::SOCKS5 => {
                    let pa: SocketAddr = map.get_required(&format!("{prefix}-proxy-addr"))?;
                    cfg.set_proxy_socks5(pa);
                }
            }
        }

        if let Some(secs) = map.get_optional(&format!("{prefix}-timeout"))? {
            cfg.set_timeout(Duration::from_millis(secs));
        }

        if let Some(cnt) = map.get_optional(&format!("{prefix}-retry-count"))? {
            cfg.set_retry_count(cnt);
        }

        if let Some(ok) = map.get_optional(&format!("{prefix}-reuse-tcp-connection"))? {
            cfg.set_reuse_tcp_connection(ok);
        }

        Ok(cfg)
    }

    pub fn is_udp_available(&self) -> bool {
        if self.encrypt_type == EncryptType::HTTPS || self.encrypt_type == EncryptType::TLS {
            return false;
        }
        if self.proxy_type == ProxyType::HTTP || self.proxy_type == ProxyType::SOCKS5 {
            return false;
        }
        true
    }

    // Getters
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn encrypt_type(&self) -> EncryptType {
        self.encrypt_type.clone()
    }

    pub fn proxy_type(&self) -> ProxyType {
        self.proxy_type.clone()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn retry_count(&self) -> u8 {
        self.retry_count
    }

    pub fn reuse_tcp_connection(&self) -> bool {
        self.reuse_tcp_connection
    }

    pub fn hostname(&self) -> &Name {
        self.hostname.as_ref().unwrap()
    }

    pub fn doh_template(&self) -> &String {
        self.doh_template.as_ref().unwrap()
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

    pub fn set_retry_count(&mut self, retry_count: u8) {
        self.retry_count = retry_count;
    }

    pub fn set_reuse_tcp_connection(&mut self, reuse_tcp_connection: bool) {
        self.reuse_tcp_connection = reuse_tcp_connection;
    }

    pub fn set_verify_cert(&mut self, verify_cert: bool) {
        self.verify_cert = verify_cert;
    }

    pub fn set_encrypt_none(&mut self) {
        self.encrypt_type = EncryptType::NONE;
        self.hostname = None;
        self.set_reuse_tcp_connection(false);
    }

    pub fn set_encrypt_tls(&mut self, hostname: Name) {
        self.encrypt_type = EncryptType::TLS;
        self.hostname = Some(hostname);
        self.set_reuse_tcp_connection(true);
    }

    pub fn set_encrypt_https(&mut self, hostname: Name, doh_template: String) {
        self.encrypt_type = EncryptType::HTTPS;
        self.hostname = Some(hostname);
        self.doh_template = Some(doh_template);
        self.set_reuse_tcp_connection(true);
    }

    pub fn set_proxy_none(&mut self) {
        self.proxy_type = ProxyType::NONE;
        self.proxy_addr = None;
    }

    pub fn set_proxy_http(&mut self, proxy_addr: SocketAddr) {
        self.proxy_type = ProxyType::HTTP;
        self.proxy_addr = Some(proxy_addr);
    }

    pub fn set_proxy_socks5(&mut self, proxy_addr: SocketAddr) {
        self.proxy_type = ProxyType::SOCKS5;
        self.proxy_addr = Some(proxy_addr);
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Config {{")?;
        write!(f, "{}", self.addr)?;
        if self.encrypt_type != EncryptType::NONE {
            write!(f, ",{:?}", self.encrypt_type)?;
        }
        if self.proxy_type != ProxyType::NONE {
            write!(f, ",{:?}", self.proxy_type)?;
        }
        writeln!(f, "}}")
    }
}
