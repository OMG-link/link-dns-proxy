use anyhow::{Error, Result};
use reqwest::dns::Name;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::error;

#[derive(Clone, PartialEq, Eq)]
pub enum EncryptType {
    NONE,
    TLS,
    HTTPS,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProxyType {
    NONE,
    SOCKS5,
    HTTP,
}

pub struct Config {
    addr: SocketAddr,
    encrypt_type: EncryptType,
    proxy_type: ProxyType,
    timeout: Duration,
    retry_count: u8,

    proxy_addr: Option<SocketAddr>,

    hostname: Option<Name>,
    doh_template: Option<String>,
    verify_cert: bool,
}

impl Config {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            encrypt_type: EncryptType::NONE,
            proxy_type: ProxyType::NONE,
            timeout: Duration::from_secs(2),
            retry_count: 1,
            proxy_addr: None,
            hostname: None,
            doh_template: None,
            verify_cert: true,
        }
    }

    pub fn from_kv_prefix(map: &HashMap<String, String>, prefix: &str) -> Result<Self> {
        let get_or_error = |key: &str| {
            map.get(&format!("{}{}", prefix, key))
                .cloned()
                .ok_or_else(|| {
                    let msg = format!("Missing config key: {}{}", prefix, key);
                    error!("{}", msg);
                    Error::msg(msg)
                })
        };

        let addr_str = get_or_error("addr")?;
        let addr: SocketAddr = match addr_str.parse() {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Invalid addr: {} {}", addr_str, e);
                error!("{}", msg);
                return Err(Error::msg(msg));
            }
        };

        let mut cfg = crate::dns_server::Config::new(addr);

        if let Some(ts) = map.get(&format!("{}timeout", prefix)) {
            let secs: u64 = match ts.parse() {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid timeout(ms): {} {}", ts, e);
                    error!("{}", msg);
                    return Err(Error::msg(msg));
                }
            };
            cfg.set_timeout(Duration::from_millis(secs));
        }

        if let Some(rc) = map.get(&format!("{}retry-count", prefix)) {
            let cnt: u8 = match rc.parse() {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid retry-count(ms): {} {}", rc, e);
                    error!("{}", msg);
                    return Err(Error::msg(msg));
                }
            };
            cfg.set_retry_count(cnt);
        }

        if let Some(enc) = map.get(&format!("{}encrypt-type", prefix)) {
            match enc.as_str() {
                "NONE" => cfg.set_encrypt_none(),
                "TLS" => {
                    let hn_str = get_or_error("hostname")?;
                    let hn = Name::from_str(&hn_str)?;
                    cfg.set_encrypt_tls(hn)
                }
                "HTTPS" => {
                    let hn_str = get_or_error("hostname")?;
                    let hn = Name::from_str(&hn_str)?;
                    let doh_tpl = get_or_error("doh-template")?;
                    cfg.set_encrypt_https(hn, doh_tpl);
                }
                other => {
                    let msg = format!("Invalid encrypt-type: {}", other);
                    error!("{}", msg);
                    return Err(Error::msg(msg));
                }
            }
        }

        if let Some(pt) = map.get(&format!("{}proxy-type", prefix)) {
            match pt.as_str() {
                "NONE" => cfg.set_proxy_none(),
                "HTTP" => {
                    let pa = get_or_error("proxy-addr")?;
                    cfg.set_proxy_http(match pa.parse() {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = format!("Invalid proxy-addr: {} {}", pa, e);
                            error!("{}", msg);
                            return Err(Error::msg(msg));
                        }
                    });
                }
                "SOCKS5" => {
                    let pa = get_or_error("proxy-addr")?;
                    cfg.set_proxy_socks5(match pa.parse() {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = format!("Invalid proxy-addr: {} {}", pa, e);
                            error!("{}", msg);
                            return Err(Error::msg(msg));
                        }
                    });
                }
                other => {
                    let msg = format!("Invalid proxy-type: {}", other);
                    error!("{}", msg);
                    return Err(Error::msg(msg));
                }
            }
        }

        if let Some(vc) = map.get(&format!("{}verify-cert", prefix)) {
            let ok: bool = match vc.parse() {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid verify-cert: {} {}", vc, e);
                    error!("{}", msg);
                    return Err(Error::msg(msg));
                }
            };
            cfg.set_verify_cert(ok);
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

    pub fn set_verify_cert(&mut self, verify_cert: bool) {
        self.verify_cert = verify_cert;
    }

    pub fn set_encrypt_none(&mut self) {
        self.encrypt_type = EncryptType::NONE;
        self.hostname = None;
    }

    pub fn set_encrypt_tls(&mut self, hostname: Name) {
        self.encrypt_type = EncryptType::TLS;
        self.hostname = Some(hostname);
    }

    pub fn set_encrypt_https(&mut self, hostname: Name, doh_template: String) {
        self.encrypt_type = EncryptType::HTTPS;
        self.hostname = Some(hostname);
        self.doh_template = Some(doh_template);
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
