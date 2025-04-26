use std::{collections::HashMap, fs, net::SocketAddr};

use anyhow::{Error, Result};
use tracing::error;

pub struct Config {
    pub listen_addrs: Vec<SocketAddr>,
    pub dns_server_configs: Vec<crate::dns_server::Config>,
}

impl Config {
    pub fn new(
        listen_addrs: Vec<SocketAddr>,
        dns_server_configs: Vec<crate::dns_server::Config>,
    ) -> Result<Self> {
        if dns_server_configs.len() == 0 {
            error!("No valid DNS server config.");
            return Err(Error::msg("No valid DNS server config."));
        }
        Ok(Self {
            listen_addrs,
            dns_server_configs,
        })
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let kvs = load_kv_file(path)?;
        Self::from_kv_map(&kvs)
    }

    fn from_kv_map(map: &HashMap<String, String>) -> Result<Self> {
        let listen_addrs = if let Some(count_str) = map.get("listen-addrs-num") {
            let la_count: usize = count_str.parse()?;
            let mut addrs = Vec::with_capacity(la_count);
            for i in 1..=la_count {
                let key = format!("listen-addr-{}", i);
                let addr: SocketAddr = map
                    .get(&key)
                    .ok_or_else(|| {
                        let msg = format!("Missing {}", key);
                        error!("{}", msg);
                        Error::msg(msg)
                    })?
                    .parse()?;
                addrs.push(addr);
            }
            addrs
        } else {
            vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
        };

        let ds_count: usize = map
            .get("dns-server-num")
            .ok_or_else(|| {
                error!("Missing dns-server-num");
                Error::msg("Missing dns-server-num")
            })?
            .parse()?;

        let mut dns_server_configs = Vec::with_capacity(ds_count);
        for i in 1..=ds_count {
            let prefix = format!("dns-server-{}-", i);
            let cfg = crate::dns_server::Config::from_kv_prefix(map, &prefix)?;
            dns_server_configs.push(cfg);
        }

        crate::dns_proxy::Config::new(listen_addrs, dns_server_configs)
    }
}

pub fn parse_kv_string(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in s.lines() {
        let line = match line.find(';') {
            Some(idx) => &line[..idx],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let val = line[pos + 1..].trim().to_string();
            map.insert(key, val);
        }
    }
    map
}

pub fn load_kv_file(path: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_kv_string(&content))
}
