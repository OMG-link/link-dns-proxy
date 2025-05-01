use std::{collections::HashMap, fs, net::SocketAddr, str::FromStr};

use anyhow::{Error, Result};
use tracing::{error, warn};

pub struct ConfigMap {
    map: HashMap<String, String>,
}

impl ConfigMap {
    pub fn from_str(s: &str) -> Self {
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
        Self { map }
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(ConfigMap::from_str(&content))
    }

    fn get_config<T: FromStr>(&mut self, key: &str, required: bool) -> Result<Option<T>>
    where
        <T as FromStr>::Err: std::fmt::Display,
    {
        match self.map.remove(key) {
            Some(val_str) => match val_str.parse::<T>() {
                Ok(val) => Ok(Some(val)),
                Err(e) => {
                    let msg = format!("Value of {} is invalid: {} {}", key, val_str, e);
                    error!("{}", msg);
                    Err(Error::msg(msg))
                }
            },
            None => {
                if required {
                    let msg = format!("Missing {}", key);
                    error!("{}", msg);
                    Err(Error::msg(msg))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn get_required<T: FromStr>(&mut self, key: &str) -> Result<T>
    where
        <T as FromStr>::Err: std::fmt::Display,
    {
        Ok(self.get_config(&key, true)?.unwrap())
    }

    pub fn get_optional<T: FromStr>(&mut self, key: &str) -> Result<Option<T>>
    where
        <T as FromStr>::Err: std::fmt::Display,
    {
        self.get_config(&key, false)
    }
}

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
        let mut kvs = ConfigMap::from_file(path)?;
        let config = Self::from_config_map(&mut kvs);
        for (key, value) in kvs.map.into_iter() {
            warn!("Unused config option: {key}={value}");
        }
        config
    }

    fn from_config_map(map: &mut ConfigMap) -> Result<Self> {
        let listen_addrs = if let Some(la_count) = map.get_optional("listen-addrs-num")? {
            let mut addrs = Vec::with_capacity(la_count);
            for i in 1..=la_count {
                let addr = map.get_required(&format!("listen-addr-{}", i))?;
                addrs.push(addr);
            }
            addrs
        } else {
            vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
        };

        let ds_count: usize = map.get_required("dns-server-num")?;

        let mut dns_server_configs = Vec::with_capacity(ds_count);
        for i in 1..=ds_count {
            let cfg =
                crate::dns_server::Config::from_config_map(map, &format!("dns-server-{}", i))?;
            dns_server_configs.push(cfg);
        }

        Ok(Self::new(listen_addrs, dns_server_configs)?)
    }
}
