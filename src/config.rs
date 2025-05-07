use anyhow::Result;
use serde::Deserialize;
use std::{fs, net::SocketAddr};

#[derive(Debug, Deserialize)]
struct ConfigYaml {
    listen_addresses: Option<Vec<SocketAddr>>,
    dns_servers: Vec<crate::dns_server::config::ConfigYaml>,
}

#[derive(Debug)]
pub struct Config {
    pub listen_addresses: Vec<SocketAddr>,
    pub dns_server_configs: Vec<crate::dns_server::Config>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                anyhow::bail!("Error when reading '{path}': {e}");
            }
        };
        let config_yaml: ConfigYaml = serde_yaml::from_str(&content)?;

        let listen_addresses = config_yaml
            .listen_addresses
            .unwrap_or_else(|| vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]);

        let mut dns_confs = Vec::with_capacity(config_yaml.dns_servers.len());
        for yaml in config_yaml.dns_servers {
            dns_confs.push(crate::dns_server::Config::from_yaml(yaml)?);
        }

        if dns_confs.is_empty() {
            anyhow::bail!("No valid DNS server config.");
        }

        Ok(Self {
            listen_addresses,
            dns_server_configs: dns_confs,
        })
    }
}
