use std::net::SocketAddr;

pub struct Config {
    pub listen_addrs: Vec<SocketAddr>,
    pub upstream_server_addr: SocketAddr,
}

impl Config {
    pub fn default() -> Self {
        Config {
            listen_addrs: vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()],
            upstream_server_addr: "8.8.8.8:53".parse().unwrap(),
        }
    }
}
