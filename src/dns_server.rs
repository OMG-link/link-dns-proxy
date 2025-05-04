pub mod config;
pub mod dns_server;

pub use config::Config;
pub use config::Protocol;
pub use config::ProxyType;
pub use dns_server::DnsServer;

mod connection;
mod https_connection;
mod tcp_connection;
mod udp_connection;

use connection::Connection;
use https_connection::HttpsConnection;
use tcp_connection::TcpConnection;
use udp_connection::UdpConnection;
