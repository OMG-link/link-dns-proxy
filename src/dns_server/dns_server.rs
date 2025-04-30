use crate::dns_query::DnsQuery;
use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use trust_dns_proto::op::Message;

use super::{Config, Connection, EncryptType, HttpsConnection, TcpConnection, UdpConnection};

pub struct DnsServer {
    conn: Box<dyn Connection>,
}

impl DnsServer {
    pub fn new(config: Config) -> Result<Self> {
        let boxed_conn: Box<dyn Connection> = if config.is_udp_available() {
            Box::new(UdpConnection::new(config))
        } else if config.encrypt_type() == EncryptType::HTTPS {
            Box::new(HttpsConnection::new(config)?)
        } else {
            Box::new(TcpConnection::new(config))
        };
        Ok(DnsServer { conn: boxed_conn })
    }

    pub fn query(&self, dns_query: &DnsQuery) -> BoxFuture<'_, Result<Message>> {
        let q = dns_query.clone();
        self.conn.query(q).boxed()
    }
}
