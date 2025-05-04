use crate::dns_query::DnsQuery;
use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use trust_dns_proto::op::Message;

use super::{Config, Connection, HttpsConnection, Protocol, TcpConnection, UdpConnection};

pub struct DnsServer {
    conn: Box<dyn Connection>,
}

impl DnsServer {
    pub fn new(config: Config) -> Result<Self> {
        let boxed_conn: Box<dyn Connection> = match config.protocol_type() {
            Protocol::Udp => Box::new(UdpConnection::new(config)),
            Protocol::Tcp | Protocol::Tls => Box::new(TcpConnection::new(config)),
            Protocol::Https => Box::new(HttpsConnection::new(config)?),
        };
        Ok(DnsServer { conn: boxed_conn })
    }

    pub fn query(&self, dns_query: &DnsQuery) -> BoxFuture<'_, Result<Message>> {
        self.conn.query(dns_query.clone()).boxed()
    }
}
