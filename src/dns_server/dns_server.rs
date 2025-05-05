use crate::dns_query::DnsQuery;
use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use trust_dns_proto::op::Message;

use super::{Config, Connection, HttpsConnection, Protocol, TcpConnection, UdpConnection};

pub struct DnsServer {
    conn: Box<dyn Connection>,
    filters: Vec<String>,
}

impl DnsServer {
    pub fn new(config: Config) -> Result<Self> {
        let filters = config.filters().clone();
        let boxed_conn: Box<dyn Connection> = match config.protocol_type() {
            Protocol::Udp => Box::new(UdpConnection::new(config)),
            Protocol::Tcp | Protocol::Tls => Box::new(TcpConnection::new(config)),
            Protocol::Https => Box::new(HttpsConnection::new(config)?),
        };
        Ok(DnsServer {
            conn: boxed_conn,
            filters,
        })
    }

    pub fn filters(&self) -> &Vec<String> {
        &self.filters
    }

    pub fn query(&self, dns_query: &DnsQuery) -> BoxFuture<'_, Result<Message>> {
        self.conn.query(dns_query.clone()).boxed()
    }
}
