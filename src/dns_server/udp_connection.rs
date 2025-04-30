use super::{Config, Connection};
use crate::dns_query::DnsQuery;
use anyhow::{Error, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trust_dns_proto::op::Message;

pub struct UdpConnection {
    config: Config,
}

impl UdpConnection {
    pub fn new(config: Config) -> Self {
        UdpConnection { config }
    }
}

#[async_trait]
impl Connection for UdpConnection {
    async fn query(&self, dns_query: DnsQuery) -> Result<Message> {
        let mut message = dns_query.to_message();
        let mut buf = [0u8; 512];

        for _ in 0..self.config.retry_count() {
            let id: u16 = rand::random();
            message.set_id(id);
            let bytes = message.to_vec()?;

            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(&bytes, self.config.addr()).await?;

            match timeout(self.config.timeout(), sock.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    let resp = Message::from_vec(&buf[..len])?;
                    if !resp.truncated() && resp.id() == id {
                        return Ok(resp);
                    }
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        Err(Error::msg("UDP query failed after retries"))
    }
}
