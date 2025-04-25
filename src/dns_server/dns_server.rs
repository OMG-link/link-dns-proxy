use anyhow::{Error, Result};
use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::warn;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

pub struct DnsServer {
    upstream_addr: SocketAddr,
}

impl DnsServer {
    pub async fn new(upstream_addr: SocketAddr) -> Self {
        DnsServer { upstream_addr }
    }

    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let query_id: u16 = rand::rng().random();

        // 1. 构建 DNS 查询消息
        let name = Name::from_utf8(domain)?;
        let mut query_message = Message::new();
        query_message
            .set_id(query_id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query({
                let mut query = trust_dns_proto::op::Query::new();
                query.set_name(name);
                query.set_query_class(DNSClass::IN);
                query.set_query_type(record_type);
                query
            });

        // 2. 将消息序列化为字节
        let query_bytes = query_message.to_vec()?;

        // 3. 发送查询消息到 DNS 服务器
        let server_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        server_socket
            .send_to(&query_bytes, self.upstream_addr)
            .await?;

        // 4. recv & filter by ID with timeout
        let mut rbuf = [0u8; 512];
        loop {
            let upstream_addr = self.upstream_addr.clone();
            let query_domain = String::from(domain);
            let recv_future = server_socket.recv_from(&mut rbuf);
            match timeout(Duration::from_secs(2), recv_future).await {
                Ok(result) => match result {
                    Ok((len, _)) => {
                        let resp = Message::from_vec(&rbuf[..len])?;
                        if resp.id() == query_id {
                            return Ok(resp);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Error receiving data from upstream server {}. (Domain={})",
                            upstream_addr, query_domain
                        );
                        return Err(
                            Error::new(e).context("Error receiving data from upstream server")
                        );
                    }
                },
                Err(_) => {
                    warn!(
                        "Timeout waiting for response from upstream server {}. (Domain={})",
                        upstream_addr, query_domain
                    );
                    return Err(Error::msg("Timeout while waiting for response"));
                }
            }
        }
    }
}
