use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

pub struct DnsServer {
    server_addr: SocketAddr,
    server_socket: UdpSocket,
}

impl DnsServer {
    pub async fn new(server_addr: SocketAddr) -> Self {
        let server_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        DnsServer {
            server_addr,
            server_socket,
        }
    }

    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        // 1. 构建 DNS 查询消息
        let name = Name::from_utf8(domain)?;
        let mut query_message = Message::new();
        query_message
            .set_id(1234)
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
        self.server_socket
            .send_to(&query_bytes, self.server_addr)
            .await?;

        // 4. 接收 DNS 响应消息
        let mut buf = [0; 512];
        let (len, _) = self.server_socket.recv_from(&mut buf).await?;

        // 5. 解析响应消息
        let response_message = Message::from_vec(&buf[..len])?;

        // 6. 将响应反序列化并返回
        Ok(response_message)
    }
}
