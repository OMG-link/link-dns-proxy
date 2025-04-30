use super::{Config, Connection, EncryptType};
use crate::dns_query::DnsQuery;
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, native_tls};
use trust_dns_proto::op::Message;

pub struct TcpConnection {
    config: Config,
}

impl TcpConnection {
    pub fn new(config: Config) -> Self {
        TcpConnection { config }
    }

    async fn plain_direct(&self, query: DnsQuery) -> Result<Message> {
        let mut stream = TcpStream::connect(self.config.addr()).await?;
        self.send_over_tcp(&mut stream, query).await
    }

    async fn dot_direct(&self, query: DnsQuery) -> Result<Message> {
        let tcp = TcpStream::connect(self.config.addr()).await?;
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(!self.config.verify_cert())
            .build()?;
        let tls = TlsConnector::from(connector)
            .connect(&self.config.hostname().as_str(), tcp)
            .await?;
        self.send_over_tcp(tls, query).await
    }

    async fn send_over_tcp<S>(&self, mut stream: S, dns_query: DnsQuery) -> Result<Message>
    where
        S: AsyncWriteExt + AsyncReadExt + Unpin + Send,
    {
        let msg = dns_query.to_message();
        let bytes = msg.to_vec()?;
        let len = (bytes.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&bytes).await?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        Ok(Message::from_vec(&resp_buf)?)
    }
}

#[async_trait]
impl Connection for TcpConnection {
    async fn query(&self, dns_query: DnsQuery) -> Result<Message> {
        match self.config.encrypt_type() {
            EncryptType::NONE => self.plain_direct(dns_query).await,
            EncryptType::TLS => self.dot_direct(dns_query).await,
            _ => unimplemented!("Use HttpsConnection for HTTPS"),
        }
    }
}
