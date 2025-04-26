use anyhow::{Error, Result};
use rand::Rng;
use reqwest::{Client, Proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_native_tls::{TlsConnector, native_tls};
use tokio_socks::tcp::Socks5Stream;
use tracing::{info, trace, warn};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

use crate::dns_server::{Config, EncryptType, ProxyType};

pub struct DnsServer {
    config: Config,
}

impl DnsServer {
    pub async fn new(config: Config) -> Self {
        DnsServer { config }
    }

    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        if self.config.is_udp_available() {
            return self.query_udp(domain, record_type).await;
        } else {
            return self.query_tcp(domain, record_type).await;
        }
    }

    async fn query_udp(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let name = Name::from_utf8(domain)?;

        let mut query_message = Message::new();
        query_message
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query({
                let mut query = trust_dns_proto::op::Query::new();
                query.set_name(name.clone());
                query.set_query_class(DNSClass::IN);
                query.set_query_type(record_type);
                query
            });

        let mut rbuf = [0u8; 512];

        for attempt in 0..self.config.retry_count() {
            let query_id: u16 = rand::rng().random();
            query_message.set_id(query_id);
            let query_bytes = query_message.to_vec()?;

            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket
                .send_to(&query_bytes, self.config.addr())
                .await?;
            let recv_future = server_socket.recv_from(&mut rbuf);

            match timeout(self.config.timeout(), recv_future).await {
                Ok(result) => match result {
                    Ok((len, _)) => {
                        let resp = Message::from_vec(&rbuf[..len])?;
                        if resp.truncated() {
                            trace!(
                                "Upstream server send a truncated response. We will try again with TCP now."
                            );
                            return self.query_tcp(domain, record_type).await;
                        }
                        if resp.id() == query_id {
                            return Ok(resp);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Error receiving data from upstream server {} (attempt {}/{}). Domain={}. Error={}",
                            self.config.addr(),
                            attempt + 1,
                            self.config.retry_count(),
                            domain,
                            e
                        );
                        continue;
                    }
                },
                Err(_) => {
                    info!(
                        "Timeout from upstream server {} (attempt {}/{}). Domain={}",
                        self.config.addr(),
                        attempt + 1,
                        self.config.retry_count(),
                        domain
                    );
                    continue;
                }
            }
        }

        Err(Error::msg(format!(
            "All {} attempts to query domain '{}' failed",
            self.config.retry_count(),
            domain
        )))
    }

    pub async fn query_tcp(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        match (self.config.encrypt_type(), self.config.proxy_type()) {
            (EncryptType::NONE, ProxyType::NONE) => {
                self.query_plain_no_proxy(domain, record_type).await
            }
            (EncryptType::NONE, ProxyType::HTTP) => {
                self.query_plain_http_proxy(domain, record_type).await
            }
            (EncryptType::NONE, ProxyType::SOCKS5) => {
                self.query_plain_socks5_proxy(domain, record_type).await
            }

            (EncryptType::TLS, ProxyType::NONE) => {
                self.query_dot_no_proxy(domain, record_type).await
            }
            (EncryptType::TLS, ProxyType::HTTP) => {
                self.query_dot_http_proxy(domain, record_type).await
            }
            (EncryptType::TLS, ProxyType::SOCKS5) => {
                self.query_dot_socks5_proxy(domain, record_type).await
            }

            (EncryptType::HTTPS, ProxyType::NONE) => {
                self.query_doh_no_proxy(domain, record_type).await
            }
            (EncryptType::HTTPS, ProxyType::HTTP) => {
                self.query_doh_http_proxy(domain, record_type).await
            }
            (EncryptType::HTTPS, ProxyType::SOCKS5) => {
                self.query_doh_socks5_proxy(domain, record_type).await
            }
        }
    }

    // ---------------- Plain DNS (No encryption) ----------------

    async fn query_plain_no_proxy(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let tcp = TcpStream::connect(self.config.addr()).await?;
        self.send_dns_over_tcp(tcp, domain, record_type).await
    }

    async fn query_plain_http_proxy(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message> {
        let proxy_addr = self.config.proxy_addr();

        let mut stream = TcpStream::connect(proxy_addr).await?;
        let target = self.config.addr();
        let connect_req = format!(
            "CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n",
            ip = target.ip(),
            port = target.port()
        );
        stream.write_all(connect_req.as_bytes()).await?;

        let mut buf = Vec::new();
        loop {
            let mut tmp = [0u8; 1024];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::msg("Proxy closed connection during CONNECT"));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header = String::from_utf8_lossy(&buf);
        let status_line = header.lines().next().unwrap_or("");
        if !status_line.contains("200") {
            return Err(Error::msg(format!("Proxy CONNECT failed: {}", status_line)));
        }

        self.send_dns_over_tcp(stream, domain, record_type).await
    }

    async fn query_plain_socks5_proxy(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message> {
        let proxy_addr = self.config.proxy_addr();
        let tcp = Socks5Stream::connect(proxy_addr, self.config.addr())
            .await?
            .into_inner();
        self.send_dns_over_tcp(tcp, domain, record_type).await
    }

    // ---------------- DNS-over-TLS (DoT) ----------------

    async fn query_dot_no_proxy(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let tcp = TcpStream::connect(self.config.addr()).await?;
        self.send_dns_over_tls(tcp, domain, record_type).await
    }

    async fn query_dot_http_proxy(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let proxy_addr = self.config.proxy_addr();

        let mut stream = TcpStream::connect(proxy_addr).await?;
        let target = self.config.addr();
        let connect_req = format!(
            "CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n",
            ip = target.ip(),
            port = target.port()
        );
        stream.write_all(connect_req.as_bytes()).await?;

        let mut buf = Vec::new();
        loop {
            let mut tmp = [0u8; 1024];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::msg("Proxy closed connection during CONNECT"));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header = String::from_utf8_lossy(&buf);
        let status_line = header.lines().next().unwrap_or("");
        if !status_line.contains("200") {
            return Err(Error::msg(format!("Proxy CONNECT failed: {}", status_line)));
        }

        let hostname = self.config.hostname();
        let native = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(!self.config.verify_cert())
            .build()?;
        let tls_connector = TlsConnector::from(native);
        let tls_stream = tls_connector.connect(&hostname, stream).await?;

        self.send_dns_over_tcp(tls_stream, domain, record_type)
            .await
    }

    async fn query_dot_socks5_proxy(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message> {
        let proxy_addr = self.config.proxy_addr();
        let tcp = Socks5Stream::connect(proxy_addr, self.config.addr())
            .await?
            .into_inner();
        self.send_dns_over_tls(tcp, domain, record_type).await
    }

    // ---------------- DNS-over-HTTPS (DoH) ----------------

    async fn query_doh_no_proxy(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        self.send_dns_over_https(domain, record_type, None).await
    }

    async fn query_doh_http_proxy(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let proxy_url = format!("http://{}", self.config.proxy_addr());
        self.send_dns_over_https(domain, record_type, Some(proxy_url))
            .await
    }

    async fn query_doh_socks5_proxy(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message> {
        let proxy_url = format!("socks5h://{}", self.config.proxy_addr());
        self.send_dns_over_https(domain, record_type, Some(proxy_url))
            .await
    }

    // ---------------- Helpers ----------------

    async fn send_dns_over_tcp<S>(
        &self,
        mut stream: S,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let req_msg = self.build_query(domain, record_type)?;
        let req_msg_bytes = req_msg.to_vec()?;

        let req_len_bytes = (req_msg_bytes.len() as u16).to_be_bytes();
        stream.write_all(&req_len_bytes).await?;
        stream.write_all(&req_msg_bytes).await?;

        let mut resp_len_bytes = [0u8; 2];
        stream.read_exact(&mut resp_len_bytes).await?;
        let resp_len = u16::from_be_bytes(resp_len_bytes) as usize;

        let mut resp_msg_bytes = vec![0; resp_len];
        stream.read_exact(&mut resp_msg_bytes).await?;

        Ok(Message::from_vec(&resp_msg_bytes)?)
    }

    async fn send_dns_over_tls<S>(
        &self,
        stream: S,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Message>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let hostname = self.config.hostname();

        let tls_connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(!self.config.verify_cert())
            .build()?;
        let tls_connector = TlsConnector::from(tls_connector);

        let tls_stream = tls_connector.connect(hostname, stream).await?;
        self.send_dns_over_tcp(tls_stream, domain, record_type)
            .await
    }

    async fn send_dns_over_https(
        &self,
        domain: &str,
        record_type: RecordType,
        proxy: Option<String>,
    ) -> Result<Message> {
        let client = {
            let mut builder = Client::builder();
            if let Some(proxy_url) = proxy {
                builder = builder.proxy(Proxy::all(&proxy_url)?);
            }
            builder.build()?
        };

        let doh_url = self.config.doh_template();
        let req_msg = self.build_query(domain, record_type)?;
        let req_msg_bytes = req_msg.to_vec()?;

        let resp = client
            .post(doh_url)
            .header("Content-Type", "application/dns-message")
            .body(req_msg_bytes)
            .send()
            .await?;

        let resp_msg_bytes = resp.bytes().await?;
        Ok(Message::from_vec(&resp_msg_bytes)?)
    }

    fn build_query(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        let name = Name::from_utf8(domain)?;
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(trust_dns_proto::op::MessageType::Query);
        message.set_op_code(trust_dns_proto::op::OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query({
            let mut q = Query::new();
            q.set_name(name);
            q.set_query_class(DNSClass::IN);
            q.set_query_type(record_type);
            q
        });
        Ok(message)
    }
}
