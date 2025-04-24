use anyhow::Result;
use tokio::net::UdpSocket;
use trust_dns_proto::op::Message;

use super::super::dns_server::DnsServer;
use super::Config;

pub struct DnsProxy {
    udp_listeners: Vec<UdpSocket>,
    upstream_server: DnsServer,
}

impl DnsProxy {
    pub async fn new(config: Config) -> Result<Self> {
        let mut udp_listeners = Vec::new();

        for listen_addr in &config.listen_addrs {
            let socket = UdpSocket::bind(listen_addr).await?;
            udp_listeners.push(socket);
        }

        Ok(DnsProxy {
            udp_listeners,
            upstream_server: DnsServer::new(config.upstream_server_addr).await,
        })
    }

    pub async fn listen_and_serve(&self) -> Result<()> {
        let mut buf = [0u8; 512];
        loop {
            for listener in &self.udp_listeners {
                let (len, src) = listener.recv_from(&mut buf).await?;
                match Message::from_vec(&buf[..len]) {
                    Ok(request_msg) => {
                        for question in request_msg.queries() {
                            let name = question.name().to_utf8();
                            let qtype = question.query_type();
                            println!("Query: {} {:?}", name, qtype);

                            match self.upstream_server.query(&name, qtype).await {
                                Ok(mut response_msg) => {
                                    response_msg.set_id(request_msg.id());
                                    let response_bytes = response_msg.to_vec()?;
                                    listener.send_to(&response_bytes, src).await?;
                                }
                                Err(e) => {
                                    eprintln!("Upstream query failed: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to decode DNS message: {}", e);
                    }
                }
            }
        }
    }
}
