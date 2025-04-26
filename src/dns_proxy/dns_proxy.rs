use std::sync::Arc;

use anyhow::Result;
use futures::future;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;
use tracing::{error, info, trace, warn};
use trust_dns_proto::op::Message;

use super::Config;
use crate::dns_server::DnsServer;

pub struct DnsProxy {
    udp_listeners: Vec<Arc<UdpSocket>>,
    upstream_server: Arc<DnsServer>,
}

impl DnsProxy {
    pub async fn new(config: Config) -> Result<Self> {
        let mut udp_listeners = Vec::new();

        for listen_addr in &config.listen_addrs {
            let socket = UdpSocket::bind(listen_addr).await?;
            udp_listeners.push(Arc::new(socket));
        }

        let upstream_server = Arc::new(DnsServer::new(config.dns_server_configs[0].clone()).await);

        Ok(DnsProxy {
            udp_listeners,
            upstream_server,
        })
    }

    pub async fn listen_and_serve(&self) -> Result<()> {
        let mut listen_threads = Vec::new();
        for listener in &self.udp_listeners {
            let listener = listener.clone();
            let upstream_server = self.upstream_server.clone();

            let listen_thread = tokio::spawn(async move {
                match listen_and_serve_port(listener.clone(), upstream_server).await {
                    Ok(()) => (),
                    Err(e) => {
                        let server_addr = match listener.local_addr() {
                            Ok(v) => v.to_string(),
                            Err(_e) => String::from("Unknown"),
                        };
                        error!("Worker listening {} crashed: {}", server_addr, e);
                    }
                };
            });
            listen_threads.push(listen_thread);
        }

        future::join_all(listen_threads).await;
        error!("All workers crashed. Stopping the server.");
        Ok(())
    }
}

async fn listen_and_serve_port(listener: Arc<UdpSocket>, dns_server: Arc<DnsServer>) -> Result<()> {
    let mut buf = [0u8; 512];
    loop {
        let (len, user_addr) = match listener.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    info!("{}", e);
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };

        let data = buf[..len].to_vec();
        let server_addr = listener.clone();
        let dns_server = dns_server.clone();

        tokio::spawn(async move {
            match handle_dns_request(server_addr, user_addr, dns_server, data).await {
                Ok(()) => (),
                Err(e) => {
                    warn!("Error processing DNS request: {}", e);
                }
            }
        });
    }
}

async fn handle_dns_request(
    server_addr: Arc<UdpSocket>,
    user_addr: std::net::SocketAddr,
    dns_server: Arc<DnsServer>,
    data: Vec<u8>,
) -> Result<()> {
    let request_msg = Message::from_vec(&data)?;

    let id = request_msg.id();

    let mut query_futs = FuturesUnordered::new();
    for question in request_msg.queries() {
        let domain = question.name().to_utf8();
        let qtype = question.query_type();
        let dns_server = dns_server.clone();
        trace!("Received request [{} {:?}]", domain, qtype);
        query_futs.push(async move {
            (
                domain.clone(),
                qtype,
                dns_server.query(&domain, qtype).await,
            )
        });
    }

    while let Some((domain, qtype, result)) = query_futs.next().await {
        let server_addr = server_addr.clone();
        match result {
            Ok(mut response_msg) => {
                response_msg.set_id(id);
                let response_bytes = response_msg.to_vec()?;
                trace!("Replying request [{} {:?}]", domain, qtype);
                tokio::spawn(async move {
                    if let Err(e) = server_addr.send_to(&response_bytes, user_addr).await {
                        warn!("Unable to reply: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("Upstream server error [{} {:?}]: {}", domain, qtype, e);
            }
        }
    }

    Ok(())
}
