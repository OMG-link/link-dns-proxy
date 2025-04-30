use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::future;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tracing::{error, info, trace, warn};
use trust_dns_proto::op::Message;

use super::cache::{DnsCache, DnsCacheEntry};
use crate::dns_query::DnsQuery;
use crate::dns_server::DnsServer;

pub struct PendingQuery {
    waiters: Vec<oneshot::Sender<Arc<Result<Message>>>>,
    last_request_time: Instant,
}

impl PendingQuery {
    pub fn new() -> Self {
        Self {
            waiters: Vec::new(),
            last_request_time: Instant::now(),
        }
    }

    pub fn add_waiter(&mut self) -> oneshot::Receiver<Arc<Result<Message>>> {
        let (sender, receiver) = oneshot::channel();
        self.waiters.push(sender);
        receiver
    }

    pub fn notify_all(self, result: Arc<Result<Message>>) {
        for waiter in self.waiters {
            let _ = waiter.send(result.clone());
        }
    }

    pub fn get_time_elapsed(&self) -> Duration {
        return Instant::now() - self.last_request_time;
    }
}

pub struct DnsProxy {
    upstream_servers: Vec<DnsServer>,
    dns_cache: Arc<Mutex<DnsCache>>,
    pending_querys: Arc<Mutex<HashMap<DnsQuery, PendingQuery>>>,
}

impl DnsProxy {
    pub async fn new(dns_server_configs: Vec<crate::dns_server::Config>) -> Result<Self> {
        let upstream_servers = dns_server_configs
            .into_iter()
            .map(|config| DnsServer::new(config))
            .collect::<Result<Vec<_>, _>>()?;
        let dns_cache = Arc::new(Mutex::new(HashMap::new()));
        let pending_querys = Arc::new(Mutex::new(HashMap::new()));

        Ok(DnsProxy {
            upstream_servers,
            dns_cache,
            pending_querys,
        })
    }

    pub async fn listen_and_serve(self: Arc<Self>, listen_addrs: Vec<SocketAddr>) -> Result<()> {
        let mut listen_threads = Vec::new();
        for listen_addr in listen_addrs.into_iter() {
            let self_cloned = self.clone();
            let listen_addr_cloned = listen_addr.clone();
            let listen_thread = tokio::spawn(async move {
                match self_cloned.listen_and_serve_port(listen_addr_cloned).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Worker listening {} crashed: {}", listen_addr, e);
                    }
                };
            });
            listen_threads.push(listen_thread);
        }

        future::join_all(listen_threads).await;
        error!("All workers crashed. Stopping the server.");
        Ok(())
    }

    async fn listen_and_serve_port(self: Arc<Self>, listen_addr: SocketAddr) -> Result<()> {
        let listener = Arc::new(UdpSocket::bind(listen_addr).await?);
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

            let request_msg_raw = buf[..len].to_vec();
            let request_msg = match Message::from_vec(&request_msg_raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let request_id = request_msg.id();
            let mut query_futs = FuturesUnordered::new();
            for question in request_msg.queries() {
                let domain = question.name().clone();
                let qtype = question.query_type();
                trace!("Received request [{} {:?}]", domain, qtype);

                let self_cloned = self.clone();
                let question_cloned = question.clone();
                query_futs.push(async move {
                    let query = DnsQuery {
                        domain: domain.clone(),
                        qtype,
                    };
                    let result = self_cloned.handle_dns_request(query).await;
                    if let Err(e) = &result {
                        warn!("Failed to resolve [{} {:?}]: {}", domain, qtype, e);
                    }
                    (question_cloned, result)
                });
            }

            let server_addr = listener.clone();
            tokio::spawn(async move {
                while let Some((question, result)) = query_futs.next().await {
                    let domain = question.name().to_utf8();
                    let qtype = question.query_type();
                    match result {
                        Ok(result) => match &*result {
                            Ok(response_msg) => {
                                let mut response_msg = response_msg.clone();
                                response_msg.set_id(request_id);
                                response_msg.add_query(question);
                                let response_bytes = response_msg.to_vec().unwrap();
                                let server_addr = server_addr.clone();
                                trace!("Replying request [{} {:?}]", domain, qtype);
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        server_addr.send_to(&response_bytes, user_addr).await
                                    {
                                        warn!("Unable to reply: {}", e);
                                    }
                                });
                            }
                            Err(_) => {} // Failed when querying upstream server
                        },
                        Err(e) => {
                            warn!("One shot channel error: {:?}", e);
                        }
                    }
                }
            });
        }
    }

    async fn handle_dns_request(self: Arc<Self>, query: DnsQuery) -> Result<Arc<Result<Message>>> {
        {
            let cache = self.dns_cache.lock().await;
            if let Some(entry) = cache.get(&query) {
                if !entry.is_expired() {
                    trace!("Cache hit {:?}", query);
                    return Ok(Arc::new(Ok(entry.get_message())));
                }
            }
        }

        {
            let mut pending = self.pending_querys.lock().await;
            if let Some(pq) = pending.get_mut(&query) {
                let receiver = pq.add_waiter();
                let time_epalsed = pq.get_time_elapsed();
                drop(pending);
                trace!(
                    "Query appended to waiting list {:?}. Last query sent {} seconds ago.",
                    query,
                    time_epalsed.as_secs_f32()
                );
                if time_epalsed >= Duration::from_secs(10) {
                    warn!(
                        "Query {:?} has take {} seconds!",
                        query,
                        time_epalsed.as_secs_f32()
                    )
                }
                let response = receiver.await?;
                return Ok(response);
            } else {
                let mut new_pq = PendingQuery::new();
                let receiver = new_pq.add_waiter();
                pending.insert(query.clone(), new_pq);
                drop(pending);
                trace!("Making a new upstream query {:?}", query);

                let self_cloned = self.clone();
                tokio::spawn(async move {
                    let lookup_result = self_cloned.upstream_servers[0].query(&query).await;
                    match lookup_result {
                        Ok(msg_upstream) => {
                            let msg_cache: Message;
                            {
                                let msg = Arc::new(msg_upstream);
                                let mut cache = self_cloned.dns_cache.lock().await;
                                cache.insert(query.clone(), DnsCacheEntry::new(msg));
                                msg_cache = cache.get(&query).unwrap().get_message();
                            }
                            {
                                let mut pending = self_cloned.pending_querys.lock().await;
                                if let Some(pq) = pending.remove(&query) {
                                    pq.notify_all(Arc::new(Ok(msg_cache)));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Upstream lookup failed: {}", e);
                            let mut pending = self_cloned.pending_querys.lock().await;
                            let pq = pending.remove(&query).unwrap();
                            pq.notify_all(Arc::new(Err(e)));
                        }
                    }
                });

                let response = receiver.await?;
                return Ok(response);
            }
        }
    }
}
