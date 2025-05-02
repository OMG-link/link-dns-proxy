use super::{Config, Connection, EncryptType, ProxyType};
use crate::DnsQuery;
use anyhow::{Error, Result};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Duration, timeout};
use tokio_native_tls::{TlsConnector, native_tls};
use tokio_socks::tcp::Socks5Stream;
use tracing::{error, info, trace, warn};
use trust_dns_proto::op::Message;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

struct SendRequest {
    query: DnsQuery,
    resp_tx: oneshot::Sender<Result<Message>>,
}

type PendingQueryMap = Arc<Mutex<HashMap<u16, oneshot::Sender<Result<Message>>>>>;

pub struct TcpConnection {
    send_task_sender: mpsc::Sender<SendRequest>,
    timeout: Duration,
    maximum_retry: u8,
    config_str: String,
}

impl TcpConnection {
    pub fn new(config: Config) -> Self {
        let timeout = config.timeout();
        let maximum_retry = config.retry_count();
        let config_str = config.to_string();
        let (send_task_sender, send_task_receiver) = mpsc::channel::<SendRequest>(100);

        tokio::spawn(async move {
            if config.reuse_tcp_connection() {
                connection_loop_reuse_tcp(config, send_task_receiver).await;
            } else {
                connection_loop_no_reuse_tcp(config, send_task_receiver).await;
            }
        });

        TcpConnection {
            send_task_sender,
            timeout,
            maximum_retry,
            config_str,
        }
    }

    async fn send_and_receive(&self, dns_query: &DnsQuery) -> Result<Message> {
        // Prepare oneshot channel
        let (resp_tx, resp_rx) = oneshot::channel();
        // Enqueue write request
        let req = SendRequest {
            query: dns_query.clone(),
            resp_tx,
        };
        self.send_task_sender
            .send(req)
            .await
            .map_err(|_| Error::msg("write channel closed"))?;
        // Wait for response with timeout
        match timeout(self.timeout, resp_rx).await {
            Ok(Ok(msg_result)) => msg_result,
            Ok(Err(_)) => Err(Error::msg("response channel closed")),
            Err(_) => Err(Error::msg("TCP query timeout")),
        }
    }
}

async fn get_connection(
    config: &Config,
) -> Result<(
    ReadHalf<Box<dyn AsyncStream>>,
    WriteHalf<Box<dyn AsyncStream>>,
)> {
    let proxy_stream = match config.proxy_type() {
        ProxyType::None => TcpStream::connect(config.addr()).await?,
        ProxyType::Http => {
            let proxy_addr = config.proxy_addr();
            let upstream_addr = config.addr();
            let mut stream = TcpStream::connect(proxy_addr).await?;
            let req = format!(
                "CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n",
                ip = upstream_addr.ip(),
                port = upstream_addr.port()
            );
            stream.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            loop {
                let mut tmp = [0u8; 1024];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(Error::msg("Proxy closed connection"));
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let header = String::from_utf8_lossy(&buf);
            let status = header.lines().next().unwrap_or("");
            if !status.contains("200") {
                return Err(Error::msg(format!("HTTP CONNECT failed: {}", status)));
            }
            stream
        }
        ProxyType::Socks5 => {
            let proxy_addr = config.proxy_addr();
            let upstream_addr = config.addr();
            Socks5Stream::connect(proxy_addr, upstream_addr)
                .await?
                .into_inner()
        }
    };
    let encrypt_stream: Box<dyn AsyncStream> = match config.encrypt_type() {
        EncryptType::None => Box::new(proxy_stream),
        EncryptType::Tls => {
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(!config.verify_cert())
                .build()?;
            let tls = TlsConnector::from(connector)
                .connect(config.hostname().as_str(), proxy_stream)
                .await?;
            Box::new(tls)
        }
        EncryptType::Https => unreachable!("HTTPS should use HttpsConnection"),
    };
    let (reader, writer) = tokio::io::split(encrypt_stream);
    Ok((reader, writer))
}

async fn read_message(reader: &mut ReadHalf<Box<dyn AsyncStream>>) -> Result<Message> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0; resp_len];
    reader.read_exact(&mut resp_buf).await?;
    let msg = Message::from_vec(&resp_buf)?;
    trace!("Response received, id={}", msg.id());
    Ok(msg)
}

async fn write_message(writer: &mut WriteHalf<Box<dyn AsyncStream>>, msg: &Message) -> Result<()> {
    let bytes = match msg.to_vec() {
        Ok(v) => v,
        Err(e) => {
            error!("DNS message serialization failed: {}", e);
            return Ok(());
        }
    };
    writer
        .write_all(&(bytes.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    trace!("Query sent, id={}", msg.id());
    Ok(())
}

async fn connection_loop_no_reuse_tcp(
    config: Config,
    mut send_task_receiver: mpsc::Receiver<SendRequest>,
) {
    'task_receive_loop: while let Some(SendRequest { query, resp_tx }) =
        send_task_receiver.recv().await
    {
        match get_connection(&config).await {
            Ok((mut reader, mut writer)) => {
                let mut req_msg = query.to_message();
                req_msg.set_id(rand::random());
                if let Err(e) = write_message(&mut writer, &req_msg).await {
                    info!("Error when sending message: {}", e);
                    let _ = resp_tx.send(Err(e));
                    continue 'task_receive_loop;
                }
                let mut resp_msg: Message;
                loop {
                    resp_msg = match read_message(&mut reader).await {
                        Ok(v) => v,
                        Err(e) => {
                            info!("Error when receiving message: {}", e);
                            let _ = resp_tx.send(Err(e));
                            continue 'task_receive_loop;
                        }
                    };
                    if resp_msg.id() == req_msg.id() {
                        break;
                    }
                }
                let _ = resp_tx.send(Ok(resp_msg));
                continue 'task_receive_loop;
            }
            Err(e) => {
                let _ = resp_tx.send(Err(e));
                continue 'task_receive_loop;
            }
        }
    }
}

async fn connection_loop_reuse_tcp(
    config: Config,
    mut send_task_receiver: mpsc::Receiver<SendRequest>,
) {
    let pending_querys: PendingQueryMap = Arc::new(Mutex::new(HashMap::new()));

    // Random starting ID and odd increment for full-cycle permutation
    let mut id_counter: u16 = rand::random();
    let id_inc: u16 = rand::random::<u16>() | 1;

    // Create read task and write task. When both tasks crashed, try reconnect.
    loop {
        match get_connection(&config).await {
            Ok((mut reader, mut writer)) => {
                // read task
                let pending_querys_alias = pending_querys.clone();
                let reader_handle = tokio::spawn(async move {
                    loop {
                        match read_message(&mut reader).await {
                            Ok(msg) => {
                                if let Some(tx) =
                                    pending_querys_alias.lock().await.remove(&msg.id())
                                {
                                    let _ = tx.send(Ok(msg));
                                }
                            }
                            Err(e) => {
                                info!("Error when receiving message: {}", e);
                                break;
                            }
                        }
                    }
                    let mut pending_querys = pending_querys_alias.lock().await;
                    for (_id, tx) in pending_querys.drain() {
                        let _ = tx.send(Err(Error::msg("Connection reset.")));
                    }
                });

                // write task (simply use current thread to simplify code)
                {
                    while let Some(SendRequest { query, resp_tx }) = send_task_receiver.recv().await
                    {
                        let id = id_counter;
                        id_counter = id_counter.wrapping_add(id_inc);
                        let mut msg = query.to_message();
                        msg.set_id(id);
                        pending_querys.lock().await.insert(id, resp_tx);
                        if let Err(e) = write_message(&mut writer, &msg).await {
                            info!("Error when sending message: {}", e);
                            break;
                        }
                    }
                    let mut pending_querys = pending_querys.lock().await;
                    for (_id, tx) in pending_querys.drain() {
                        let _ = tx.send(Err(Error::msg("connection reset")));
                    }
                }
                let _ = reader_handle.await;
            }
            Err(e) => {
                warn!("Cannot establish connection to upstream server: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[async_trait]
impl Connection for TcpConnection {
    async fn query(&self, dns_query: DnsQuery) -> Result<Message> {
        for attempt_id in 0..self.maximum_retry {
            match self.send_and_receive(&dns_query).await {
                Ok(v) => {
                    return Ok(v);
                }
                Err(e) => {
                    info!(
                        "TCP query attempt failed. ({}, {:?}, {}/{})",
                        e,
                        dns_query,
                        attempt_id + 1,
                        self.maximum_retry
                    );
                }
            }
        }
        warn!(
            "TCP query failed after many tries. {} {:?}",
            self.config_str, dns_query
        );
        Err(Error::msg("TCP query failed after retries"))
    }
}
