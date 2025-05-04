use super::{Connection, ProxyType};
use crate::dns_query::DnsQuery;
use crate::dns_server::Config;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, Proxy};
use trust_dns_proto::op::Message;

pub struct HttpsConnection {
    config: Config,
    client: Client,
}

impl HttpsConnection {
    pub fn new(config: Config) -> Result<Self> {
        let mut builder = Client::builder().resolve(config.hostname().as_str(), config.addr());
        if config.proxy_type() != ProxyType::None {
            let proxy_url = match config.proxy_type() {
                ProxyType::None => unreachable!(),
                ProxyType::Http => format!("http://{}", config.proxy_addr()),
                ProxyType::Socks5 => format!("socks5://{}", config.proxy_addr()),
            };
            builder = builder.proxy(Proxy::all(&proxy_url)?);
        }
        let client = builder.build()?;
        Ok(HttpsConnection { config, client })
    }
}

#[async_trait]
impl Connection for HttpsConnection {
    async fn query(&self, dns_query: DnsQuery) -> Result<Message> {
        let msg = dns_query.to_message();
        let bytes = msg.to_vec()?;
        let resp = self
            .client
            .post(format!(
                "https://{}/{}",
                self.config.hostname().as_str(),
                self.config.doh_path()
            ))
            .header("Content-Type", "application/dns-message")
            .body(bytes)
            .send()
            .await?;
        let b = resp.bytes().await?;
        Ok(Message::from_vec(&b)?)
    }
}
