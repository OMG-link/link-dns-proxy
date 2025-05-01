mod config;
mod dns_proxy;
mod dns_query;
mod dns_server;

use std::sync::Arc;

use anyhow::Result;
use tracing::error;

use config::Config;
use dns_proxy::DnsProxy;
use dns_query::DnsQuery;

async fn run() -> Result<()> {
    let Config {
        listen_addrs,
        dns_server_configs,
    } = Config::from_file("config/test.cfg")?;
    let dns_proxy = Arc::new(DnsProxy::new(dns_server_configs).await.unwrap());
    dns_proxy.listen_and_serve(listen_addrs).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    match run().await {
        Ok(()) => {}
        Err(e) => {
            error!("Server crashed: {:?}", e);
        }
    }
}
