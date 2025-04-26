mod dns_proxy;
mod dns_server;

use anyhow::Result;
use tracing::error;

use dns_proxy::DnsProxy;

async fn run() -> Result<()> {
    let dns_proxy_config = dns_proxy::Config::from_file("config/test.cfg")?;
    let dns_proxy = DnsProxy::new(dns_proxy_config).await.unwrap();
    dns_proxy.listen_and_serve().await?;
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
