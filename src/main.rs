mod dns_proxy;
mod dns_server;

use dns_proxy::DnsProxy;
use tracing::error;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let dns_proxy_config = dns_proxy::Config::default();
    let dns_proxy = DnsProxy::new(dns_proxy_config).await.unwrap();
    match dns_proxy.listen_and_serve().await {
        Ok(()) => {}
        Err(e) => {
            error!("Server crashed: {}", e);
        }
    }
}
