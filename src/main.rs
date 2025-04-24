mod dns_proxy;
mod dns_server;

use dns_proxy::DnsProxy;

#[tokio::main]
async fn main() {
    let dns_proxy_config = dns_proxy::Config::default();
    let dns_proxy = DnsProxy::new(dns_proxy_config).await.unwrap();
    match dns_proxy.listen_and_serve().await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Server crashed: {}", e);
        }
    }
}
