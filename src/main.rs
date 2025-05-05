mod config;
mod dns_proxy;
mod dns_query;
mod dns_server;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use config::Config;
use dns_proxy::DnsProxy;
use dns_query::DnsQuery;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "config/default.yaml")]
    config: String,
}

async fn run(config_path: &str) -> Result<()> {
    let Config {
        listen_addrs,
        dns_server_configs,
    } = Config::from_file(config_path)?;
    let dns_proxy = Arc::new(DnsProxy::new(dns_server_configs).unwrap());
    dns_proxy.listen_and_serve(listen_addrs).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let args = Args::parse();

    match run(&args.config).await {
        Ok(()) => {}
        Err(e) => {
            error!("Server crashed: {:?}", e);
        }
    }
}
