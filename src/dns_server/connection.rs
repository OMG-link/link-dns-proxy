use anyhow::Result;
use async_trait::async_trait;
use trust_dns_proto::op::Message;

use crate::dns_query::DnsQuery;

#[async_trait]
pub trait Connection: Send + Sync {
    async fn query(&self, dns_query: DnsQuery) -> Result<Message>;
}
