use trust_dns_proto::rr::RecordType;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuery {
    pub domain: String,
    pub qtype: RecordType,
}
