use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuery {
    pub domain: Name,
    pub qtype: RecordType,
}

impl DnsQuery {
    pub fn to_message(&self) -> Message {
        let name = self.domain.clone();
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(trust_dns_proto::op::MessageType::Query);
        message.set_op_code(trust_dns_proto::op::OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query({
            let mut q = Query::new();
            q.set_name(name);
            q.set_query_class(DNSClass::IN);
            q.set_query_type(self.qtype);
            q
        });
        message
    }
}
