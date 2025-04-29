use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::Record;

type DnsCacheKey = crate::dns_query::DnsQuery;

pub struct DnsCacheEntry {
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    inserted_at: Instant,
    expires_at: Instant,
}

impl DnsCacheEntry {
    pub fn new(message: Arc<Message>) -> Self {
        let now = Instant::now();

        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();

        answers.extend(message.answers().iter().cloned());
        authorities.extend(message.name_servers().iter().cloned());
        additionals.extend(message.additionals().iter().cloned());

        let min_ttl = answers
            .iter()
            .chain(&authorities)
            .chain(&additionals)
            .map(|r| r.ttl())
            .min()
            .unwrap_or(0);

        let expires_at = now + Duration::from_secs(min_ttl as u64);

        Self {
            answers,
            authorities,
            additionals,
            inserted_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn get_message(&self) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        msg.set_recursion_desired(true);
        msg.set_recursion_available(true);

        let elapsed_secs = self.inserted_at.elapsed().as_secs() as u32;

        msg.add_answers(self.adjust_ttl(&self.answers, elapsed_secs));
        msg.add_name_servers(self.adjust_ttl(&self.authorities, elapsed_secs));
        msg.add_additionals(self.adjust_ttl(&self.additionals, elapsed_secs));

        msg
    }

    fn adjust_ttl(&self, records: &[Record], elapsed_secs: u32) -> Vec<Record> {
        records
            .iter()
            .map(|r| {
                let mut new_rec = r.clone();
                let new_ttl = r.ttl().saturating_sub(elapsed_secs);
                new_rec.set_ttl(new_ttl);
                new_rec
            })
            .collect()
    }
}

pub type DnsCache = HashMap<DnsCacheKey, DnsCacheEntry>;
