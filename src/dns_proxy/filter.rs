use std::collections::HashMap;

use trust_dns_proto::rr::Name;

struct Node {
    children: HashMap<String, Node>,
    exact: Vec<usize>,
    wildcard: Vec<usize>,
}

impl Node {
    fn new() -> Self {
        Node {
            children: HashMap::new(),
            exact: Vec::new(),
            wildcard: Vec::new(),
        }
    }
}

pub struct FilterTrie {
    root: Node,
}

impl FilterTrie {
    pub fn new() -> Self {
        Self { root: Node::new() }
    }

    pub fn insert(&mut self, pattern: &String, server_idx: usize) {
        // special case
        if pattern.eq("*") {
            self.root.wildcard.push(server_idx);
            return;
        }
        // process pattern
        let is_wildcard = pattern.starts_with("*.");
        let domain = if is_wildcard {
            &pattern[2..]
        } else {
            pattern.as_str()
        };
        let labels_rev: Vec<String> = domain
            .to_lowercase()
            .split('.')
            .rev()
            .map(|s| s.to_string())
            .collect();
        // insert to trie
        let mut node = &mut self.root;
        for label in labels_rev {
            node = node.children.entry(label.clone()).or_insert_with(Node::new);
        }
        let bucket = if is_wildcard {
            &mut node.wildcard
        } else {
            &mut node.exact
        };
        bucket.push(server_idx);
    }

    pub fn query(&self, domain: &Name) -> Vec<usize> {
        let labels_rev: Vec<String> = domain
            .to_ascii()
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .split('.')
            .rev()
            .map(|s| s.to_string())
            .collect();

        let mut matched_idxs: Vec<usize> = Vec::new();
        let mut node = &self.root;
        'collect_idx: {
            for label in labels_rev.iter() {
                matched_idxs.extend(&node.wildcard);
                if let Some(child) = node.children.get(label) {
                    node = child;
                } else {
                    break 'collect_idx;
                }
            }
            matched_idxs.extend(&node.exact);
        }
        matched_idxs.sort();
        matched_idxs.dedup();
        matched_idxs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::rr::Name;

    fn parse_name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn test_exact_match() {
        let mut trie = FilterTrie::new();
        trie.insert(&"example.com".to_string(), 1);
        trie.insert(&"example.com".to_string(), 2);

        let result = trie.query(&parse_name("example.com."));
        assert_eq!(result, vec![1, 2]);

        let result_none = trie.query(&parse_name("sub.example.com."));
        assert!(result_none.is_empty());
    }

    #[test]
    fn test_wildcard_match() {
        let mut trie = FilterTrie::new();
        trie.insert(&"*.example.com".to_string(), 3);
        trie.insert(&"*".to_string(), 4);

        let result1 = trie.query(&parse_name("sub.example.com."));
        assert_eq!(result1, vec![3, 4]);

        let result2 = trie.query(&parse_name("example.com."));
        assert_eq!(result2, vec![4]);
    }

    #[test]
    fn test_combined_match() {
        let mut trie = FilterTrie::new();
        trie.insert(&"*".to_string(), 0);
        trie.insert(&"example.com".to_string(), 1);
        trie.insert(&"*.example.com".to_string(), 2);
        trie.insert(&"*.sub.example.com".to_string(), 3);

        let result1 = trie.query(&parse_name("example.com."));
        assert_eq!(result1, vec![0, 1]);

        let result2 = trie.query(&parse_name("a.example.com."));
        assert_eq!(result2, vec![0, 2]);

        let result3 = trie.query(&parse_name("b.sub.example.com."));
        assert_eq!(result3, vec![0, 2, 3]);

        let result4 = trie.query(&parse_name("sub.example.com."));
        assert_eq!(result4, vec![0, 2]);
    }

    #[test]
    fn test_deduplication_and_ordering() {
        let mut trie = FilterTrie::new();
        trie.insert(&"*.example.com".to_string(), 5);
        trie.insert(&"*.example.com".to_string(), 3);
        trie.insert(&"*.example.com".to_string(), 3); // duplicate

        let result = trie.query(&parse_name("a.example.com."));
        assert_eq!(result, vec![3, 5]); // sorted, deduped
    }
}
