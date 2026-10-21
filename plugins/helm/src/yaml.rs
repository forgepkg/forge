//! Loading the YAML a chart repository serves and stores (`Chart.yaml`,
//! `index.yaml`) within bounds.
//!
//! `yaml-rust2` builds the document tree by cloning an anchored node for
//! every alias that names it, so a few hundred bytes of nested anchors
//! expand to gigabytes. Charts and chart indexes have no use for that, but
//! both are written by others (a pusher, an upstream), so a document is
//! first walked as parser events, which costs no more than its size, and
//! refused when its aliases would expand it by more than
//! [`MAX_ALIAS_NODES`] nodes or when it nests deeper than [`MAX_DEPTH`].

use std::collections::HashMap;
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::{Yaml, YamlLoader};

/// The most nodes that aliases may add to a document, all aliases
/// together. Anchors in a chart or an index are rare and small.
pub const MAX_ALIAS_NODES: u64 = 100_000;

/// The deepest nesting of sequences and mappings a document may have. A
/// chart index nests about six levels deep.
pub const MAX_DEPTH: usize = 64;

/// Load every document of `text`, refusing one that aliases would expand
/// past [`MAX_ALIAS_NODES`] or that nests past [`MAX_DEPTH`].
pub fn load(text: &str) -> Result<Vec<Yaml>, String> {
    let mut budget = Budget::default();
    Parser::new_from_str(text)
        .load(&mut budget, true)
        .map_err(|e| e.to_string())?;
    if budget.deepest > MAX_DEPTH {
        return Err(format!("nested deeper than {MAX_DEPTH} levels"));
    }
    if budget.alias_nodes > MAX_ALIAS_NODES {
        return Err(format!(
            "its aliases expand to more than {MAX_ALIAS_NODES} nodes"
        ));
    }
    YamlLoader::load_from_str(text).map_err(|e| e.to_string())
}

/// Counts what loading a document would build, without building it.
#[derive(Default)]
struct Budget {
    /// Nodes built so far, aliases expanded.
    nodes: u64,
    /// Nodes the aliases added.
    alias_nodes: u64,
    /// Expanded size of each anchored node, by anchor id.
    anchors: HashMap<usize, u64>,
    /// Open sequences and mappings: their anchor id and `nodes` before them.
    open: Vec<(usize, u64)>,
    deepest: usize,
}

impl EventReceiver for Budget {
    fn on_event(&mut self, event: Event) {
        match event {
            Event::Scalar(_, _, anchor, _) => {
                self.nodes = self.nodes.saturating_add(1);
                if anchor > 0 {
                    self.anchors.insert(anchor, 1);
                }
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                self.open.push((anchor, self.nodes));
                self.deepest = self.deepest.max(self.open.len());
                self.nodes = self.nodes.saturating_add(1);
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((anchor, before)) = self.open.pop() {
                    if anchor > 0 {
                        self.anchors.insert(anchor, self.nodes - before);
                    }
                }
            }
            Event::Alias(anchor) => {
                let size = self.anchors.get(&anchor).copied().unwrap_or(1);
                self.nodes = self.nodes.saturating_add(size);
                self.alias_nodes = self.alias_nodes.saturating_add(size);
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `levels` anchors, each a sequence of ten aliases of the previous one.
    fn laughs(levels: usize) -> String {
        let mut doc =
            String::from("name: demo\nversion: 1.0.0\na0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..=levels {
            let prev = format!("*a{}", i - 1);
            doc.push_str(&format!("a{i}: &a{i} [{}]\n", vec![prev; 10].join(", ")));
        }
        doc
    }

    #[test]
    fn plain_documents_and_small_anchors_load() {
        let docs = load("name: demo\nversion: 1.0.0\nkeywords: [a, b]\n").unwrap();
        assert_eq!(docs[0]["name"].as_str(), Some("demo"));
        // A shared block reused a few times is fine.
        let docs = load(&laughs(2)).unwrap();
        assert_eq!(docs[0]["a2"][9][9][9].as_str(), Some("x"));
    }

    #[test]
    fn alias_bombs_are_refused_before_they_expand() {
        // 6 levels expand to over a million nodes (gigabytes once built);
        // the check costs what the 500 bytes cost.
        let err = load(&laughs(6)).unwrap_err();
        assert!(err.contains("aliases"), "{err}");
        let err = load(&laughs(30)).unwrap_err();
        assert!(err.contains("aliases"), "{err}");
    }

    #[test]
    fn deep_nesting_is_refused() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(load(&deep).unwrap_err().contains("deeper"));
        let mut block = String::new();
        for depth in 0..100 {
            block.push_str(&format!("{}k{depth}:\n", "  ".repeat(depth)));
        }
        assert!(load(&block).unwrap_err().contains("deeper"));
        assert!(load(&format!("{}{}", "[".repeat(10), "]".repeat(10))).is_ok());
    }
}
