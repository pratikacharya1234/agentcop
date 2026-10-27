//! Redaction before storage (item 3). Secret-shaped text is masked in every string of an event before the
//! event is written to the evidence store. The patterns come from `[[redact]]` in the policy file, so a user
//! can add their own.
//!
//! PLAN:
//! 1. Compile each pattern once. A bad pattern is an error (fail closed).
//! 2. A match becomes `[REDACTED:<name>]`. Patterns run in policy order.
//! 3. Values are redacted one string at a time. A multi-line key block is one string, not escaped text.

use crate::AgentEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One redaction pattern from the policy file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactRule {
    pub name: String,
    pub pattern: String,
}

/// Compiled redaction patterns.
pub struct Redactor {
    rules: Vec<(String, Regex)>,
}

impl Redactor {
    pub fn new(rules: &[RedactRule]) -> Result<Self, String> {
        let mut compiled = Vec::new();
        for rule in rules {
            let re = Regex::new(&rule.pattern)
                .map_err(|e| format!("bad redact pattern {}: {e}", rule.name))?;
            compiled.push((rule.name.clone(), re));
        }
        Ok(Redactor { rules: compiled })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Mask every match in `text`.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (name, re) in &self.rules {
            let marker = format!("[REDACTED:{name}]");
            out = re.replace_all(&out, marker.as_str()).into_owned();
        }
        out
    }

    /// Mask every string inside a JSON value (object keys are left as they are).
    pub fn value(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.value(v)),
            Value::Object(map) => map.values_mut().for_each(|v| self.value(v)),
            _ => {}
        }
    }

    /// A copy of the event with every string in its input and context masked.
    pub fn event(&self, event: &AgentEvent) -> AgentEvent {
        let mut out = event.clone();
        self.value(&mut out.tool_input);
        for value in out.context.values_mut() {
            self.value(value);
        }
        out
    }
}
