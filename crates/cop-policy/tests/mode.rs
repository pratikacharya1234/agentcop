//! The policy's `mode` key: enforce (default) or log-only. Unknown values must fail.
use cop_policy::{Mode, Policy};

const RULES: &str = "[[rules]]\npattern = \"rm\"\nverdict = \"deny\"\n";

#[test]
fn mode_defaults_to_enforce() {
    let p: Policy = toml::from_str(RULES).unwrap();
    assert_eq!(p.mode, Mode::Enforce);
}

#[test]
fn mode_log_only_parses() {
    let p: Policy = toml::from_str(&format!("mode = \"log-only\"\n{RULES}")).unwrap();
    assert_eq!(p.mode, Mode::LogOnly);
}

#[test]
fn unknown_mode_is_an_error() {
    assert!(toml::from_str::<Policy>(&format!("mode = \"maybe\"\n{RULES}")).is_err());
}
