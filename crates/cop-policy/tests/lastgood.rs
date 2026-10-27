//! Item 4b (2026-10-26): which policy the hook runs. The live policy runs only while it passes every canary.
//! Otherwise the last-known-good copy runs, and if that is missing or fails too, the built-in defaults run.
//! Never an empty or weaker policy.
use cop_policy::{canary_failures, choose_policy, PolicySource};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

/// The shipped policy with the rm rule mangled, so `rm -rf /` is no longer caught by the rule.
fn broken_rm() -> String {
    let broken = DEFAULT.replacen("'''rm\\s+", "'''zz\\s+", 1);
    assert_ne!(
        broken, DEFAULT,
        "the rm rule must be found in the shipped policy"
    );
    broken
}

#[test]
fn shipped_policy_passes_every_canary() {
    assert!(canary_failures(DEFAULT).unwrap().is_empty());
}

#[test]
fn mangled_rm_rule_fails_the_rm_canary() {
    let failed = canary_failures(&broken_rm()).unwrap();
    assert!(failed.contains(&"rm -rf /"), "{failed:?}");
}

#[test]
fn live_policy_that_passes_is_used() {
    let chosen = choose_policy(DEFAULT, None).unwrap();
    assert_eq!(chosen.source, PolicySource::Live);
    assert!(chosen.live_failed.is_empty());
    assert_eq!(chosen.text, DEFAULT);
}

#[test]
fn failing_live_policy_falls_back_to_last_known_good() {
    let chosen = choose_policy(&broken_rm(), Some(DEFAULT)).unwrap();
    assert_eq!(chosen.source, PolicySource::LastGood);
    assert!(chosen.live_failed.contains(&"rm -rf /"));
    assert_eq!(chosen.text, DEFAULT);
}

#[test]
fn failing_live_policy_without_last_known_good_uses_builtin_defaults() {
    let chosen = choose_policy(&broken_rm(), None).unwrap();
    assert_eq!(chosen.source, PolicySource::Builtin);
    assert!(chosen.live_failed.contains(&"rm -rf /"));
    assert_eq!(chosen.text, DEFAULT);
}

#[test]
fn a_last_known_good_that_fails_canaries_is_never_used() {
    let chosen = choose_policy(&broken_rm(), Some(&broken_rm())).unwrap();
    assert_eq!(chosen.source, PolicySource::Builtin);
    assert_eq!(chosen.text, DEFAULT);
}

#[test]
fn live_policy_that_does_not_load_is_an_error_not_a_fallback() {
    assert!(choose_policy("this is = not [toml", Some(DEFAULT)).is_err());
}
