//! Policy canaries (2026-10-27): the shipped policy passes every canary; a policy that lost a law fails it by name.
use cop_policy::{run_canaries, Judge, Policy};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

fn judge(text: &str) -> Judge {
    let policy: Policy = toml::from_str(text).expect("policy parses");
    Judge::new(policy).expect("policy compiles")
}

#[test]
fn the_shipped_policy_passes_every_canary() {
    for r in run_canaries(&judge(DEFAULT)) {
        assert!(r.passed, "canary {} was allowed", r.name);
    }
}

#[test]
fn today_s_broken_rm_quoting_fails_the_rm_canary_by_name() {
    // The 2026-10-27 bug: a single-quoted TOML literal re-wrapped, so the pattern began with two extra quotes.
    let broken = DEFAULT.replacen("pattern = '''rm", "pattern = '''''rm", 1);
    assert_ne!(broken, DEFAULT, "the test must actually break the rule");
    let failed: Vec<&str> = run_canaries(&judge(&broken))
        .into_iter()
        .filter(|r| !r.passed)
        .map(|r| r.name)
        .collect();
    assert!(
        failed.contains(&"rm -rf /"),
        "rm canary must fail: {failed:?}"
    );
}

#[test]
fn a_disabled_hook_guard_downgrades_the_edit_canary_to_ask() {
    // With the guard off, the TOML ask rule for project settings still stops the edit, but it no longer denies.
    let text = format!("{DEFAULT}\n[hook_guard]\nenabled = false\n");
    let edit = run_canaries(&judge(&text))
        .into_iter()
        .find(|r| r.name == "Edit removing the cop-hook entry")
        .expect("canary present");
    assert_eq!(edit.verdict, cop_core::Verdict::Ask);
    assert!(edit.passed, "ask is a catch");
}
