//! FP-1 follow-up (2026-10-26, ADR 26): policy TOML can ADD secret file names (`sensitive_files_extra`). The built-in
//! names always apply, so a user cannot remove them by adding names.
use cop_shell::{is_secret_path, is_secret_with};

fn extra() -> Vec<String> {
    vec!["*.secret".to_string(), "vault.json".to_string()]
}

#[test]
fn an_extra_glob_matches_the_basename() {
    assert!(is_secret_with("config/app.secret", &extra()));
    assert!(is_secret_with("/srv/data/prod.secret", &extra()));
}

#[test]
fn an_extra_exact_name_matches_only_that_name() {
    assert!(is_secret_with("vault.json", &extra()));
    assert!(is_secret_with("ops/vault.json", &extra()));
    assert!(!is_secret_with("app.json", &extra()));
    assert!(!is_secret_with("vault.json.bak", &extra()));
}

#[test]
fn an_extra_name_never_removes_a_built_in() {
    assert!(is_secret_with(".env", &extra()));
    assert!(is_secret_with("~/.ssh/id_rsa", &extra()));
    assert!(is_secret_with("~/.agentcop/hmac.key", &extra()));
}

#[test]
fn no_extra_names_is_the_built_in_check() {
    assert_eq!(
        is_secret_with("app.secret", &[]),
        is_secret_path("app.secret")
    );
    assert!(!is_secret_with("app.secret", &[]));
}
