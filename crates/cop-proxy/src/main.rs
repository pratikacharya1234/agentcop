//! Run the egress proxy.
//!
//! PLAN:
//! 1. Read the policy file named on the command line.
//! 2. Refuse to start if the policy is bad (fail closed).
//! 3. Bind the listen address and serve forever.

use cop_proxy::{serve, EgressPolicy};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: cop-proxy <policy.toml> <listen addr, e.g. 127.0.0.1:8899>");
        return ExitCode::from(2);
    }
    let text = match std::fs::read_to_string(&args[1]) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cop-proxy: cannot read policy {}: {e}", args[1]);
            return ExitCode::from(2);
        }
    };
    let policy = match EgressPolicy::from_toml(&text) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("cop-proxy: {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(&args[2]) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cop-proxy: cannot listen on {}: {e}", args[2]);
            return ExitCode::from(2);
        }
    };
    eprintln!("cop-proxy: listening on {}", args[2]);
    serve(listener, Arc::new(policy));
    ExitCode::SUCCESS
}
