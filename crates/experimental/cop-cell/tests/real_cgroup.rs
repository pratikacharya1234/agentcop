//! Real cgroup v2 test. Needs a writable cgroup root, so it runs only in the container script.
//! Set AGENTCOP_CELL_CGROUP_ROOT to a writable cgroup2 directory to run it.
use cop_cell::{HoldingCell, Method};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn events_say(dir: &Path, line: &str) -> bool {
    fs::read_to_string(dir.join("cgroup.events"))
        .unwrap()
        .lines()
        .any(|l| l == line)
}

#[test]
fn real_cgroup_freeze_thaw_kill() {
    let Ok(root) = std::env::var("AGENTCOP_CELL_CGROUP_ROOT") else {
        eprintln!("SKIPPED real_cgroup_freeze_thaw_kill: AGENTCOP_CELL_CGROUP_ROOT not set");
        return;
    };
    let root = PathBuf::from(root);
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();
    let cell = HoldingCell::new(Some(root.clone()));

    let frozen = cell
        .freeze("agentcop-real-test", &[child.id()])
        .expect("freeze");
    assert_eq!(
        frozen.method,
        Method::Cgroup,
        "real cgroup must be used, not the fallback"
    );
    let dir = root.join("agentcop-real-test");
    assert!(events_say(&dir, "frozen 1"));

    cell.thaw(&frozen).expect("thaw");
    thread::sleep(Duration::from_millis(50));
    assert!(events_say(&dir, "frozen 0"));

    cell.kill(&frozen).expect("kill");
    let status = child.wait().unwrap();
    assert!(!status.success());
}
