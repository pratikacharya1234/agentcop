use cop_cell::{snapshot, verify_frozen, HoldingCell, Method};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

fn spawn_sleeper() -> Child {
    Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep")
}

/// Process state letter from /proc/<pid>/stat ("T" = stopped).
fn state(pid: u32) -> char {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("proc stat");
    let after_name = stat.rsplit_once(')').expect("stat has name").1;
    after_name.trim_start().chars().next().unwrap()
}

fn fake_root(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("fake-cgroup-{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

/// Make the cgroup dir a kernel would create, with an events file saying what we want.
fn fake_cgroup(root: &Path, name: &str, events: &str) {
    let dir = root.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cgroup.events"), events).unwrap();
}

// ---- snapshot ----

#[test]
fn snapshot_reads_own_cmdline_and_cwd() {
    let me = std::process::id();
    let events = vec!["Bash rm -rf /".to_string()];
    let snap = snapshot(me, &events).expect("own pid must be readable");
    assert!(!snap.cmdline.is_empty());
    assert_eq!(snap.pid, me);
    assert_eq!(
        snap.cwd.as_deref(),
        std::env::current_dir().unwrap().to_str()
    );
    assert_eq!(snap.recent_events, events);
}

#[test]
fn snapshot_of_missing_pid_is_error() {
    assert!(snapshot(0x7fff_fff0, &[]).is_err());
}

// ---- safety ----

#[test]
fn freeze_refuses_init_self_and_empty_lists() {
    let cell = HoldingCell::new(None);
    assert!(cell.freeze("t", &[1]).is_err());
    assert!(cell.freeze("t", &[std::process::id()]).is_err());
    assert!(cell.freeze("t", &[]).is_err());
}

// ---- verify_frozen ----

#[test]
fn verify_frozen_reads_the_frozen_line_only() {
    assert!(verify_frozen("populated 1\nfrozen 1\n"));
    assert!(!verify_frozen("populated 1\nfrozen 0\n"));
    assert!(!verify_frozen("populated 1\n"));
    assert!(!verify_frozen(""));
}

// ---- SIGSTOP path (real child process) ----

#[test]
fn sigstop_freeze_thaw_kill_on_real_child() {
    let mut child = spawn_sleeper();
    let pid = child.id();
    let cell = HoldingCell::new(None);

    let frozen = cell.freeze("sigstop-test", &[pid]).expect("freeze");
    assert_eq!(frozen.method, Method::Sigstop);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(state(pid), 'T', "SIGSTOP must stop the child");

    cell.thaw(&frozen).expect("thaw");
    thread::sleep(Duration::from_millis(50));
    assert_ne!(state(pid), 'T', "SIGCONT must resume the child");

    cell.kill(&frozen).expect("kill");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "killed child must not exit 0");
}

// ---- cgroup path (fake cgroup dir: files only, no kernel) ----

#[test]
fn cgroup_freeze_writes_pid_and_flag_then_thaw_writes_zero() {
    let mut child = spawn_sleeper();
    let pid = child.id();
    let root = fake_root("write-flags");
    fake_cgroup(&root, "session-a", "populated 1\nfrozen 1\n");
    let cell = HoldingCell::new(Some(root.clone()));

    let frozen = cell.freeze("session-a", &[pid]).expect("freeze");
    assert_eq!(frozen.method, Method::Cgroup);
    let dir = root.join("session-a");
    assert_eq!(
        fs::read_to_string(dir.join("cgroup.procs")).unwrap(),
        pid.to_string()
    );
    assert_eq!(fs::read_to_string(dir.join("cgroup.freeze")).unwrap(), "1");

    cell.thaw(&frozen).expect("thaw");
    assert_eq!(fs::read_to_string(dir.join("cgroup.freeze")).unwrap(), "0");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn cgroup_freeze_not_confirmed_falls_back_to_sigstop() {
    let mut child = spawn_sleeper();
    let pid = child.id();
    let root = fake_root("fallback");
    fake_cgroup(&root, "session-b", "populated 1\nfrozen 0\n");
    let cell = HoldingCell::new(Some(root));

    let frozen = cell
        .freeze("session-b", &[pid])
        .expect("freeze must still succeed via fallback");
    assert_eq!(frozen.method, Method::Sigstop);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(state(pid), 'T', "fallback must stop the child");

    cell.kill(&frozen).expect("kill");
    let _ = child.wait();
}
