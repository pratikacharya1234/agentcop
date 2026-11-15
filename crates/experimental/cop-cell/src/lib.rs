//! Holding cell: freeze an agent's processes, record what they were doing, then thaw or kill them.
//!
//! PLAN:
//! 1. Refuse to freeze pid 0, pid 1, our own pid, or an empty list. Freezing init or ourselves is a bug.
//! 2. Freeze with cgroup v2: move the pids into `<root>/<name>`, write `1` to `cgroup.freeze`, confirm `frozen 1` in `cgroup.events`.
//! 3. If the cgroup path fails or is not confirmed, fall back to SIGSTOP and confirm each pid is stopped (state `T`).
//! 4. Thaw: write `0` to `cgroup.freeze`, or send SIGCONT. Kill: thaw, then SIGKILL each pid.
//! 5. Snapshot: read cmdline and cwd from /proc, plus the recent events the caller passes in.

use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Cgroup,
    Sigstop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub pid: u32,
    pub cmdline: String,
    pub cwd: Option<String>,
    pub recent_events: Vec<String>,
}

/// A frozen group. Pass it back to `thaw` or `kill`.
#[derive(Debug)]
pub struct Frozen {
    pub method: Method,
    pub name: String,
    pub pids: Vec<u32>,
    pub cgroup_dir: Option<PathBuf>,
}

pub struct HoldingCell {
    cgroup_root: Option<PathBuf>,
}

impl HoldingCell {
    /// `None` means no cgroup v2 on this host: SIGSTOP only.
    pub fn new(cgroup_root: Option<PathBuf>) -> Self {
        Self { cgroup_root }
    }

    pub fn freeze(&self, name: &str, pids: &[u32]) -> Result<Frozen, String> {
        guard(pids)?;
        if let Some(root) = &self.cgroup_root {
            match freeze_cgroup(root, name, pids) {
                Ok(frozen) => return Ok(frozen),
                Err(why) => eprintln!("cop-cell: cgroup freeze failed ({why}); using SIGSTOP"),
            }
        }
        freeze_sigstop(name, pids)
    }

    pub fn thaw(&self, frozen: &Frozen) -> Result<(), String> {
        match &frozen.cgroup_dir {
            Some(dir) => write_file(&dir.join("cgroup.freeze"), "0"),
            None => frozen
                .pids
                .iter()
                .try_for_each(|&pid| signal(pid, libc::SIGCONT)),
        }
    }

    pub fn kill(&self, frozen: &Frozen) -> Result<(), String> {
        let _ = self.thaw(frozen);
        for &pid in &frozen.pids {
            match signal(pid, libc::SIGKILL) {
                Ok(()) => {}
                Err(e) if e.contains("No such process") => {}
                Err(e) => return Err(e),
            }
        }
        if let Some(dir) = &frozen.cgroup_dir {
            // May still be busy until the killed processes exit. The kill has already happened.
            let _ = fs::remove_dir(dir);
        }
        Ok(())
    }
}

/// Record what the process is doing. Caller passes in the recent events it already has.
pub fn snapshot(pid: u32, recent_events: &[String]) -> Result<Snapshot, String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).map_err(|e| io_ctx("read cmdline", e))?;
    let cmdline = raw
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_string));
    Ok(Snapshot {
        pid,
        cmdline,
        cwd,
        recent_events: recent_events.to_vec(),
    })
}

/// True when a cgroup.events text says the group is frozen.
pub fn verify_frozen(events: &str) -> bool {
    events.lines().any(|line| line.trim() == "frozen 1")
}

fn guard(pids: &[u32]) -> Result<(), String> {
    if pids.is_empty() {
        return Err("no pids to freeze".to_string());
    }
    let me = std::process::id();
    for &pid in pids {
        if pid <= 1 || pid == me {
            return Err(format!(
                "refusing to freeze pid {pid} (init or the cop itself)"
            ));
        }
    }
    Ok(())
}

fn freeze_cgroup(root: &Path, name: &str, pids: &[u32]) -> Result<Frozen, String> {
    let dir = root.join(name);
    fs::create_dir_all(&dir).map_err(|e| io_ctx("create cgroup dir", e))?;
    for pid in pids {
        write_file(&dir.join("cgroup.procs"), &pid.to_string())?;
    }
    write_file(&dir.join("cgroup.freeze"), "1")?;
    if !wait_for_frozen(&dir.join("cgroup.events"))? {
        let _ = write_file(&dir.join("cgroup.freeze"), "0");
        return Err("cgroup.events does not show frozen 1".to_string());
    }
    Ok(Frozen {
        method: Method::Cgroup,
        name: name.to_string(),
        pids: pids.to_vec(),
        cgroup_dir: Some(dir),
    })
}

fn freeze_sigstop(name: &str, pids: &[u32]) -> Result<Frozen, String> {
    for &pid in pids {
        signal(pid, libc::SIGSTOP)?;
    }
    for &pid in pids {
        wait_for_state(pid, 'T')?;
    }
    Ok(Frozen {
        method: Method::Sigstop,
        name: name.to_string(),
        pids: pids.to_vec(),
        cgroup_dir: None,
    })
}

/// The kernel updates cgroup.events asynchronously after cgroup.freeze is written. Poll for up to one second.
fn wait_for_frozen(events_path: &Path) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let events =
            fs::read_to_string(events_path).map_err(|e| io_ctx("read cgroup.events", e))?;
        if verify_frozen(&events) {
            return Ok(true);
        }
        if Instant::now() > deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// SIGSTOP is not instant. Poll /proc until the process reports stopped, up to one second.
fn wait_for_state(pid: u32, want: char) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if state(pid)? == want {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("pid {pid} did not reach state '{want}'"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Process state letter from /proc/<pid>/stat. The name is in parentheses and may contain spaces.
fn state(pid: u32) -> Result<char, String> {
    let stat =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| io_ctx("read stat", e))?;
    let (_, after_name) = stat.rsplit_once(')').ok_or("stat has no name field")?;
    after_name
        .trim_start()
        .chars()
        .next()
        .ok_or_else(|| "stat has no state".to_string())
}

fn signal(pid: u32, sig: libc::c_int) -> Result<(), String> {
    // SAFETY: kill(2) only sends a signal to the given pid. It reads no memory from us.
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io_ctx(
            &format!("signal {sig} to pid {pid}"),
            io::Error::last_os_error(),
        ))
    }
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|e| io_ctx(&format!("write {}", path.display()), e))
}

fn io_ctx(what: &str, e: io::Error) -> String {
    format!("{what}: {e}")
}
