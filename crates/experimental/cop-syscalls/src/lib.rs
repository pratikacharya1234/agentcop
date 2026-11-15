//! File and network syscall observation
//!
//! PLAN:
//! 1. Define SyscallEvent: syscall type, pid, fd, path, args
//! 2. Track file operations: open, read, write, delete, chmod
//! 3. Track network operations: socket, connect, bind, listen
//! 4. Detect suspicious patterns: /etc/shadow, /proc, system dirs
//! 5. Build access maps: per-process file/network graph

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A syscall event from eBPF (file or network operation)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyscallEvent {
    Open {
        pid: u32,
        path: String,
        flags: String, // "read", "write", "append", etc.
    },
    Read {
        pid: u32,
        path: String,
        bytes: u32,
    },
    Write {
        pid: u32,
        path: String,
        bytes: u32,
    },
    Delete {
        pid: u32,
        path: String,
    },
    Chmod {
        pid: u32,
        path: String,
        mode: String,
    },
    Connect {
        pid: u32,
        addr: String,
        port: u16,
    },
    Bind {
        pid: u32,
        addr: String,
        port: u16,
    },
    Listen {
        pid: u32,
        port: u16,
    },
}

impl SyscallEvent {
    /// Get the PID of the process making the syscall
    pub fn pid(&self) -> u32 {
        match self {
            SyscallEvent::Open { pid, .. }
            | SyscallEvent::Read { pid, .. }
            | SyscallEvent::Write { pid, .. }
            | SyscallEvent::Delete { pid, .. }
            | SyscallEvent::Chmod { pid, .. }
            | SyscallEvent::Connect { pid, .. }
            | SyscallEvent::Bind { pid, .. }
            | SyscallEvent::Listen { pid, .. } => *pid,
        }
    }

    /// Check if syscall is suspicious
    pub fn is_suspicious(&self) -> bool {
        match self {
            SyscallEvent::Open { path, .. } | SyscallEvent::Read { path, .. } => {
                // Reading sensitive files
                path.contains("/etc/shadow")
                    || path.contains("/etc/passwd")
                    || path.contains("/.ssh/")
                    || path.contains("/.aws/")
                    || path.contains("/proc/")
                    || path.contains("/.env")
            }
            SyscallEvent::Write { path, .. } => {
                // Writing to system directories or sensitive files
                path.starts_with("/etc/")
                    || path.starts_with("/bin/")
                    || path.starts_with("/sbin/")
                    || path.starts_with("/usr/bin/")
                    || path.starts_with("/root/")
                    || path.contains("/.ssh/")
                    || path.contains("crontab")
                    || path.contains("sudoers")
            }
            SyscallEvent::Delete { path, .. } => {
                // Deleting logs or critical files
                path.contains("/var/log/")
                    || path.contains("/tmp/")
                    || path.starts_with("/etc/")
                    || path.contains("history")
            }
            SyscallEvent::Chmod { path, mode, .. } => {
                // Making files world-readable/writable
                path.contains("/.ssh/") || (mode.contains("777") || mode.contains("666"))
            }
            SyscallEvent::Connect { addr, port, .. } => {
                // Connections to suspicious addresses
                is_suspicious_addr(addr) || is_suspicious_port(*port)
            }
            SyscallEvent::Bind { addr, port, .. } => {
                // Listening on suspicious ports
                is_suspicious_port(*port) || addr == "0.0.0.0"
            }
            SyscallEvent::Listen { port, .. } => {
                // Listening on suspicious ports
                is_suspicious_port(*port)
            }
        }
    }
}

fn is_suspicious_addr(addr: &str) -> bool {
    // Private IP ranges
    addr.starts_with("127.")
        || addr.starts_with("10.")
        || addr.starts_with("172.16.")
        || addr.starts_with("192.168.")
        // Known C2 infrastructure (example)
        || addr == "169.254.169.254" // AWS metadata
}

fn is_suspicious_port(port: u16) -> bool {
    match port {
        // Specific risky services (not all privileged ports - HTTPS on 443 is normal)
        // SQL servers
        1433 | 3306 | 5432 | 5984 => true, // MSSQL, MySQL, PostgreSQL, CouchDB
        // Remote access / shells
        22 | 3389 | 5900 => true, // SSH, RDP, VNC
        // Database admin ports
        6379 => true, // Redis
        // Common backdoor/C2 ports
        4444 | 5555 | 6666 | 7777 | 8888 | 9999 | 31337 | 40404 => true,
        _ => false,
    }
}

/// Access tracker: maps process->files and process->sockets
#[derive(Debug, Clone)]
pub struct AccessMap {
    file_access: HashMap<u32, Vec<(String, String)>>, // pid -> (path, operation)
    network_access: HashMap<u32, Vec<(String, u16)>>, // pid -> (addr, port)
    suspicious_ops: Vec<SyscallEvent>,                // suspicious syscalls
}

impl AccessMap {
    pub fn new() -> Self {
        AccessMap {
            file_access: HashMap::new(),
            network_access: HashMap::new(),
            suspicious_ops: Vec::new(),
        }
    }

    /// Record a syscall event
    pub fn observe(&mut self, event: SyscallEvent) {
        let pid = event.pid();

        match &event {
            SyscallEvent::Open { path, flags, .. } => {
                self.file_access
                    .entry(pid)
                    .or_default()
                    .push((path.clone(), format!("open({})", flags)));
            }
            SyscallEvent::Read { path, bytes, .. } => {
                self.file_access
                    .entry(pid)
                    .or_default()
                    .push((path.clone(), format!("read({}B)", bytes)));
            }
            SyscallEvent::Write { path, bytes, .. } => {
                self.file_access
                    .entry(pid)
                    .or_default()
                    .push((path.clone(), format!("write({}B)", bytes)));
            }
            SyscallEvent::Delete { path, .. } => {
                self.file_access
                    .entry(pid)
                    .or_default()
                    .push((path.clone(), "delete".to_string()));
            }
            SyscallEvent::Chmod { path, mode, .. } => {
                self.file_access
                    .entry(pid)
                    .or_default()
                    .push((path.clone(), format!("chmod({})", mode)));
            }
            SyscallEvent::Connect { addr, port, .. } => {
                self.network_access
                    .entry(pid)
                    .or_default()
                    .push((addr.clone(), *port));
            }
            SyscallEvent::Bind { addr, port, .. } => {
                self.network_access
                    .entry(pid)
                    .or_default()
                    .push((addr.clone(), *port));
            }
            SyscallEvent::Listen { port, .. } => {
                self.network_access
                    .entry(pid)
                    .or_default()
                    .push(("0.0.0.0".to_string(), *port));
            }
        }

        if event.is_suspicious() {
            self.suspicious_ops.push(event);
        }
    }

    /// Get all file accesses for a process
    pub fn get_file_access(&self, pid: u32) -> Vec<(String, String)> {
        self.file_access.get(&pid).cloned().unwrap_or_default()
    }

    /// Get all network accesses for a process
    pub fn get_network_access(&self, pid: u32) -> Vec<(String, u16)> {
        self.network_access.get(&pid).cloned().unwrap_or_default()
    }

    /// Get suspicious operations
    pub fn get_suspicious(&self) -> &[SyscallEvent] {
        &self.suspicious_ops
    }

    /// Count suspicious operations
    pub fn suspicious_count(&self) -> usize {
        self.suspicious_ops.len()
    }

    /// Get unique files accessed by a process
    pub fn get_files_accessed(&self, pid: u32) -> HashSet<String> {
        self.get_file_access(pid)
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Check if process accessed sensitive files
    pub fn accessed_sensitive_files(&self, pid: u32) -> bool {
        self.get_files_accessed(pid).iter().any(|path| {
            path.contains("/etc/shadow")
                || path.contains("/.ssh/")
                || path.contains("/.aws/")
                || path.contains("/.env")
        })
    }

    /// Check if process attempted privilege escalation via suid
    pub fn attempted_suid_chmod(&self, pid: u32) -> bool {
        self.get_file_access(pid)
            .iter()
            .any(|(_path, op)| op.contains("chmod") && op.contains("4"))
        // chmod 4xxx = setuid
    }
}

impl Default for AccessMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_read_not_suspicious() {
        let event = SyscallEvent::Open {
            pid: 1234,
            path: "/tmp/file.txt".to_string(),
            flags: "read".to_string(),
        };
        assert!(!event.is_suspicious());
    }

    #[test]
    fn test_read_shadow_suspicious() {
        let event = SyscallEvent::Read {
            pid: 1234,
            path: "/etc/shadow".to_string(),
            bytes: 1024,
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_read_env_suspicious() {
        let event = SyscallEvent::Read {
            pid: 1234,
            path: "/home/user/.env".to_string(),
            bytes: 512,
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_write_etc_suspicious() {
        let event = SyscallEvent::Write {
            pid: 1234,
            path: "/etc/passwd".to_string(),
            bytes: 256,
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_delete_log_suspicious() {
        let event = SyscallEvent::Delete {
            pid: 1234,
            path: "/var/log/auth.log".to_string(),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_chmod_world_writable_suspicious() {
        let event = SyscallEvent::Chmod {
            pid: 1234,
            path: "/home/user/.ssh/id_rsa".to_string(),
            mode: "666".to_string(),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_connect_privileged_port_suspicious() {
        let event = SyscallEvent::Connect {
            pid: 1234,
            addr: "192.168.1.1".to_string(),
            port: 22,
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_bind_c2_port_suspicious() {
        let event = SyscallEvent::Bind {
            pid: 1234,
            addr: "0.0.0.0".to_string(),
            port: 4444,
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_access_map_tracks_file_ops() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Open {
            pid: 1234,
            path: "/tmp/file.txt".to_string(),
            flags: "write".to_string(),
        });

        let accesses = map.get_file_access(1234);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].0, "/tmp/file.txt");
    }

    #[test]
    fn test_access_map_tracks_network_ops() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Connect {
            pid: 1234,
            addr: "8.8.8.8".to_string(),
            port: 53,
        });

        let accesses = map.get_network_access(1234);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].0, "8.8.8.8");
    }

    #[test]
    fn test_suspicious_ops_tracked() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Read {
            pid: 1234,
            path: "/etc/shadow".to_string(),
            bytes: 1024,
        });

        assert_eq!(map.suspicious_count(), 1);
        assert!(!map.get_suspicious().is_empty());
    }

    #[test]
    fn test_get_files_accessed() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Open {
            pid: 1234,
            path: "/tmp/file1.txt".to_string(),
            flags: "read".to_string(),
        });
        map.observe(SyscallEvent::Read {
            pid: 1234,
            path: "/tmp/file2.txt".to_string(),
            bytes: 512,
        });

        let files = map.get_files_accessed(1234);
        assert_eq!(files.len(), 2);
        assert!(files.contains("/tmp/file1.txt"));
        assert!(files.contains("/tmp/file2.txt"));
    }

    #[test]
    fn test_accessed_sensitive_files() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Read {
            pid: 1234,
            path: "/home/user/.ssh/id_rsa".to_string(),
            bytes: 2048,
        });

        assert!(map.accessed_sensitive_files(1234));
    }

    #[test]
    fn test_multiple_processes_isolated() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Open {
            pid: 1000,
            path: "/tmp/file1.txt".to_string(),
            flags: "read".to_string(),
        });
        map.observe(SyscallEvent::Open {
            pid: 2000,
            path: "/tmp/file2.txt".to_string(),
            flags: "write".to_string(),
        });

        assert_eq!(map.get_file_access(1000).len(), 1);
        assert_eq!(map.get_file_access(2000).len(), 1);
    }

    #[test]
    fn test_attempted_suid_chmod() {
        let mut map = AccessMap::new();
        map.observe(SyscallEvent::Chmod {
            pid: 1234,
            path: "/tmp/binary".to_string(),
            mode: "4755".to_string(),
        });

        assert!(map.attempted_suid_chmod(1234));
    }

    #[test]
    fn test_benign_https_not_flagged() {
        // BUG #7 FIX: HTTPS on 443 should NOT be flagged as suspicious
        // Removed blanket "ports 1-1024" rule that caused false positives
        assert!(
            !super::is_suspicious_port(443),
            "HTTPS on 443 should be benign"
        );
    }

    #[test]
    fn test_benign_dns_not_flagged() {
        // DNS (53) should not be flagged as suspicious
        assert!(!super::is_suspicious_port(53), "DNS on 53 should be benign");
    }

    #[test]
    fn test_benign_ntp_not_flagged() {
        // NTP (123) should not be flagged
        assert!(
            !super::is_suspicious_port(123),
            "NTP on 123 should be benign"
        );
    }

    #[test]
    fn test_specific_risky_ports_still_flagged() {
        // These specific services ARE suspicious and should still be flagged
        assert!(
            super::is_suspicious_port(3306),
            "MySQL on 3306 should be suspicious"
        );
        assert!(
            super::is_suspicious_port(5432),
            "PostgreSQL on 5432 should be suspicious"
        );
        assert!(
            super::is_suspicious_port(6379),
            "Redis on 6379 should be suspicious"
        );
        assert!(
            !super::is_suspicious_port(27017),
            "MongoDB on 27017 should not be flagged (not in specific list)"
        );
    }

    #[test]
    fn test_backdoor_ports_flagged() {
        // Known backdoor/C2 ports should still be flagged
        assert!(super::is_suspicious_port(4444), "Common backdoor port 4444");
        assert!(super::is_suspicious_port(8888), "Common backdoor port 8888");
    }
}
