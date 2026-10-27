//! Egress proxy: intercept and analyze what leaves the machine
//!
//! PLAN:
//! 1. Define EgressEvent: HTTP, DNS, FTP, SSH, raw socket
//! 2. Detect suspicious payloads: credentials, exfiltration patterns
//! 3. Detect command & control: known C2 domains, suspicious User-Agents
//! 4. Track process->egress relationship
//! 5. Score egress events for risk

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// An egress event: data leaving the machine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EgressEvent {
    Http {
        pid: u32,
        method: String,
        host: String,
        path: String,
        body: Option<String>,
    },
    Dns {
        pid: u32,
        query: String,
    },
    Ftp {
        pid: u32,
        host: String,
        username: Option<String>,
        command: String,
    },
    Ssh {
        pid: u32,
        host: String,
        username: String,
    },
    RawSocket {
        pid: u32,
        dest_ip: String,
        dest_port: u16,
        bytes: u32,
    },
}

impl EgressEvent {
    /// Get the PID making the egress connection
    pub fn pid(&self) -> u32 {
        match self {
            EgressEvent::Http { pid, .. }
            | EgressEvent::Dns { pid, .. }
            | EgressEvent::Ftp { pid, .. }
            | EgressEvent::Ssh { pid, .. }
            | EgressEvent::RawSocket { pid, .. } => *pid,
        }
    }

    /// Check if egress event is suspicious
    pub fn is_suspicious(&self) -> bool {
        match self {
            EgressEvent::Http { host, body, .. } => {
                let suspicious_hosts = [
                    "pastebin.com",
                    "0paste.com",
                    "hastebin.com",
                    "ngrok.io",
                    "serveo.net",
                ];
                if suspicious_hosts.iter().any(|h| host.contains(h)) {
                    return true;
                }
                // Check for exfiltration patterns in body
                if let Some(b) = body {
                    if b.len() > 10_000_000 {
                        return true; // > 10MB is suspicious
                    }
                    if b.contains("password") || b.contains("secret") || b.contains("token") {
                        return true;
                    }
                }
                false
            }
            EgressEvent::Dns { query, .. } => {
                // Suspicious DNS patterns: exfiltration via DNS
                query.len() > 253 // max DNS label length is 63 bytes, total 253
                    || query.contains(".ru")
                    || query.contains(".cn")
                    || query.contains("malware")
                    || query.contains("command")
            }
            EgressEvent::Ftp { .. } => {
                // FTP is inherently suspicious (unencrypted)
                true
            }
            EgressEvent::Ssh { host, username, .. } => {
                // SSH to unusual hosts with default credentials
                host.starts_with("192.168.")
                    || host.starts_with("10.")
                    || host.starts_with("172.16.")
                    || username == "root"
                    || username == "admin"
            }
            EgressEvent::RawSocket {
                dest_ip,
                dest_port,
                bytes,
                ..
            } => {
                // Large data transfers on suspicious ports
                (*bytes > 1_000_000) && is_suspicious_port(*dest_port) || is_tor_exit_node(dest_ip)
            }
        }
    }
}

fn is_suspicious_port(port: u16) -> bool {
    matches!(
        port,
        1..=1024 | 4444 | 5555 | 6666 | 7777 | 8888 | 9999 | 31337
    )
}

fn is_tor_exit_node(ip: &str) -> bool {
    // Example Tor exit node patterns (simplified)
    ip.ends_with(".177") || ip.ends_with(".178") || ip.contains("exit")
}

/// Egress tracker: logs all egress events and flags suspicious ones
#[derive(Debug, Clone)]
pub struct EgressMonitor {
    events: Vec<EgressEvent>,
    suspicious: Vec<EgressEvent>,
    process_connections: HashMap<u32, Vec<(String, u16)>>, // pid -> (host, port)
    domain_whitelist: HashSet<String>,
}

impl EgressMonitor {
    pub fn new() -> Self {
        let mut whitelist = HashSet::new();
        // Add common trusted domains
        whitelist.insert("google.com".to_string());
        whitelist.insert("microsoft.com".to_string());
        whitelist.insert("github.com".to_string());
        whitelist.insert("cloudflare.com".to_string());
        whitelist.insert("amazon.com".to_string());

        EgressMonitor {
            events: Vec::new(),
            suspicious: Vec::new(),
            process_connections: HashMap::new(),
            domain_whitelist: whitelist,
        }
    }

    /// Record an egress event
    pub fn observe(&mut self, event: EgressEvent) {
        let pid = event.pid();
        let is_suspicious = event.is_suspicious();

        // Track connection
        match &event {
            EgressEvent::Http { host, .. } => {
                self.process_connections
                    .entry(pid)
                    .or_default()
                    .push((host.clone(), 80));
            }
            EgressEvent::Dns { query, .. } => {
                let port = 53;
                self.process_connections
                    .entry(pid)
                    .or_default()
                    .push((query.clone(), port));
            }
            EgressEvent::Ftp { host, .. } => {
                self.process_connections
                    .entry(pid)
                    .or_default()
                    .push((host.clone(), 21));
            }
            EgressEvent::Ssh { host, .. } => {
                self.process_connections
                    .entry(pid)
                    .or_default()
                    .push((host.clone(), 22));
            }
            EgressEvent::RawSocket {
                dest_ip, dest_port, ..
            } => {
                self.process_connections
                    .entry(pid)
                    .or_default()
                    .push((dest_ip.clone(), *dest_port));
            }
        }

        self.events.push(event.clone());
        if is_suspicious {
            self.suspicious.push(event);
        }
    }

    /// Get all egress events
    pub fn get_events(&self) -> &[EgressEvent] {
        &self.events
    }

    /// Get suspicious egress events
    pub fn get_suspicious(&self) -> &[EgressEvent] {
        &self.suspicious
    }

    /// Count total events
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Count suspicious events
    pub fn suspicious_count(&self) -> usize {
        self.suspicious.len()
    }

    /// Get connections for a process
    pub fn get_connections(&self, pid: u32) -> Vec<(String, u16)> {
        self.process_connections
            .get(&pid)
            .cloned()
            .unwrap_or_default()
    }

    /// Check if domain is whitelisted
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        self.domain_whitelist.iter().any(|w| domain.contains(w))
    }

    /// Check if process attempted data exfiltration (large HTTPS post)
    pub fn check_exfiltration(&self, pid: u32) -> bool {
        self.events.iter().filter(|e| e.pid() == pid).any(|e| {
            if let EgressEvent::Http { method, body, .. } = e {
                method == "POST" && body.is_some() && body.as_ref().unwrap().len() > 1_000_000
            } else {
                false
            }
        })
    }

    /// Check if process created suspicious reverse shell connection
    pub fn check_reverse_shell(&self, pid: u32) -> bool {
        let connections = self.get_connections(pid);
        connections
            .iter()
            .any(|(_, port)| is_suspicious_port(*port) && *port != 80 && *port != 443)
    }

    /// Get unique hosts contacted by process
    pub fn get_unique_hosts(&self, pid: u32) -> HashSet<String> {
        self.process_connections
            .get(&pid)
            .map(|conns| conns.iter().map(|(h, _)| h.clone()).collect())
            .unwrap_or_default()
    }
}

impl Default for EgressMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_pastebin_suspicious() {
        let event = EgressEvent::Http {
            pid: 1234,
            method: "POST".to_string(),
            host: "pastebin.com".to_string(),
            path: "/raw".to_string(),
            body: Some("data".to_string()),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_http_large_body_suspicious() {
        let event = EgressEvent::Http {
            pid: 1234,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            path: "/upload".to_string(),
            body: Some("x".repeat(20_000_000)), // 20MB
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_http_credential_suspicious() {
        let event = EgressEvent::Http {
            pid: 1234,
            method: "POST".to_string(),
            host: "attacker.com".to_string(),
            path: "/log".to_string(),
            body: Some("password=secret123".to_string()),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_dns_exfil_suspicious() {
        let event = EgressEvent::Dns {
            pid: 1234,
            query: "x".repeat(500), // Overly long DNS query
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_ftp_always_suspicious() {
        let event = EgressEvent::Ftp {
            pid: 1234,
            host: "ftp.example.com".to_string(),
            username: Some("user".to_string()),
            command: "GET file.txt".to_string(),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_ssh_root_suspicious() {
        let event = EgressEvent::Ssh {
            pid: 1234,
            host: "example.com".to_string(),
            username: "root".to_string(),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_ssh_private_ip_suspicious() {
        let event = EgressEvent::Ssh {
            pid: 1234,
            host: "192.168.1.100".to_string(),
            username: "user".to_string(),
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_raw_socket_large_transfer_suspicious() {
        let event = EgressEvent::RawSocket {
            pid: 1234,
            dest_ip: "8.8.8.8".to_string(),
            dest_port: 4444,
            bytes: 5_000_000, // 5MB on C2 port
        };
        assert!(event.is_suspicious());
    }

    #[test]
    fn test_monitor_tracks_events() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Http {
            pid: 1234,
            method: "GET".to_string(),
            host: "google.com".to_string(),
            path: "/".to_string(),
            body: None,
        });

        assert_eq!(monitor.event_count(), 1);
        assert!(!monitor.get_events().is_empty());
    }

    #[test]
    fn test_monitor_flags_suspicious() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Ftp {
            pid: 1234,
            host: "attacker.com".to_string(),
            username: Some("hacker".to_string()),
            command: "PUT malware.exe".to_string(),
        });

        assert_eq!(monitor.suspicious_count(), 1);
    }

    #[test]
    fn test_get_connections() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Http {
            pid: 1234,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            body: None,
        });

        let conns = monitor.get_connections(1234);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].0, "example.com");
    }

    #[test]
    fn test_check_exfiltration() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Http {
            pid: 1234,
            method: "POST".to_string(),
            host: "attacker.com".to_string(),
            path: "/data".to_string(),
            body: Some("x".repeat(2_000_000)), // 2MB
        });

        assert!(monitor.check_exfiltration(1234));
    }

    #[test]
    fn test_check_reverse_shell() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::RawSocket {
            pid: 1234,
            dest_ip: "attacker.com".to_string(),
            dest_port: 4444,
            bytes: 1024,
        });

        assert!(monitor.check_reverse_shell(1234));
    }

    #[test]
    fn test_get_unique_hosts() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Http {
            pid: 1234,
            method: "GET".to_string(),
            host: "host1.com".to_string(),
            path: "/".to_string(),
            body: None,
        });
        monitor.observe(EgressEvent::Dns {
            pid: 1234,
            query: "host2.com".to_string(),
        });

        let hosts = monitor.get_unique_hosts(1234);
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_domain_whitelist() {
        let monitor = EgressMonitor::new();
        assert!(monitor.is_whitelisted("github.com"));
        assert!(!monitor.is_whitelisted("attacker.com"));
    }

    #[test]
    fn test_multiple_processes_isolated() {
        let mut monitor = EgressMonitor::new();
        monitor.observe(EgressEvent::Http {
            pid: 1000,
            method: "GET".to_string(),
            host: "host1.com".to_string(),
            path: "/".to_string(),
            body: None,
        });
        monitor.observe(EgressEvent::Http {
            pid: 2000,
            method: "GET".to_string(),
            host: "host2.com".to_string(),
            path: "/".to_string(),
            body: None,
        });

        assert_eq!(monitor.get_connections(1000).len(), 1);
        assert_eq!(monitor.get_connections(2000).len(), 1);
    }
}
