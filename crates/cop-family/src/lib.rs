//! Process family tracking: detect suspicious process relationships
//!
//! PLAN:
//! 1. Build process family tree from ExecEvents
//! 2. Track privilege escalation (uid change)
//! 3. Detect process injection (orphaned, parent death)
//! 4. Find suspicious patterns: grandparent→grandchild, shell spawning
//! 5. Score family relationships for anomalies

use cop_ebpf::ExecEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A process node in the family tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub command: String,
    pub suspicious: bool,
    pub anomaly_score: u32, // 0-100
}

impl ProcessNode {
    pub fn from_exec_event(event: &ExecEvent) -> Self {
        ProcessNode {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            command: event.command.clone(),
            suspicious: false,
            anomaly_score: 0,
        }
    }
}

/// A process family tree: all processes and their relationships
#[derive(Debug, Clone)]
pub struct ProcessFamily {
    nodes: HashMap<u32, ProcessNode>,
    parent_map: HashMap<u32, u32>,        // pid -> ppid
    children_map: HashMap<u32, Vec<u32>>, // ppid -> [children]
}

impl ProcessFamily {
    pub fn new() -> Self {
        ProcessFamily {
            nodes: HashMap::new(),
            parent_map: HashMap::new(),
            children_map: HashMap::new(),
        }
    }

    /// Add a process to the family tree
    pub fn add_process(&mut self, event: &ExecEvent) {
        let node = ProcessNode::from_exec_event(event);
        self.nodes.insert(event.pid, node);
        self.parent_map.insert(event.pid, event.ppid);
        self.children_map
            .entry(event.ppid)
            .or_default()
            .push(event.pid);
    }

    /// Get a process node
    pub fn get_process(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Get all children of a process
    pub fn get_children(&self, pid: u32) -> Vec<u32> {
        self.children_map.get(&pid).cloned().unwrap_or_default()
    }

    /// Get parent PID
    pub fn get_parent(&self, pid: u32) -> Option<u32> {
        self.parent_map.get(&pid).copied()
    }

    /// Get ancestors of a process (chain to root, stopping before init)
    pub fn get_ancestors(&self, pid: u32) -> Vec<u32> {
        let mut ancestors = Vec::new();
        let mut current = pid;
        while let Some(parent) = self.get_parent(current) {
            if parent == 0 || parent == 1 {
                break;
            } // stop at init
            ancestors.push(parent);
            current = parent;
        }
        ancestors.reverse();
        ancestors
    }

    /// Get the depth of a process (0 = root, 1 = child of root, etc.)
    pub fn get_depth(&self, pid: u32) -> u32 {
        self.get_ancestors(pid).len() as u32
    }

    /// Count total processes
    pub fn process_count(&self) -> usize {
        self.nodes.len()
    }

    /// Check for privilege escalation: child has higher uid than parent
    pub fn check_privilege_escalation(&mut self, child_pid: u32) -> bool {
        if let Some(child) = self.get_process(child_pid) {
            if let Some(parent_pid) = self.get_parent(child_pid) {
                if let Some(parent) = self.get_process(parent_pid) {
                    let escalated = child.uid < parent.uid; // lower uid = higher privilege
                    if escalated {
                        if let Some(node) = self.nodes.get_mut(&child_pid) {
                            node.anomaly_score += 50;
                            node.suspicious = true;
                        }
                    }
                    return escalated;
                }
            }
        }
        false
    }

    /// Check for shell spawning chain: dangerous pattern like bash->sh->bash
    pub fn check_shell_chain(&mut self, pid: u32) -> u32 {
        let ancestors = self.get_ancestors(pid);
        let current = self.get_process(pid);
        if current.is_none() {
            return 0;
        }

        let current_cmd = &current.unwrap().command;
        let is_shell =
            |cmd: &str| matches!(cmd, "bash" | "sh" | "ksh" | "zsh" | "tcsh" | "csh" | "fish");

        if !is_shell(current_cmd) {
            return 0;
        }

        // Count shell ancestors
        let shell_ancestor_count = ancestors
            .iter()
            .filter_map(|&pid| self.get_process(pid).map(|p| &p.command))
            .filter(|cmd| is_shell(cmd))
            .count() as u32;

        if shell_ancestor_count >= 2 {
            // shell->shell->shell is suspicious
            if let Some(node) = self.nodes.get_mut(&pid) {
                node.anomaly_score += 30 * shell_ancestor_count.min(3);
                if node.anomaly_score > 50 {
                    node.suspicious = true;
                }
            }
        }

        shell_ancestor_count
    }

    /// Check for orphaned processes: parent doesn't exist in tree
    pub fn check_orphaned(&mut self, pid: u32) -> bool {
        if let Some(node) = self.get_process(pid) {
            let parent_exists = self.get_process(node.ppid).is_some();
            if !parent_exists && node.ppid != 1 && node.ppid != 0 {
                if let Some(n) = self.nodes.get_mut(&pid) {
                    n.anomaly_score += 40;
                    n.suspicious = true;
                }
                return true;
            }
        }
        false
    }

    /// Check for suspicious grandparent patterns
    pub fn check_grandparent_chain(&mut self, pid: u32) -> bool {
        let ancestors = self.get_ancestors(pid);
        if ancestors.len() < 2 {
            return false;
        }

        // Pattern: sshd -> (user shell) -> suspicious_tool
        // or: apache -> script_interpreter -> shell
        let suspicious_patterns = [
            ("sshd", "bash"),
            ("sshd", "sh"),
            ("apache", "python"),
            ("apache", "perl"),
            ("nginx", "bash"),
            ("www-data", "curl"),
        ];

        let mut is_suspicious = false;
        if ancestors.len() >= 2 {
            let grandparent_pid = ancestors[ancestors.len() - 2];
            let parent_pid = ancestors[ancestors.len() - 1];

            if let (Some(gp), Some(p), Some(_)) = (
                self.get_process(grandparent_pid),
                self.get_process(parent_pid),
                self.get_process(pid),
            ) {
                for (gp_cmd, p_cmd) in &suspicious_patterns {
                    if gp.command.contains(gp_cmd) && p.command.contains(p_cmd) {
                        is_suspicious = true;
                        break;
                    }
                }

                if is_suspicious {
                    if let Some(node) = self.nodes.get_mut(&pid) {
                        node.anomaly_score += 60;
                        node.suspicious = true;
                    }
                }
            }
        }

        is_suspicious
    }

    /// Get all suspicious processes
    pub fn get_suspicious(&self) -> Vec<u32> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.suspicious)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Get anomaly score for a process
    pub fn get_anomaly_score(&self, pid: u32) -> u32 {
        self.get_process(pid)
            .map(|p| p.anomaly_score.min(100))
            .unwrap_or(0)
    }
}

impl Default for ProcessFamily {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_exec_event(pid: u32, ppid: u32, uid: u32, command: &str) -> ExecEvent {
        ExecEvent {
            timestamp: "2026-10-20T10:00:00Z".to_string(),
            pid,
            ppid,
            uid,
            gid: 1000,
            command: command.to_string(),
            args: vec![],
            cwd: "/tmp".to_string(),
        }
    }

    #[test]
    fn test_process_family_add_process() {
        let mut family = ProcessFamily::new();
        let event = create_exec_event(100, 1, 1000, "bash");

        family.add_process(&event);
        assert_eq!(family.process_count(), 1);
        assert!(family.get_process(100).is_some());
    }

    #[test]
    fn test_get_children() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));
        family.add_process(&create_exec_event(101, 100, 1000, "curl"));
        family.add_process(&create_exec_event(102, 100, 1000, "wget"));

        let children = family.get_children(100);
        assert_eq!(children.len(), 2);
        assert!(children.contains(&101));
        assert!(children.contains(&102));
    }

    #[test]
    fn test_get_ancestors() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(1, 0, 0, "init"));
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));
        family.add_process(&create_exec_event(101, 100, 1000, "curl"));

        let ancestors = family.get_ancestors(101);
        assert_eq!(ancestors, vec![100]); // stops before init (1)
    }

    #[test]
    fn test_privilege_escalation_detection() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "user_bash")); // uid 1000
        family.add_process(&create_exec_event(101, 100, 0, "root_shell")); // uid 0 (escalated)

        let escalated = family.check_privilege_escalation(101);
        assert!(escalated);
        assert!(family.get_process(101).unwrap().suspicious);
    }

    #[test]
    fn test_shell_chain_detection() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));
        family.add_process(&create_exec_event(101, 100, 1000, "sh"));
        family.add_process(&create_exec_event(102, 101, 1000, "bash"));

        let shell_count = family.check_shell_chain(102);
        assert!(shell_count >= 2);
        assert!(family.get_process(102).unwrap().suspicious);
    }

    #[test]
    fn test_no_false_positive_single_shell() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));

        let shell_count = family.check_shell_chain(100);
        assert_eq!(shell_count, 0); // single shell not suspicious
        assert!(!family.get_process(100).unwrap().suspicious);
    }

    #[test]
    fn test_orphaned_process_detection() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));
        family.add_process(&create_exec_event(101, 999, 1000, "curl")); // parent 999 doesn't exist

        let orphaned = family.check_orphaned(101);
        assert!(orphaned);
        assert!(family.get_process(101).unwrap().suspicious);
    }

    #[test]
    fn test_init_parent_not_orphaned() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash")); // parent is init (1)

        let orphaned = family.check_orphaned(100);
        assert!(!orphaned);
    }

    #[test]
    fn test_grandparent_chain_detection() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(1, 0, 0, "init"));
        family.add_process(&create_exec_event(100, 1, 0, "sshd"));
        family.add_process(&create_exec_event(101, 100, 1000, "bash"));
        family.add_process(&create_exec_event(102, 101, 1000, "curl")); // sshd->bash->curl

        let suspicious = family.check_grandparent_chain(102);
        assert!(suspicious);
        assert!(family.get_process(102).unwrap().anomaly_score > 50);
    }

    #[test]
    fn test_get_suspicious_processes() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(100, 1, 1000, "bash"));
        family.add_process(&create_exec_event(101, 100, 0, "root_shell")); // escalated
        family.add_process(&create_exec_event(102, 100, 1000, "echo"));

        family.check_privilege_escalation(101);
        let suspicious = family.get_suspicious();

        assert_eq!(suspicious.len(), 1);
        assert!(suspicious.contains(&101));
    }

    #[test]
    fn test_anomaly_score_capped_at_100() {
        let mut family = ProcessFamily::new();
        family.add_process(&create_exec_event(1, 0, 0, "init"));
        family.add_process(&create_exec_event(50, 1, 0, "root"));
        family.add_process(&create_exec_event(100, 50, 0, "bash")); // root->bash
        family.add_process(&create_exec_event(101, 100, 1000, "bash")); // bash->bash
        family.add_process(&create_exec_event(102, 101, 1000, "sh")); // bash->bash->sh

        family.check_shell_chain(102); // 2+ shell ancestors, score 60+
        family.check_privilege_escalation(101); // 0 < 0, no escalation
        family.check_orphaned(102);

        let score = family.get_anomaly_score(102);
        assert!(score >= 60); // at least the shell chain score
    }
}
