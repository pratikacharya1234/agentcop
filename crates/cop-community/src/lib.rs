//! Community fun: celebration features, metrics, and engagement dashboards
//!
//! PLAN:
//! 1. Define CommunityMetrics: achievements, milestones, statistics
//! 2. Define Leaderboard: top contributors, most-blocked processes, etc.
//! 3. Define Achievement: badges for defensive milestones
//! 4. Track fun stats: blocks prevented, fastest response time, etc.
//! 5. Generate celebration messages and fun facts

use serde::{Deserialize, Serialize};

/// A community achievement/badge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Achievement {
    FirstBlock,          // Blocked first malicious agent
    CentBlock,           // 100 blocks reached
    SecurityChampion,    // 10+ consecutive days of compliance
    FalsePositiveHunter, // Appeals reviewed and approved
    SpeedDemon,          // Fastest enforcement response
    ZeroTrustVanguard,   // 100% denial rate (suspicious)
    AppealMaster,        // Processed 50+ appeals
    CommunityLeader,     // High compliance and engagement
}

impl Achievement {
    pub fn description(&self) -> &str {
        match self {
            Achievement::FirstBlock => "Blocked the first malicious agent action",
            Achievement::CentBlock => "Reached 100 blocked suspicious actions",
            Achievement::SecurityChampion => "10 consecutive days of 100% compliance",
            Achievement::FalsePositiveHunter => "Approved 10 user appeals",
            Achievement::SpeedDemon => "Fastest enforcement response time",
            Achievement::ZeroTrustVanguard => "Maintained zero-trust approach",
            Achievement::AppealMaster => "Processed and reviewed 50+ appeals",
            Achievement::CommunityLeader => "Community contributor with high engagement",
        }
    }

    pub fn emoji(&self) -> &str {
        match self {
            Achievement::FirstBlock => "🎯",
            Achievement::CentBlock => "💯",
            Achievement::SecurityChampion => "🏆",
            Achievement::FalsePositiveHunter => "🔍",
            Achievement::SpeedDemon => "⚡",
            Achievement::ZeroTrustVanguard => "🛡️",
            Achievement::AppealMaster => "⚖️",
            Achievement::CommunityLeader => "👑",
        }
    }
}

/// Community contributor profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityMember {
    pub name: String,
    pub role: String, // "enforcer", "reviewer", "contributor", "user"
    pub joined: String,
    pub total_actions: u32,
    pub achievements: Vec<Achievement>,
    pub compliance_score: u32,    // 0-100
    pub engagement_level: String, // "inactive", "active", "super_active"
}

impl CommunityMember {
    pub fn new(
        name: impl Into<String>,
        role: impl Into<String>,
        joined: impl Into<String>,
    ) -> Self {
        CommunityMember {
            name: name.into(),
            role: role.into(),
            joined: joined.into(),
            total_actions: 0,
            achievements: Vec::new(),
            compliance_score: 50,
            engagement_level: "active".to_string(),
        }
    }

    pub fn add_achievement(&mut self, achievement: Achievement) {
        if !self.achievements.contains(&achievement) {
            self.achievements.push(achievement);
        }
    }

    pub fn update_compliance_score(&mut self, score: u32) {
        self.compliance_score = score.min(100);
    }

    pub fn update_engagement(&mut self) {
        self.engagement_level = match self.total_actions {
            0..=10 => "inactive",
            11..=100 => "active",
            _ => "super_active",
        }
        .to_string();
    }
}

/// Fun statistics about the community
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityStats {
    pub total_members: usize,
    pub total_blocks_prevented: u32,
    pub total_appeals: u32,
    pub avg_response_time_ms: u32,
    pub highest_compliance_rate: u32,
    pub fun_facts: Vec<String>,
    pub milestones_reached: Vec<String>,
}

impl CommunityStats {
    pub fn new() -> Self {
        CommunityStats {
            total_members: 0,
            total_blocks_prevented: 0,
            total_appeals: 0,
            avg_response_time_ms: 0,
            highest_compliance_rate: 0,
            fun_facts: Vec::new(),
            milestones_reached: Vec::new(),
        }
    }

    pub fn add_fun_fact(&mut self, fact: impl Into<String>) {
        self.fun_facts.push(fact.into());
    }

    pub fn add_milestone(&mut self, milestone: impl Into<String>) {
        self.milestones_reached.push(milestone.into());
    }

    pub fn summary(&self) -> String {
        format!(
            "🎉 Community Stats\n✅ {} suspicious actions blocked\n👥 {} members strong\n⚡ {} ms avg response\n🏅 {}% highest compliance",
            self.total_blocks_prevented,
            self.total_members,
            self.avg_response_time_ms,
            self.highest_compliance_rate
        )
    }
}

impl Default for CommunityStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Community leaderboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityLeaderboard {
    pub period: String,
    pub top_enforcers: Vec<(String, u32)>, // name, blocks count
    pub top_reviewers: Vec<(String, u32)>, // name, appeals reviewed
    pub top_compliance: Vec<(String, u32)>, // name, compliance rate
}

impl CommunityLeaderboard {
    pub fn new(period: impl Into<String>) -> Self {
        CommunityLeaderboard {
            period: period.into(),
            top_enforcers: Vec::new(),
            top_reviewers: Vec::new(),
            top_compliance: Vec::new(),
        }
    }

    pub fn add_enforcer(&mut self, name: impl Into<String>, blocks: u32) {
        self.top_enforcers.push((name.into(), blocks));
        self.top_enforcers
            .sort_by_key(|(_name, count)| std::cmp::Reverse(*count));
        self.top_enforcers.truncate(10);
    }

    pub fn add_reviewer(&mut self, name: impl Into<String>, reviews: u32) {
        self.top_reviewers.push((name.into(), reviews));
        self.top_reviewers
            .sort_by_key(|(_name, count)| std::cmp::Reverse(*count));
        self.top_reviewers.truncate(10);
    }

    pub fn add_compliance(&mut self, name: impl Into<String>, rate: u32) {
        self.top_compliance.push((name.into(), rate));
        self.top_compliance
            .sort_by_key(|(_name, rate)| std::cmp::Reverse(*rate));
        self.top_compliance.truncate(10);
    }

    pub fn format_leaderboard(&self) -> String {
        let mut board = format!("🏆 {} Leaderboard\n\n", self.period);

        if !self.top_enforcers.is_empty() {
            board.push_str("🛡️ Top Enforcers:\n");
            for (i, (name, blocks)) in self.top_enforcers.iter().enumerate() {
                board.push_str(&format!("  {}. {} - {} blocks\n", i + 1, name, blocks));
            }
            board.push('\n');
        }

        if !self.top_reviewers.is_empty() {
            board.push_str("⚖️ Top Reviewers:\n");
            for (i, (name, reviews)) in self.top_reviewers.iter().enumerate() {
                board.push_str(&format!("  {}. {} - {} appeals\n", i + 1, name, reviews));
            }
            board.push('\n');
        }

        if !self.top_compliance.is_empty() {
            board.push_str("📊 Best Compliance:\n");
            for (i, (name, rate)) in self.top_compliance.iter().enumerate() {
                board.push_str(&format!("  {}. {} - {}%\n", i + 1, name, rate));
            }
        }

        board
    }
}

pub struct Community;

impl Community {
    /// Generate celebration message for milestone
    pub fn celebrate_milestone(blocks: u32) -> Option<String> {
        match blocks {
            100 => Some("🎉 Century! 100 suspicious actions blocked!".to_string()),
            500 => Some("🚀 Half-kiloton! 500 blocks and counting!".to_string()),
            1000 => Some("💪 1000 blocks! You're a security champion!".to_string()),
            5000 => Some("🏆 5000 blocks! The community owes you a drink!".to_string()),
            _ => None,
        }
    }

    /// Generate fun fact about security
    pub fn fun_security_fact() -> String {
        let facts = [
            "Did you know? 60% of data breaches involve credentials",
            "Fun fact: AgentCop has prevented X suspicious actions this month",
            "Security tip: Zero-trust means verifying every action, even trusted ones",
            "Celebration: Your team is 10% more secure than last month!",
            "Did you know? Most breaches take months to detect",
        ];
        facts[facts.len() % 5].to_string()
    }

    /// Generate achievement notification
    pub fn achievement_unlocked(achievement: &Achievement) -> String {
        format!(
            "{} Achievement Unlocked!\n{}",
            achievement.emoji(),
            achievement.description()
        )
    }

    /// Generate engagement message
    pub fn engagement_message(compliance_score: u32) -> String {
        match compliance_score {
            90..=100 => "🌟 Security Champion - Keep up the excellent work!".to_string(),
            75..=89 => "📈 Great security posture - You're making a difference".to_string(),
            60..=74 => "👍 Good work - Keep improving your compliance".to_string(),
            _ => "💡 There's room for improvement - Review recent blocks and appeals".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_achievement_descriptions() {
        assert!(!Achievement::FirstBlock.description().is_empty());
        assert!(!Achievement::CentBlock.description().is_empty());
    }

    #[test]
    fn test_achievement_emojis() {
        assert_eq!(Achievement::FirstBlock.emoji(), "🎯");
        assert_eq!(Achievement::CentBlock.emoji(), "💯");
    }

    #[test]
    fn test_community_member_creation() {
        let member = CommunityMember::new("Alice", "enforcer", "2026-01-01");
        assert_eq!(member.name, "Alice");
        assert_eq!(member.role, "enforcer");
    }

    #[test]
    fn test_community_member_add_achievement() {
        let mut member = CommunityMember::new("Bob", "reviewer", "2026-01-01");
        member.add_achievement(Achievement::FirstBlock);
        assert!(member.achievements.contains(&Achievement::FirstBlock));
    }

    #[test]
    fn test_community_member_no_duplicate_achievements() {
        let mut member = CommunityMember::new("Charlie", "enforcer", "2026-01-01");
        member.add_achievement(Achievement::CentBlock);
        member.add_achievement(Achievement::CentBlock);
        assert_eq!(member.achievements.len(), 1);
    }

    #[test]
    fn test_community_stats_summary() {
        let mut stats = CommunityStats::new();
        stats.total_blocks_prevented = 250;
        stats.total_members = 15;
        let summary = stats.summary();
        assert!(summary.contains("250"));
        assert!(summary.contains("15"));
    }

    #[test]
    fn test_community_leaderboard_ordering() {
        let mut leaderboard = CommunityLeaderboard::new("monthly");
        leaderboard.add_enforcer("Alice", 100);
        leaderboard.add_enforcer("Bob", 150);
        leaderboard.add_enforcer("Charlie", 120);

        assert_eq!(leaderboard.top_enforcers[0].0, "Bob");
        assert_eq!(leaderboard.top_enforcers[1].0, "Charlie");
    }

    #[test]
    fn test_celebrate_milestone_100() {
        let msg = Community::celebrate_milestone(100);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("100"));
    }

    #[test]
    fn test_celebrate_milestone_500() {
        let msg = Community::celebrate_milestone(500);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("500"));
    }

    #[test]
    fn test_celebrate_milestone_no_message() {
        let msg = Community::celebrate_milestone(42);
        assert!(msg.is_none());
    }

    #[test]
    fn test_achievement_unlocked() {
        let notif = Community::achievement_unlocked(&Achievement::SecurityChampion);
        assert!(notif.contains("Achievement Unlocked"));
        assert!(notif.contains("🏆"));
    }

    #[test]
    fn test_engagement_message_high_score() {
        let msg = Community::engagement_message(95);
        assert!(msg.contains("Champion"));
    }

    #[test]
    fn test_engagement_message_low_score() {
        let msg = Community::engagement_message(20);
        assert!(msg.contains("improvement"));
    }

    #[test]
    fn test_community_member_update_engagement() {
        let mut member = CommunityMember::new("Diana", "enforcer", "2026-01-01");
        member.total_actions = 50;
        member.update_engagement();
        assert_eq!(member.engagement_level, "active");

        member.total_actions = 150;
        member.update_engagement();
        assert_eq!(member.engagement_level, "super_active");
    }

    #[test]
    fn test_community_member_compliance_score_capped() {
        let mut member = CommunityMember::new("Eve", "reviewer", "2026-01-01");
        member.update_compliance_score(150);
        assert_eq!(member.compliance_score, 100);
    }

    #[test]
    fn test_leaderboard_format() {
        let mut leaderboard = CommunityLeaderboard::new("weekly");
        leaderboard.add_enforcer("Frank", 75);
        let formatted = leaderboard.format_leaderboard();
        assert!(formatted.contains("weekly"));
        assert!(formatted.contains("Frank"));
    }

    #[test]
    fn test_leaderboard_truncate_to_10() {
        let mut leaderboard = CommunityLeaderboard::new("monthly");
        for i in 0..20 {
            leaderboard.add_enforcer(format!("User{}", i), i as u32);
        }
        assert!(leaderboard.top_enforcers.len() <= 10);
    }

    #[test]
    fn test_community_stats_add_fun_fact() {
        let mut stats = CommunityStats::new();
        stats.add_fun_fact("AgentCop prevents attacks 24/7");
        assert_eq!(stats.fun_facts.len(), 1);
    }

    #[test]
    fn test_community_stats_add_milestone() {
        let mut stats = CommunityStats::new();
        stats.add_milestone("1000 blocks reached");
        assert_eq!(stats.milestones_reached.len(), 1);
    }

    #[test]
    fn test_fun_security_fact() {
        let fact = Community::fun_security_fact();
        assert!(!fact.is_empty());
    }

    #[test]
    fn test_leaderboard_multiple_categories() {
        let mut leaderboard = CommunityLeaderboard::new("quarterly");
        leaderboard.add_enforcer("Grace", 100);
        leaderboard.add_reviewer("Henry", 50);
        leaderboard.add_compliance("Iris", 98);

        assert_eq!(leaderboard.top_enforcers.len(), 1);
        assert_eq!(leaderboard.top_reviewers.len(), 1);
        assert_eq!(leaderboard.top_compliance.len(), 1);
    }
}
