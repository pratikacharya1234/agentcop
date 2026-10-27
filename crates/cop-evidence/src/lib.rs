//! Hash-chained, append-only SQLite evidence store
//!
//! PLAN:
//! 1. Create SQLite schema with hash chain column
//! 2. Implement append operation that stores previous hash
//! 3. Implement verify() to check chain integrity
//! 4. Guard against edit/delete with integrity checks
//! 5. Performance: 10k entries verify in <1s

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // Phase A4 will add evidence store tests
    }
}
