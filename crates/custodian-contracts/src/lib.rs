//! Placeholder for the versioned contracts crate.
//!
//! Request, approval, execution, receipt and disclosure contracts, including
//! canonical serialization and digest rules, are defined by issue C2 and must
//! not be invented here. This crate exists so the workspace layout, crate name
//! and dependency direction are fixed before C2 starts. See ADR 0002.

/// Marks that no contract has been defined yet. C2 removes this constant.
pub const CONTRACTS_STATUS: &str = "placeholder: contracts are not defined (C2)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_explicit() {
        assert!(CONTRACTS_STATUS.starts_with("placeholder"));
    }
}
