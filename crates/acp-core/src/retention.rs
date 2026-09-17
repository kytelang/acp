//! Sector minimum-retention enforcement (decision v1.2.2).
//!
//! Some sectors mandate that records be kept for a minimum period (SEC 17a-4, FINRA 4511, MiFID II).
//! A purge or tier move must never drop a record below that floor, even if the tenant's own
//! retention setting is shorter. This is the guard the purge path consults: it is fail-closed, a
//! record younger than the floor is never purgeable, regardless of the requested retention.

/// Whether a record of the given age may be purged, honouring both the tenant setting and the
/// mandated floor. The floor always wins: a record is purgeable only if it is older than BOTH.
pub fn purgeable(age_days: u64, tenant_retention_days: u64, mandated_floor_days: u64) -> bool {
    let effective_min = tenant_retention_days.max(mandated_floor_days);
    age_days > effective_min
}

/// The effective retention a tenant is actually held to (never below the mandated floor).
pub fn effective_retention_days(tenant_retention_days: u64, mandated_floor_days: u64) -> u64 {
    tenant_retention_days.max(mandated_floor_days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_below_the_mandated_floor_is_never_purgeable() {
        // Tenant wants 30-day retention, but the sector floor is 7 years (2555 days).
        assert!(
            !purgeable(100, 30, 2555),
            "floor overrides a shorter tenant setting"
        );
        assert_eq!(effective_retention_days(30, 2555), 2555);
    }

    #[test]
    fn a_record_older_than_both_is_purgeable() {
        assert!(
            purgeable(3000, 30, 2555),
            "older than the floor and the tenant setting"
        );
    }

    #[test]
    fn the_longer_of_the_two_always_wins() {
        // Tenant asks for longer than the floor: the tenant setting governs.
        assert!(!purgeable(100, 365, 30));
        assert!(purgeable(400, 365, 30));
    }
}
