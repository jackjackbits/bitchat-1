// firmware/common/health/mod.rs
//
// Health monitoring for canary nodes.
// Adapted from SecuraCV's health module — tracks device vitals and
// triggers alerts when thresholds are crossed.
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::TimeBucket;

/// Canary node health snapshot.
#[derive(Clone, Debug)]
pub struct HealthSnapshot {
    /// Free heap memory in bytes.
    pub free_heap_bytes: u32,
    /// Minimum free heap since boot.
    pub min_free_heap_bytes: u32,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Sealed log entry count.
    pub sealed_log_entries: u64,
    /// Connected mesh peer count.
    pub mesh_peer_count: u16,
    /// BLE advertising active.
    pub ble_advertising: bool,
    /// BLE scanning active.
    pub ble_scanning: bool,
    /// Last heartbeat bucket.
    pub last_heartbeat: Option<TimeBucket>,
    /// Total packets relayed since boot.
    pub packets_relayed: u64,
    /// Total gated tweets emitted since boot.
    pub tweets_emitted: u64,
}

/// Health check result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    /// All systems nominal.
    Healthy,
    /// Warning: approaching limits.
    Degraded(String),
    /// Critical: immediate attention needed.
    Critical(String),
}

/// Evaluate health from a snapshot.
pub fn evaluate_health(snapshot: &HealthSnapshot) -> HealthStatus {
    // Critical: very low memory
    if snapshot.free_heap_bytes < 8192 {
        return HealthStatus::Critical(format!(
            "Critically low heap: {} bytes",
            snapshot.free_heap_bytes
        ));
    }

    // Warning: low memory
    if snapshot.free_heap_bytes < 32768 {
        return HealthStatus::Degraded(format!(
            "Low heap: {} bytes",
            snapshot.free_heap_bytes
        ));
    }

    // Warning: no peers
    if snapshot.mesh_peer_count == 0 && snapshot.uptime_secs > 60 {
        return HealthStatus::Degraded("No mesh peers connected".to_string());
    }

    HealthStatus::Healthy
}
