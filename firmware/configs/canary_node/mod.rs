// firmware/configs/canary_node/mod.rs
//
// Product configuration for the bitchat canary node.
//
// Follows SecuraCV's config layering: configs/ provides product-level
// defaults that are composed with board pin maps in projects/.
//
// Two product configurations:
//   - canary_relay:  Passive mesh relay (minimal, ESP32-C3)
//   - canary_full:   Full witness + harm reduction (ESP32-S3)
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Product: Canary Relay (ESP32-C3, minimal)
// ---------------------------------------------------------------------------

/// Configuration for a passive mesh relay canary.
/// Low-power, no sensors, just forwards bitchat traffic.
pub fn canary_relay() -> super::super::common::canary::CanaryConfig {
    super::super::common::canary::CanaryConfig {
        mode: super::super::common::canary::CanaryMode::Relay,
        nickname: String::from("relay"),
        zone_id: 0,
        harm_reduction_opted_in: false,
        bucket_width_secs: 300,
        max_log_entries: 128, // Small log, relay-only
        relay_enabled: true,
        duty_on_ms: 3000,   // Shorter duty cycle for power savings
        duty_off_ms: 15000,
        announce_interval_ms: 4000,
    }
}

// ---------------------------------------------------------------------------
// Product: Canary Full (ESP32-S3, all capabilities)
// ---------------------------------------------------------------------------

/// Configuration for a full-featured canary with witness + harm reduction.
/// Requires sensors, more RAM, and explicit opt-in consent.
pub fn canary_full() -> super::super::common::canary::CanaryConfig {
    super::super::common::canary::CanaryConfig {
        mode: super::super::common::canary::CanaryMode::Full,
        nickname: String::from("canary"),
        zone_id: 1,
        harm_reduction_opted_in: false, // Must be explicitly opted in
        bucket_width_secs: 300,
        max_log_entries: 512,
        relay_enabled: true,
        duty_on_ms: 5000,
        duty_off_ms: 10000,
        announce_interval_ms: 4000,
    }
}

// ---------------------------------------------------------------------------
// Product: Canary Harm Reduction Responder (ESP32-S3 or C3)
// ---------------------------------------------------------------------------

/// Configuration specifically for harm-reduction tweet responders.
/// Does not need camera/vision — just BLE mesh and response engine.
pub fn canary_responder() -> super::super::common::canary::CanaryConfig {
    super::super::common::canary::CanaryConfig {
        mode: super::super::common::canary::CanaryMode::HarmReductionResponder,
        nickname: String::from("hrnode"),
        zone_id: 1,
        harm_reduction_opted_in: false, // Must be explicitly opted in
        bucket_width_secs: 300,
        max_log_entries: 256,
        relay_enabled: true,
        duty_on_ms: 5000,
        duty_off_ms: 10000,
        announce_interval_ms: 4000,
    }
}
