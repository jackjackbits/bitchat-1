// firmware/common/chirp/mod.rs
//
// Chirp — Community Witness Network for bitchat canary mesh.
//
// Adapted from SecuraCV's chirp module. Provides a lightweight
// pub/sub alert system for canary nodes to share privacy-preserving
// events across the bitchat mesh without centralized coordination.
//
// Chirp messages ride on bitchat's public message transport (0x02)
// with a structured payload prefix that canary-aware clients can parse.
//
// Non-canary bitchat clients see chirps as regular public messages
// with a human-readable prefix, maintaining backward compatibility.
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::{CanaryEvent, CanaryEventKind, TimeBucket};

// ---------------------------------------------------------------------------
// Chirp Message
// ---------------------------------------------------------------------------

/// Chirp payload magic prefix (identifies canary chirp in bitchat message).
pub const CHIRP_MAGIC: &[u8; 4] = b"CHR\x01";

/// A chirp alert that can be broadcast over the bitchat mesh.
#[derive(Clone, Debug)]
pub struct ChirpMessage {
    /// Source zone ID.
    pub zone_id: u8,
    /// Alert type.
    pub alert_type: ChirpAlertType,
    /// Time bucket (coarse).
    pub bucket: TimeBucket,
    /// Human-readable summary (for non-canary bitchat clients).
    pub summary: String,
    /// Structured payload (for canary-aware clients).
    pub structured_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChirpAlertType {
    /// Environmental condition change.
    Environmental = 0x01,
    /// Resource availability update.
    ResourceUpdate = 0x02,
    /// Harm reduction service status.
    HarmReductionStatus = 0x03,
    /// Community safety alert.
    SafetyAlert = 0x04,
    /// Canary node status (heartbeat, coming online/offline).
    NodeStatus = 0x05,
}

impl ChirpMessage {
    /// Encode a chirp as a bitchat-compatible public message content string.
    /// Non-canary clients see: "[canary:zone_id] summary_text"
    /// Canary clients parse the structured payload from the prefix.
    pub fn encode_for_bitchat(&self) -> String {
        format!(
            "[canary:z{}] {}",
            self.zone_id, self.summary
        )
    }

    /// Try to parse a chirp from a bitchat public message.
    /// Returns None if the message is not a chirp.
    pub fn parse_from_bitchat(content: &str) -> Option<ChirpMessage> {
        if !content.starts_with("[canary:z") {
            return None;
        }
        let close = content.find(']')?;
        let zone_str = &content[9..close];
        let zone_id: u8 = zone_str.parse().ok()?;
        let summary = content[close + 2..].to_string();

        Some(ChirpMessage {
            zone_id,
            alert_type: ChirpAlertType::NodeStatus, // Default; refined by structured payload
            bucket: TimeBucket::from_epoch(0, 300),  // Caller should set correct bucket
            summary,
            structured_payload: Vec::new(),
        })
    }

    /// Create a chirp from a canary event.
    pub fn from_canary_event(event: &CanaryEvent) -> Option<Self> {
        let (alert_type, summary) = match &event.kind {
            CanaryEventKind::RfPresenceDetected { device_count } => (
                ChirpAlertType::SafetyAlert,
                format!("RF presence: {} devices detected", device_count),
            ),
            CanaryEventKind::RfPresenceCleared => (
                ChirpAlertType::SafetyAlert,
                "RF presence cleared".to_string(),
            ),
            CanaryEventKind::EnvironmentalAlert { metric, value_centi } => (
                ChirpAlertType::Environmental,
                format!("Environmental: {:?} = {:.1}", metric, *value_centi as f64 / 100.0),
            ),
            CanaryEventKind::Heartbeat => (
                ChirpAlertType::NodeStatus,
                "Node heartbeat".to_string(),
            ),
            CanaryEventKind::GatedTweetEmitted { .. } => (
                ChirpAlertType::HarmReductionStatus,
                "Harm reduction update available".to_string(),
            ),
            CanaryEventKind::ConsentChanged { opted_in, .. } => (
                ChirpAlertType::NodeStatus,
                format!(
                    "Harm reduction {}",
                    if *opted_in { "enabled" } else { "disabled" }
                ),
            ),
            _ => return None,
        };

        Some(ChirpMessage {
            zone_id: event.zone_id,
            alert_type,
            bucket: event.bucket,
            summary,
            structured_payload: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Chirp Subscription
// ---------------------------------------------------------------------------

/// Subscription filter for chirp alerts.
#[derive(Clone, Debug)]
pub struct ChirpSubscription {
    /// Zone IDs to subscribe to (empty = all zones).
    pub zone_ids: Vec<u8>,
    /// Alert types to subscribe to (empty = all types).
    pub alert_types: Vec<ChirpAlertType>,
}

impl ChirpSubscription {
    pub fn all() -> Self {
        Self {
            zone_ids: Vec::new(),
            alert_types: Vec::new(),
        }
    }

    pub fn matches(&self, chirp: &ChirpMessage) -> bool {
        let zone_ok = self.zone_ids.is_empty() || self.zone_ids.contains(&chirp.zone_id);
        let type_ok =
            self.alert_types.is_empty() || self.alert_types.contains(&chirp.alert_type);
        zone_ok && type_ok
    }
}
