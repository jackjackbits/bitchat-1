// firmware/common/harm_reduction/mod.rs
//
// Harm Reduction Policy — zone-specific rules for gated tweet emission.
//
// This module defines the policy layer that determines:
//   - What types of harm-reduction content a zone can emit
//   - Time-of-day and environmental condition gating
//   - Consent lifecycle (opt-in, renewal, revocation)
//   - Audit requirements for policy changes
//
// Design principles (from both repos):
//   SecuraCV: Positive allowlists, no retroactive expansion, metadata minimization
//   Bitchat:  Privacy by default, no persistent identifiers, BLE mesh locality
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::TimeBucket;

// ---------------------------------------------------------------------------
// Harm Reduction Content Templates
// ---------------------------------------------------------------------------

/// Pre-approved response templates for harm reduction tweets.
/// Content is template-based to prevent arbitrary text injection while
/// still providing useful, timely information.
#[derive(Clone, Debug)]
pub struct ResponseTemplate {
    /// Template identifier (for sealed log reference).
    pub id: u16,
    /// Human-readable category.
    pub category: TemplateCategory,
    /// Template text with `{}` placeholders for dynamic values.
    pub template: String,
    /// Allowed dynamic value types for each placeholder.
    pub slot_types: Vec<SlotType>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateCategory {
    /// Resource location/availability (shelters, water, food, medical).
    ResourceInfo,
    /// Weather/environmental safety.
    EnvironmentalSafety,
    /// General safety tips and guidance.
    SafetyGuidance,
    /// Harm reduction specific: testing availability, safe use info.
    HarmReductionSpecific,
    /// Community mutual aid coordination.
    MutualAid,
    /// Emergency / urgent alert.
    EmergencyAlert,
}

/// Types of dynamic values allowed in template slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotType {
    /// A number (count, temperature, etc.).
    Number,
    /// A time range (e.g., "9am-5pm").
    TimeRange,
    /// A coarse location descriptor (e.g., "zone A", "north area").
    /// Never GPS coordinates (SecuraCV Invariant III).
    CoarseLocation,
    /// A status keyword from a fixed set.
    StatusKeyword,
}

// ---------------------------------------------------------------------------
// Consent Record
// ---------------------------------------------------------------------------

/// An auditable consent record for harm-reduction opt-in.
/// Stored in sealed log and NVS for persistence.
#[derive(Clone, Debug)]
pub struct ConsentRecord {
    /// Zone this consent applies to.
    pub zone_id: u8,
    /// Whether consent is granted.
    pub opted_in: bool,
    /// Time bucket when consent was recorded.
    pub recorded_bucket: TimeBucket,
    /// Ed25519 signature from the consent grantor.
    pub grantor_signature: Option<[u8; 64]>,
    /// Expiry: consent must be renewed after this bucket.
    pub expires_bucket: Option<TimeBucket>,
}

impl ConsentRecord {
    /// Check if this consent is currently valid.
    pub fn is_valid(&self, current_bucket: TimeBucket) -> bool {
        if !self.opted_in {
            return false;
        }
        if let Some(expiry) = self.expires_bucket {
            current_bucket.start_epoch < expiry.start_epoch + expiry.width_secs
        } else {
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Harm Reduction Policy
// ---------------------------------------------------------------------------

/// Zone-specific policy for harm-reduction tweet emission.
pub struct HarmReductionPolicy {
    /// Zone this policy applies to.
    pub zone_id: u8,
    /// Whether the policy is currently active (consent granted + not expired).
    pub active: bool,
    /// Approved response templates for this zone.
    pub templates: Vec<ResponseTemplate>,
    /// Current consent record.
    pub consent: Option<ConsentRecord>,
    /// Maximum tweets per time bucket.
    pub max_tweets_per_bucket: u8,
    /// Tweets emitted in the current bucket.
    tweets_this_bucket: u8,
    /// Current bucket (for reset tracking).
    current_bucket: Option<TimeBucket>,
}

impl HarmReductionPolicy {
    /// Create a default policy for a zone (inactive until consent is granted).
    pub fn default_for_zone(zone_id: u8) -> Self {
        Self {
            zone_id,
            active: false,
            templates: Self::default_templates(),
            consent: None,
            max_tweets_per_bucket: 3,
            tweets_this_bucket: 0,
            current_bucket: None,
        }
    }

    /// Check if the policy permits emission right now.
    pub fn permits_emission(&self) -> bool {
        if !self.active {
            return false;
        }
        self.tweets_this_bucket < self.max_tweets_per_bucket
    }

    /// Record that a tweet was emitted in the current bucket.
    pub fn record_emission(&mut self, bucket: TimeBucket) {
        if self.current_bucket != Some(bucket) {
            // New bucket — reset counter
            self.current_bucket = Some(bucket);
            self.tweets_this_bucket = 0;
        }
        self.tweets_this_bucket += 1;
    }

    /// Grant consent for this zone.
    pub fn grant_consent(&mut self, record: ConsentRecord) {
        self.active = record.opted_in;
        self.consent = Some(record);
    }

    /// Revoke consent for this zone.
    pub fn revoke_consent(&mut self, bucket: TimeBucket) {
        self.active = false;
        self.consent = Some(ConsentRecord {
            zone_id: self.zone_id,
            opted_in: false,
            recorded_bucket: bucket,
            grantor_signature: None,
            expires_bucket: None,
        });
    }

    /// Check and refresh consent validity.
    pub fn refresh_consent(&mut self, current_bucket: TimeBucket) {
        if let Some(ref consent) = self.consent {
            if !consent.is_valid(current_bucket) {
                self.active = false;
            }
        }
    }

    /// Fill a template with dynamic values.
    /// Returns None if template_id not found or slot types don't match.
    pub fn fill_template(
        &self,
        template_id: u16,
        values: &[&str],
    ) -> Option<String> {
        let template = self.templates.iter().find(|t| t.id == template_id)?;

        if values.len() != template.slot_types.len() {
            return None;
        }

        // Simple placeholder replacement
        let mut result = template.template.clone();
        for value in values {
            if let Some(pos) = result.find("{}") {
                result.replace_range(pos..pos + 2, value);
            } else {
                return None; // More values than placeholders
            }
        }

        Some(result)
    }

    /// Default harm-reduction response templates.
    fn default_templates() -> Vec<ResponseTemplate> {
        vec![
            ResponseTemplate {
                id: 1,
                category: TemplateCategory::ResourceInfo,
                template: "Resource available: {} in zone {}".to_string(),
                slot_types: vec![SlotType::StatusKeyword, SlotType::CoarseLocation],
            },
            ResponseTemplate {
                id: 2,
                category: TemplateCategory::EnvironmentalSafety,
                template: "Environmental alert: {} level {} in zone {}".to_string(),
                slot_types: vec![
                    SlotType::StatusKeyword,
                    SlotType::Number,
                    SlotType::CoarseLocation,
                ],
            },
            ResponseTemplate {
                id: 3,
                category: TemplateCategory::SafetyGuidance,
                template: "Safety info: {} — hours: {}".to_string(),
                slot_types: vec![SlotType::StatusKeyword, SlotType::TimeRange],
            },
            ResponseTemplate {
                id: 4,
                category: TemplateCategory::HarmReductionSpecific,
                template: "Harm reduction: {} available at zone {} ({})".to_string(),
                slot_types: vec![
                    SlotType::StatusKeyword,
                    SlotType::CoarseLocation,
                    SlotType::TimeRange,
                ],
            },
            ResponseTemplate {
                id: 5,
                category: TemplateCategory::MutualAid,
                template: "Mutual aid: {} — {} needed in zone {}".to_string(),
                slot_types: vec![
                    SlotType::StatusKeyword,
                    SlotType::StatusKeyword,
                    SlotType::CoarseLocation,
                ],
            },
            ResponseTemplate {
                id: 6,
                category: TemplateCategory::EmergencyAlert,
                template: "ALERT: {} in zone {} — {}".to_string(),
                slot_types: vec![
                    SlotType::StatusKeyword,
                    SlotType::CoarseLocation,
                    SlotType::StatusKeyword,
                ],
            },
        ]
    }
}
