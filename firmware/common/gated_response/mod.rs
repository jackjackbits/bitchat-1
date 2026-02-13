// firmware/common/gated_response/mod.rs
//
// Gated Response Engine — adapted from SecuraCV's break-glass quorum system.
//
// Provides policy-controlled "gates" that must be passed before any
// harm-reduction tweet is emitted into the bitchat mesh. Gates include:
//   1. Opt-in consent verification (zone-level)
//   2. Content allowlist matching (positive vocabulary only)
//   3. Rate limiting (prevent flooding)
//   4. Optional N-of-M quorum approval for sensitive responses
//   5. Sealed audit trail for every emission decision
//
// The break-glass pattern from SecuraCV is adapted here:
//   - Instead of unlocking raw video frames, we unlock tweet emission
//   - Trustees are mesh peers who have opted-in as approvers
//   - Single-use tokens prevent replay of approvals
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::{CanaryError, CanaryPeerID, TimeBucket};
use super::harm_reduction::HarmReductionPolicy;

// ---------------------------------------------------------------------------
// Gated Response Types
// ---------------------------------------------------------------------------

/// Result of a successful gate evaluation — the approved tweet.
#[derive(Clone, Debug)]
pub struct ApprovedTweet {
    /// The final content (may be modified by policy, e.g., truncated).
    pub content: String,
    /// Hash of the original submitted content.
    pub original_hash: [u8; 32],
    /// Gate that approved it.
    pub gate_id: GateId,
    /// Time bucket when approved.
    pub bucket: TimeBucket,
}

/// Identifies which gate approved a tweet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateId {
    /// Passed automatic policy checks (allowlist + rate limit).
    AutoPolicy,
    /// Required and received quorum approval.
    QuorumApproved { approvals: u8, threshold: u8 },
}

// ---------------------------------------------------------------------------
// Quorum (from SecuraCV break_glass/core.rs)
// ---------------------------------------------------------------------------

/// A trustee who can approve gated responses.
/// Identified by their bitchat Noise fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrusteeId {
    /// Ed25519 public key fingerprint (SHA-256 of Noise static key).
    pub fingerprint: [u8; 32],
    /// Optional human-readable label.
    pub label: Option<String>,
}

/// Quorum policy for gated responses requiring distributed consent.
#[derive(Clone, Debug)]
pub struct QuorumPolicy {
    /// Minimum number of approvals required (N in N-of-M).
    pub threshold: u8,
    /// Maximum number of trustees (M in N-of-M, max 32).
    pub trustees: Vec<TrusteeId>,
}

impl QuorumPolicy {
    pub fn new(threshold: u8, trustees: Vec<TrusteeId>) -> Self {
        assert!(threshold > 0);
        assert!((threshold as usize) <= trustees.len());
        assert!(trustees.len() <= 32);
        Self { threshold, trustees }
    }

    /// Verify that a set of approvals meets the threshold.
    pub fn check_quorum(&self, approvals: &[Approval]) -> bool {
        let valid_count = approvals
            .iter()
            .filter(|a| {
                self.trustees.iter().any(|t| t.fingerprint == a.trustee_fingerprint)
                    && !a.is_expired()
            })
            .count();
        valid_count >= self.threshold as usize
    }
}

/// A single trustee's approval for a gated response.
#[derive(Clone, Debug)]
pub struct Approval {
    /// Fingerprint of the approving trustee.
    pub trustee_fingerprint: [u8; 32],
    /// The request ID this approval is for.
    pub request_id: [u8; 16],
    /// Ed25519 signature over (request_id || trustee_fingerprint || timestamp).
    pub signature: [u8; 64],
    /// Epoch seconds when this approval was created.
    pub created_at_epoch: u64,
    /// Expiry epoch (single-use, time-bounded — SecuraCV pattern).
    pub expires_at_epoch: u64,
}

impl Approval {
    /// Check if this approval has expired.
    pub fn is_expired(&self) -> bool {
        // Stub: in production, compare against wall clock
        false
    }
}

/// A request for quorum approval of a gated tweet.
#[derive(Clone, Debug)]
pub struct GateRequest {
    /// Unique request ID (random nonce).
    pub request_id: [u8; 16],
    /// Hash of the tweet content.
    pub content_hash: [u8; 32],
    /// Zone ID where the tweet would be emitted.
    pub zone_id: u8,
    /// Time bucket for this request.
    pub bucket: TimeBucket,
    /// Collected approvals so far.
    pub approvals: Vec<Approval>,
}

// ---------------------------------------------------------------------------
// Gated Response Engine
// ---------------------------------------------------------------------------

/// The main gate evaluation engine.
pub struct GatedResponseEngine {
    /// Harm reduction policy (vocabulary, rate limits, etc.).
    policy: HarmReductionPolicy,
    /// Optional quorum policy for high-sensitivity responses.
    quorum: Option<QuorumPolicy>,
    /// Pending gate requests awaiting quorum.
    pending_requests: Vec<GateRequest>,
    /// Rate limiter: (bucket_start, emission_count).
    rate_window: Option<(u64, u32)>,
    /// Audit trail: hashes of all approved tweets.
    audit_hashes: Vec<[u8; 32]>,
}

impl GatedResponseEngine {
    pub fn new(policy: HarmReductionPolicy) -> Self {
        Self {
            policy,
            quorum: None,
            pending_requests: Vec::new(),
            rate_window: None,
            audit_hashes: Vec::new(),
        }
    }

    /// Set a quorum policy for responses that exceed automatic policy limits.
    pub fn set_quorum_policy(&mut self, quorum: QuorumPolicy) {
        self.quorum = Some(quorum);
    }

    /// Evaluate whether a tweet should be emitted.
    ///
    /// Checks in order:
    ///   1. Content matches positive allowlist vocabulary
    ///   2. Rate limit not exceeded
    ///   3. If quorum required, sufficient approvals collected
    ///
    /// Returns the approved tweet if all gates pass.
    pub fn evaluate_tweet(
        &mut self,
        content: &str,
        bucket: TimeBucket,
    ) -> Result<ApprovedTweet, CanaryError> {
        // Gate 1: Vocabulary allowlist
        let sanitized = self.policy.check_vocabulary(content)?;

        // Gate 2: Rate limiting
        self.check_rate_limit(bucket)?;

        // Gate 3: Quorum (if configured and content is high-sensitivity)
        let gate_id = if self.policy.requires_quorum(content) {
            if let Some(ref quorum) = self.quorum {
                // Look for a pending request with matching content hash
                let content_hash = stub_sha256(content.as_bytes());
                let request = self.pending_requests.iter().find(|r| r.content_hash == content_hash);

                match request {
                    Some(req) if quorum.check_quorum(&req.approvals) => {
                        GateId::QuorumApproved {
                            approvals: req.approvals.len() as u8,
                            threshold: quorum.threshold,
                        }
                    }
                    _ => {
                        return Err(CanaryError::QuorumNotMet {
                            have: request.map(|r| r.approvals.len() as u8).unwrap_or(0),
                            need: quorum.threshold,
                        });
                    }
                }
            } else {
                // No quorum configured but content requires it — deny
                return Err(CanaryError::QuorumNotMet { have: 0, need: 1 });
            }
        } else {
            GateId::AutoPolicy
        };

        // Update rate limiter
        self.record_emission(bucket);

        // Record in audit trail
        let original_hash = stub_sha256(content.as_bytes());
        self.audit_hashes.push(original_hash);

        Ok(ApprovedTweet {
            content: sanitized,
            original_hash,
            gate_id,
            bucket,
        })
    }

    /// Submit a gate request for quorum approval.
    /// Returns the request ID for tracking.
    pub fn submit_gate_request(
        &mut self,
        content: &str,
        zone_id: u8,
        bucket: TimeBucket,
        request_nonce: [u8; 16],
    ) -> [u8; 16] {
        let content_hash = stub_sha256(content.as_bytes());
        self.pending_requests.push(GateRequest {
            request_id: request_nonce,
            content_hash,
            zone_id,
            bucket,
            approvals: Vec::new(),
        });
        request_nonce
    }

    /// Add a trustee approval to a pending gate request.
    pub fn add_approval(
        &mut self,
        request_id: &[u8; 16],
        approval: Approval,
    ) -> Result<(), CanaryError> {
        let request = self
            .pending_requests
            .iter_mut()
            .find(|r| &r.request_id == request_id);

        match request {
            Some(req) => {
                // Prevent duplicate approvals from same trustee
                if !req.approvals.iter().any(|a| a.trustee_fingerprint == approval.trustee_fingerprint) {
                    req.approvals.push(approval);
                }
                Ok(())
            }
            None => Err(CanaryError::ForbiddenEventKind), // request not found
        }
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    fn check_rate_limit(&self, bucket: TimeBucket) -> Result<(), CanaryError> {
        if let Some((window_start, count)) = self.rate_window {
            if bucket.start_epoch == window_start && count >= self.policy.max_tweets_per_bucket {
                return Err(CanaryError::ForbiddenEventKind);
            }
        }
        Ok(())
    }

    fn record_emission(&mut self, bucket: TimeBucket) {
        match self.rate_window {
            Some((start, count)) if start == bucket.start_epoch => {
                self.rate_window = Some((start, count + 1));
            }
            _ => {
                self.rate_window = Some((bucket.start_epoch, 1));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Break-Glass Receipt (SecuraCV audit pattern)
// ---------------------------------------------------------------------------

/// Immutable audit receipt for quorum-approved gated responses.
/// Stored in the sealed log alongside the tweet emission event.
#[derive(Clone, Debug)]
pub struct BreakGlassReceipt {
    /// The gate request ID.
    pub request_id: [u8; 16],
    /// Hash of approved content.
    pub content_hash: [u8; 32],
    /// Commitment hash over all approval signatures.
    pub approvals_commitment: [u8; 32],
    /// Number of approvals that were collected.
    pub approval_count: u8,
    /// Threshold that was required.
    pub threshold: u8,
    /// Zone ID.
    pub zone_id: u8,
    /// Time bucket.
    pub bucket: TimeBucket,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn stub_sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
}
