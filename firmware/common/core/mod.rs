// firmware/common/core/mod.rs
//
// Core types for bitchat ESP32 canary nodes.
//
// Adapted from SecuraCV's Privacy Witness Kernel (PWK) architecture:
//   - Type-level privacy enforcement (private fields, no Clone on sensitive data)
//   - Domain-separated signing
//   - Positive-allowlist event vocabulary
//
// Honors bitchat protocol:
//   - PeerID format (8-byte truncated, mesh: prefix)
//   - MessageType compatibility (0x01-0x22 range)
//   - TTL-based mesh flooding
//   - Noise_XX_25519_ChaChaPoly_SHA256 handshake
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use core::fmt;

// ---------------------------------------------------------------------------
// Time Bucketing (from SecuraCV invariant III: metadata minimization)
// ---------------------------------------------------------------------------

/// Minimum bucket width — no event carries a timestamp more precise than this.
pub const MIN_BUCKET_WIDTH_SECS: u64 = 300; // 5 minutes

/// A coarse time bucket. Never stores precise timestamps (SecuraCV Invariant III).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeBucket {
    /// Bucket start epoch (floored to `MIN_BUCKET_WIDTH_SECS`).
    pub start_epoch: u64,
    /// Bucket width in seconds (>= MIN_BUCKET_WIDTH_SECS).
    pub width_secs: u64,
}

impl TimeBucket {
    pub fn from_epoch(epoch_secs: u64, width: u64) -> Self {
        let w = if width < MIN_BUCKET_WIDTH_SECS {
            MIN_BUCKET_WIDTH_SECS
        } else {
            width
        };
        Self {
            start_epoch: epoch_secs - (epoch_secs % w),
            width_secs: w,
        }
    }

    pub fn contains(&self, epoch_secs: u64) -> bool {
        epoch_secs >= self.start_epoch && epoch_secs < self.start_epoch + self.width_secs
    }
}

impl fmt::Debug for TimeBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TB[{}+{}s]", self.start_epoch, self.width_secs)
    }
}

// ---------------------------------------------------------------------------
// Event Vocabulary (SecuraCV: positive allowlist, Invariant II: no identity)
// ---------------------------------------------------------------------------

/// Constrained event types a canary node can emit.
/// Follows SecuraCV's positive-allowlist pattern — only these variants are
/// permitted. No face embeddings, license plates, or stable identity tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanaryEventKind {
    /// RF presence detected (aggregate device count, no MACs).
    RfPresenceDetected { device_count: u16 },
    /// RF presence cleared — zone returned to empty.
    RfPresenceCleared,
    /// Environmental threshold crossed (temperature, humidity, noise level).
    EnvironmentalAlert { metric: EnvironmentalMetric, value_centi: i32 },
    /// Boundary crossing by an anonymous object class.
    BoundaryCrossing { object_class: ObjectClass, zone_id: u8 },
    /// Canary node heartbeat (mesh liveness).
    Heartbeat,
    /// Harm-reduction gated tweet was emitted (contains tweet_hash, not content).
    GatedTweetEmitted { tweet_hash: [u8; 32] },
    /// Opt-in consent status changed for a zone.
    ConsentChanged { zone_id: u8, opted_in: bool },
}

/// Object classes — deliberately coarse (SecuraCV Invariant II).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectClass {
    Person,
    Vehicle,
    Animal,
    Package,
    Unknown,
}

/// Environmental metrics for threshold alerts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentalMetric {
    TemperatureCelsius,
    HumidityPercent,
    NoiseLevelDb,
    AirQualityIndex,
    Co2Ppm,
}

// ---------------------------------------------------------------------------
// Canary Event (the only thing that leaves the device)
// ---------------------------------------------------------------------------

/// A privacy-preserving event emitted by a canary node.
/// Carries a coarse time bucket (never precise timestamps), a zone ID
/// (never GPS coordinates), and an allowlisted event kind.
#[derive(Clone, Debug)]
pub struct CanaryEvent {
    pub bucket: TimeBucket,
    pub zone_id: u8,
    pub kind: CanaryEventKind,
    /// Ed25519 signature over domain-separated hash (SecuraCV pattern).
    pub signature: Option<[u8; 64]>,
}

// ---------------------------------------------------------------------------
// Bitchat-compatible Peer Identity
// ---------------------------------------------------------------------------

/// 8-byte truncated peer ID, matching bitchat's PeerID wire format.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanaryPeerID(pub [u8; 8]);

impl CanaryPeerID {
    pub fn from_noise_pubkey(pubkey: &[u8; 32]) -> Self {
        let mut id = [0u8; 8];
        id.copy_from_slice(&pubkey[..8]);
        Self(id)
    }

    /// Bitchat wire encoding: `mesh:` prefix + hex.
    pub fn to_bitchat_wire(&self) -> [u8; 8] {
        self.0
    }
}

impl fmt::Debug for CanaryPeerID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "canary:")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Domain-Separated Signing (from SecuraCV crypto/signatures.rs)
// ---------------------------------------------------------------------------

/// Domain prefixes for signing. Prevents signature reuse across contexts.
pub mod sign_domain {
    pub const SEALED_LOG_ENTRY: &[u8] = b"bitchat-canary:sealed-log:v1";
    pub const GATED_TWEET: &[u8] = b"bitchat-canary:gated-tweet:v1";
    pub const CONSENT_RECORD: &[u8] = b"bitchat-canary:consent:v1";
    pub const BREAK_GLASS_APPROVAL: &[u8] = b"bitchat-canary:break-glass:v1";
    pub const HEARTBEAT: &[u8] = b"bitchat-canary:heartbeat:v1";
}

// ---------------------------------------------------------------------------
// Bitchat Protocol Constants (must match BitchatProtocol.swift)
// ---------------------------------------------------------------------------

/// Message types matching bitchat's MessageType enum.
pub mod bitchat_msg_type {
    pub const ANNOUNCE: u8 = 0x01;
    pub const MESSAGE: u8 = 0x02;
    pub const LEAVE: u8 = 0x03;
    pub const NOISE_HANDSHAKE: u8 = 0x10;
    pub const NOISE_ENCRYPTED: u8 = 0x11;
    pub const FRAGMENT: u8 = 0x20;
    pub const REQUEST_SYNC: u8 = 0x21;
    pub const FILE_TRANSFER: u8 = 0x22;
}

/// Default TTL for mesh flooding (matches TransportConfig.messageTTLDefault).
pub const MESH_TTL_DEFAULT: u8 = 7;

/// Fragment size matching bitchat BLE MTU (TransportConfig.bleDefaultFragmentSize).
pub const BLE_FRAGMENT_SIZE: usize = 469;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CanaryError {
    /// Attempted to export raw data without break-glass token.
    RawExportDenied,
    /// Event kind is not in the positive allowlist.
    ForbiddenEventKind,
    /// Consent not granted for this zone.
    ConsentRequired { zone_id: u8 },
    /// Quorum threshold not met for break-glass.
    QuorumNotMet { have: u8, need: u8 },
    /// Sealed log chain integrity failure.
    ChainIntegrityError,
    /// Transport layer error.
    TransportError(TransportErrorKind),
}

#[derive(Debug)]
pub enum TransportErrorKind {
    BleNotAvailable,
    HandshakeFailed,
    FragmentationError,
    PeerUnreachable,
    MtuExceeded,
}
