// firmware/common/canary/mod.rs
//
// Canary Device — the core ESP32 node logic.
//
// A canary is a stationary or semi-stationary ESP32 device that:
//   1. Participates in the bitchat BLE mesh as an infrastructure node
//   2. Emits privacy-preserving events (SecuraCV witness pattern)
//   3. Can "tweet" gated harm-reduction responses with opt-in consent
//   4. Maintains a tamper-evident sealed log of all emitted events
//   5. Supports break-glass quorum for any raw data access
//
// The canary acts as a bitchat Transport peer — it advertises, connects,
// relays mesh traffic, and can inject gated messages into the mesh timeline.
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::{
    CanaryError, CanaryEvent, CanaryEventKind, CanaryPeerID,
    ObjectClass, TimeBucket, MESH_TTL_DEFAULT,
};
use super::witness::{ChainBuilder, InMemorySealedLog, SealedLogStore};
use super::gated_response::GatedResponseEngine;
use super::harm_reduction::HarmReductionPolicy;

// ---------------------------------------------------------------------------
// Canary Node Configuration
// ---------------------------------------------------------------------------

/// Operating mode for a canary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanaryMode {
    /// Passive relay: forwards mesh traffic, emits heartbeats only.
    Relay,
    /// Witness: emits privacy-preserving events from sensor observations.
    Witness,
    /// Responder: can emit gated harm-reduction tweets (requires opt-in).
    HarmReductionResponder,
    /// Full: all capabilities enabled.
    Full,
}

/// Configuration for a canary node.
/// Loaded from NVS or provisioned via BLE during setup.
#[derive(Clone, Debug)]
pub struct CanaryConfig {
    /// Node operating mode.
    pub mode: CanaryMode,
    /// Bitchat-compatible nickname for mesh presence.
    pub nickname: String,
    /// Zone ID for this node's physical location.
    pub zone_id: u8,
    /// Whether this node has received opt-in consent for its zone.
    pub harm_reduction_opted_in: bool,
    /// Time bucket width in seconds (>= 300, SecuraCV Invariant III).
    pub bucket_width_secs: u64,
    /// Maximum sealed log entries before ring-buffer eviction.
    pub max_log_entries: usize,
    /// Mesh relay: whether to forward other peers' traffic.
    pub relay_enabled: bool,
    /// BLE duty cycle: on duration in milliseconds.
    pub duty_on_ms: u32,
    /// BLE duty cycle: off duration in milliseconds.
    pub duty_off_ms: u32,
    /// Announce interval in milliseconds (bitchat compat).
    pub announce_interval_ms: u32,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            mode: CanaryMode::Relay,
            nickname: String::from("canary"),
            zone_id: 0,
            harm_reduction_opted_in: false,
            bucket_width_secs: 300,
            max_log_entries: 512,
            relay_enabled: true,
            duty_on_ms: 5000,  // 5s on  (matches TransportConfig.bleDutyOnDuration)
            duty_off_ms: 10000, // 10s off (matches TransportConfig.bleDutyOffDuration)
            announce_interval_ms: 4000, // matches TransportConfig.bleAnnounceIntervalSeconds
        }
    }
}

// ---------------------------------------------------------------------------
// Canary Node State Machine
// ---------------------------------------------------------------------------

/// Operational state of the canary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanaryState {
    /// Not yet initialized.
    Uninitialized,
    /// Initializing hardware and loading config.
    Booting,
    /// Active and participating in mesh.
    Active,
    /// Duty-cycle sleep (BLE radio off to save power).
    DutySleep,
    /// Emergency shutdown (e.g., tamper detection).
    Shutdown,
}

// ---------------------------------------------------------------------------
// RF Presence Tracker (from SecuraCV's rf_presence module)
// ---------------------------------------------------------------------------

/// Privacy-preserving RF presence observation.
/// Only stores aggregate counts — never MAC addresses (SecuraCV RF anonymization).
#[derive(Clone, Debug)]
pub struct RfPresenceSnapshot {
    /// Number of unique BLE devices detected in current observation window.
    pub device_count: u16,
    /// Mean RSSI of detected devices.
    pub mean_rssi: i8,
    /// Peak device count in current bucket.
    pub peak_count: u16,
    /// Observation window epoch (coarsened to bucket).
    pub bucket: TimeBucket,
}

/// RF presence FSM states (from SecuraCV rf_presence_architecture.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfPresenceFsmState {
    Empty,
    Impulse,
    Presence,
    Dwelling,
    Departing,
}

// ---------------------------------------------------------------------------
// Canary Node
// ---------------------------------------------------------------------------

/// The main canary node struct. Composes:
///   - Sealed log (witness chain)
///   - Gated response engine (harm-reduction tweets)
///   - RF presence tracker
///   - Mesh relay logic
pub struct CanaryNode {
    /// Node configuration.
    pub config: CanaryConfig,
    /// Current operational state.
    pub state: CanaryState,
    /// Bitchat-compatible peer ID (8 bytes, derived from Noise pubkey).
    pub peer_id: CanaryPeerID,
    /// Sealed event log with hash chain.
    sealed_log: InMemorySealedLog,
    /// Chain builder for constructing new entries.
    chain_builder: ChainBuilder,
    /// Gated response engine for harm-reduction tweets.
    gated_engine: GatedResponseEngine,
    /// Current RF presence FSM state.
    rf_state: RfPresenceFsmState,
    /// Latest RF presence snapshot.
    rf_snapshot: Option<RfPresenceSnapshot>,
    /// Connected bitchat peers (peer_id -> last_seen_ms).
    mesh_peers: Vec<(CanaryPeerID, u64)>,
    /// Messages pending relay (TTL > 0, not yet forwarded).
    relay_queue: Vec<PendingRelay>,
}

/// A message awaiting relay through the mesh.
#[derive(Clone, Debug)]
pub struct PendingRelay {
    /// Raw bitchat packet bytes.
    pub packet: Vec<u8>,
    /// Remaining TTL.
    pub ttl: u8,
    /// Peer the packet arrived from (to avoid echo).
    pub ingress_peer: CanaryPeerID,
    /// Monotonic timestamp when queued.
    pub queued_at_ms: u64,
}

impl CanaryNode {
    /// Create a new canary node with the given config and signing key.
    pub fn new(config: CanaryConfig, noise_pubkey: [u8; 32], ruleset_hash: [u8; 32]) -> Self {
        let peer_id = CanaryPeerID::from_noise_pubkey(&noise_pubkey);
        let harm_policy = HarmReductionPolicy::default_for_zone(config.zone_id);
        Self {
            sealed_log: InMemorySealedLog::new(config.max_log_entries),
            chain_builder: ChainBuilder::new(ruleset_hash),
            gated_engine: GatedResponseEngine::new(harm_policy),
            rf_state: RfPresenceFsmState::Empty,
            rf_snapshot: None,
            mesh_peers: Vec::new(),
            relay_queue: Vec::new(),
            state: CanaryState::Uninitialized,
            peer_id,
            config,
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Initialize the canary node. Call once after hardware init.
    pub fn boot(&mut self) -> Result<(), CanaryError> {
        self.state = CanaryState::Booting;
        // TODO: Load sealed log from NVS, resume chain builder
        // TODO: Initialize BLE radio via HAL
        // TODO: Load consent records from NVS
        self.state = CanaryState::Active;
        Ok(())
    }

    /// Shut down cleanly — flush sealed log, stop BLE.
    pub fn shutdown(&mut self) {
        // TODO: Flush sealed log to NVS
        // TODO: Stop BLE radio
        self.state = CanaryState::Shutdown;
    }

    // -----------------------------------------------------------------------
    // Mesh participation (bitchat protocol compatibility)
    // -----------------------------------------------------------------------

    /// Build a bitchat-compatible announce packet.
    /// Format matches MessageType.announce (0x01) from BitchatProtocol.swift.
    pub fn build_announce_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        // Message type: announce
        packet.push(super::core::bitchat_msg_type::ANNOUNCE);
        // Peer ID (8 bytes)
        packet.extend_from_slice(&self.peer_id.0);
        // Nickname (length-prefixed)
        let nick_bytes = self.config.nickname.as_bytes();
        packet.push(nick_bytes.len() as u8);
        packet.extend_from_slice(nick_bytes);
        // Canary flag: signals this is an infrastructure node, not a human user.
        // Uses reserved flag space in bitchat packet header.
        packet.push(0x01); // is_canary = true
        packet
    }

    /// Process an incoming bitchat packet from BLE.
    /// Returns `Some(packet)` if the packet should be relayed.
    pub fn process_incoming_packet(
        &mut self,
        data: &[u8],
        from_peer: CanaryPeerID,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }

        let msg_type = data[0];

        // Update peer tracking
        self.update_peer_seen(from_peer, now_ms);

        match msg_type {
            super::core::bitchat_msg_type::ANNOUNCE => {
                self.handle_announce(data, from_peer, now_ms);
                None // Don't relay announces (bitchat behavior)
            }
            super::core::bitchat_msg_type::LEAVE => {
                self.handle_leave(from_peer);
                None
            }
            _ => {
                // Relay eligible packets (TTL > 1) if relay mode enabled
                if self.config.relay_enabled {
                    self.maybe_relay(data, from_peer, now_ms)
                } else {
                    None
                }
            }
        }
    }

    /// Attempt to relay a packet. Decrements TTL and queues for forwarding.
    fn maybe_relay(
        &mut self,
        data: &[u8],
        from_peer: CanaryPeerID,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        // Bitchat packet header: [type(1), version(1), ttl(1), ...]
        if data.len() < 3 {
            return None;
        }
        let ttl = data[2];
        if ttl <= 1 {
            return None; // TTL expired
        }

        // Decrement TTL and return for forwarding
        let mut relayed = data.to_vec();
        relayed[2] = ttl - 1;

        self.relay_queue.push(PendingRelay {
            packet: relayed.clone(),
            ttl: ttl - 1,
            ingress_peer: from_peer,
            queued_at_ms: now_ms,
        });

        Some(relayed)
    }

    fn handle_announce(&mut self, _data: &[u8], peer: CanaryPeerID, now_ms: u64) {
        // TODO: Parse nickname and capabilities from announce payload
        self.update_peer_seen(peer, now_ms);
    }

    fn handle_leave(&mut self, peer: CanaryPeerID) {
        self.mesh_peers.retain(|(p, _)| *p != peer);
    }

    fn update_peer_seen(&mut self, peer: CanaryPeerID, now_ms: u64) {
        if let Some(entry) = self.mesh_peers.iter_mut().find(|(p, _)| *p == peer) {
            entry.1 = now_ms;
        } else {
            self.mesh_peers.push((peer, now_ms));
        }
    }

    // -----------------------------------------------------------------------
    // RF presence tracking (SecuraCV rf_presence pattern)
    // -----------------------------------------------------------------------

    /// Update RF presence state from a BLE scan cycle.
    /// Only stores aggregate counts — never individual MAC addresses.
    pub fn update_rf_presence(
        &mut self,
        device_count: u16,
        mean_rssi: i8,
        bucket: TimeBucket,
    ) {
        let prev_state = self.rf_state;

        // FSM transitions (from SecuraCV rf_presence_architecture.md)
        self.rf_state = match (self.rf_state, device_count) {
            (RfPresenceFsmState::Empty, n) if n > 0 => RfPresenceFsmState::Impulse,
            (RfPresenceFsmState::Impulse, n) if n > 0 => RfPresenceFsmState::Presence,
            (RfPresenceFsmState::Impulse, 0) => RfPresenceFsmState::Empty,
            (RfPresenceFsmState::Presence, n) if n > 3 => RfPresenceFsmState::Dwelling,
            (RfPresenceFsmState::Presence, 0) => RfPresenceFsmState::Departing,
            (RfPresenceFsmState::Dwelling, 0) => RfPresenceFsmState::Departing,
            (RfPresenceFsmState::Departing, 0) => RfPresenceFsmState::Empty,
            (RfPresenceFsmState::Departing, n) if n > 0 => RfPresenceFsmState::Presence,
            (state, _) => state,
        };

        let peak = self
            .rf_snapshot
            .as_ref()
            .map(|s| s.peak_count.max(device_count))
            .unwrap_or(device_count);

        self.rf_snapshot = Some(RfPresenceSnapshot {
            device_count,
            mean_rssi,
            peak_count: peak,
            bucket,
        });

        // Emit event on significant transitions
        if prev_state != self.rf_state {
            match self.rf_state {
                RfPresenceFsmState::Presence | RfPresenceFsmState::Dwelling => {
                    let _ = self.record_event(CanaryEvent {
                        bucket,
                        zone_id: self.config.zone_id,
                        kind: CanaryEventKind::RfPresenceDetected { device_count },
                        signature: None,
                    });
                }
                RfPresenceFsmState::Empty => {
                    let _ = self.record_event(CanaryEvent {
                        bucket,
                        zone_id: self.config.zone_id,
                        kind: CanaryEventKind::RfPresenceCleared,
                        signature: None,
                    });
                }
                _ => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // Event recording (sealed log)
    // -----------------------------------------------------------------------

    /// Record an event to the sealed log.
    pub fn record_event(&mut self, event: CanaryEvent) -> Result<u64, CanaryError> {
        // Serialize event (stub — use serde/postcard in production)
        let event_bytes = stub_serialize_event(&event);

        // Build chained entry with domain-separated signature
        let entry = self.chain_builder.build_entry(
            event.bucket,
            event_bytes,
            |hash| {
                // Stub signature — replace with Ed25519 signing in production
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(hash);
                sig
            },
        );

        let index = entry.index;
        self.sealed_log
            .append(entry)
            .map_err(|_| CanaryError::ChainIntegrityError)?;

        Ok(index)
    }

    // -----------------------------------------------------------------------
    // Gated tweet emission
    // -----------------------------------------------------------------------

    /// Attempt to emit a harm-reduction gated tweet into the bitchat mesh.
    /// Requires:
    ///   1. Node is in HarmReductionResponder or Full mode
    ///   2. Opt-in consent is active for this zone
    ///   3. The tweet passes the gated response engine's policy checks
    ///
    /// Returns the bitchat-compatible message packet if approved.
    pub fn emit_gated_tweet(
        &mut self,
        tweet_content: &str,
        bucket: TimeBucket,
    ) -> Result<Vec<u8>, CanaryError> {
        // Mode check
        if self.config.mode != CanaryMode::HarmReductionResponder
            && self.config.mode != CanaryMode::Full
        {
            return Err(CanaryError::ForbiddenEventKind);
        }

        // Consent check (SecuraCV: explicit opt-in required)
        if !self.config.harm_reduction_opted_in {
            return Err(CanaryError::ConsentRequired {
                zone_id: self.config.zone_id,
            });
        }

        // Policy gate — the gated response engine validates content
        let approved = self.gated_engine.evaluate_tweet(tweet_content, bucket)?;

        // Record emission event in sealed log (hash only, not content)
        let tweet_hash = stub_sha256(tweet_content.as_bytes());
        self.record_event(CanaryEvent {
            bucket,
            zone_id: self.config.zone_id,
            kind: CanaryEventKind::GatedTweetEmitted { tweet_hash },
            signature: None,
        })?;

        // Build bitchat-compatible public message packet
        let packet = self.build_tweet_packet(&approved.content);
        Ok(packet)
    }

    /// Build a bitchat MessageType.message (0x02) packet for a gated tweet.
    fn build_tweet_packet(&self, content: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        // Message type: public message
        packet.push(super::core::bitchat_msg_type::MESSAGE);
        // Peer ID (8 bytes)
        packet.extend_from_slice(&self.peer_id.0);
        // TTL
        packet.push(MESH_TTL_DEFAULT);
        // Nickname (length-prefixed)
        let nick = self.config.nickname.as_bytes();
        packet.push(nick.len() as u8);
        packet.extend_from_slice(nick);
        // Content (length-prefixed, 2-byte length for longer messages)
        let content_bytes = content.as_bytes();
        packet.extend_from_slice(&(content_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(content_bytes);
        // Canary tweet marker (so clients can identify gated tweets)
        packet.push(0xCA); // magic byte: canary tweet
        packet
    }

    // -----------------------------------------------------------------------
    // Consent management
    // -----------------------------------------------------------------------

    /// Set opt-in consent for harm-reduction responses in this zone.
    /// Records the consent change in the sealed log for auditability.
    pub fn set_consent(&mut self, opted_in: bool, bucket: TimeBucket) -> Result<(), CanaryError> {
        self.config.harm_reduction_opted_in = opted_in;

        // Record consent change in sealed log
        self.record_event(CanaryEvent {
            bucket,
            zone_id: self.config.zone_id,
            kind: CanaryEventKind::ConsentChanged {
                zone_id: self.config.zone_id,
                opted_in,
            },
            signature: None,
        })?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Heartbeat
    // -----------------------------------------------------------------------

    /// Emit a periodic heartbeat event (mesh liveness indicator).
    pub fn heartbeat(&mut self, bucket: TimeBucket) -> Result<(), CanaryError> {
        self.record_event(CanaryEvent {
            bucket,
            zone_id: self.config.zone_id,
            kind: CanaryEventKind::Heartbeat,
            signature: None,
        })
        .map(|_| ())
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn sealed_log_len(&self) -> u64 {
        self.sealed_log.len()
    }

    pub fn connected_peer_count(&self) -> usize {
        self.mesh_peers.len()
    }

    pub fn rf_presence_state(&self) -> RfPresenceFsmState {
        self.rf_state
    }
}

// ---------------------------------------------------------------------------
// Serialization stubs
// ---------------------------------------------------------------------------

fn stub_serialize_event(event: &CanaryEvent) -> Vec<u8> {
    // Stub — in production use postcard or a compact binary format
    format!("{:?}", event).into_bytes()
}

fn stub_sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
}
