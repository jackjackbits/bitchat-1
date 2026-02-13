// firmware/common/transport/mod.rs
//
// BLE Mesh Transport — bitchat-compatible transport layer for ESP32 canary nodes.
//
// This module bridges the ESP32 BLE radio (via HAL) to bitchat's protocol:
//   - Dual-role BLE (peripheral + central), matching BLEService.swift
//   - Fragmentation/reassembly at 469-byte MTU (TransportConfig.bleDefaultFragmentSize)
//   - TTL-based mesh flooding with probabilistic relay
//   - Noise_XX_25519_ChaChaPoly_SHA256 handshake stubs
//   - Announce/leave lifecycle matching BitchatProtocol.swift
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::{
    bitchat_msg_type, CanaryError, CanaryPeerID, TransportErrorKind,
    BLE_FRAGMENT_SIZE, MESH_TTL_DEFAULT,
};

// ---------------------------------------------------------------------------
// Fragment assembly (matches bitchat MessageType.fragment = 0x20)
// ---------------------------------------------------------------------------

/// Fragment header layout (matches bitchat protocol):
///   [0]    = 0x20 (fragment type)
///   [1..5] = transfer_id (4 bytes)
///   [5..7] = fragment_index (2 bytes, big-endian)
///   [7..9] = total_fragments (2 bytes, big-endian)
///   [9..]  = payload chunk
const FRAGMENT_HEADER_SIZE: usize = 9;

/// Maximum concurrent fragment assemblies (TransportConfig.bleMaxInFlightAssemblies).
const MAX_IN_FLIGHT_ASSEMBLIES: usize = 128;

/// Fragment lifetime before eviction (TransportConfig.bleFragmentLifetimeSeconds).
const FRAGMENT_LIFETIME_MS: u64 = 30_000;

/// A partially-assembled fragmented message.
#[derive(Clone, Debug)]
pub struct FragmentAssembly {
    pub transfer_id: u32,
    pub total_fragments: u16,
    pub received: Vec<Option<Vec<u8>>>,
    pub started_at_ms: u64,
}

impl FragmentAssembly {
    pub fn new(transfer_id: u32, total_fragments: u16, now_ms: u64) -> Self {
        Self {
            transfer_id,
            total_fragments,
            received: vec![None; total_fragments as usize],
            started_at_ms: now_ms,
        }
    }

    /// Insert a fragment. Returns true if assembly is now complete.
    pub fn insert(&mut self, index: u16, payload: Vec<u8>) -> bool {
        if (index as usize) < self.received.len() {
            self.received[index as usize] = Some(payload);
        }
        self.is_complete()
    }

    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|f| f.is_some())
    }

    /// Reassemble the complete message from fragments.
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut data = Vec::new();
        for fragment in &self.received {
            if let Some(ref chunk) = fragment {
                data.extend_from_slice(chunk);
            }
        }
        Some(data)
    }

    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_at_ms) > FRAGMENT_LIFETIME_MS
    }
}

// ---------------------------------------------------------------------------
// Mesh Packet Builder
// ---------------------------------------------------------------------------

/// Builds bitchat-compatible wire packets.
pub struct PacketBuilder;

impl PacketBuilder {
    /// Build an announce packet (MessageType.announce = 0x01).
    pub fn announce(peer_id: &CanaryPeerID, nickname: &str, is_canary: bool) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(bitchat_msg_type::ANNOUNCE);
        pkt.extend_from_slice(&peer_id.0);
        let nick = nickname.as_bytes();
        pkt.push(nick.len().min(255) as u8);
        pkt.extend_from_slice(&nick[..nick.len().min(255)]);
        if is_canary {
            pkt.push(0x01); // canary infrastructure flag
        }
        pkt
    }

    /// Build a leave packet (MessageType.leave = 0x03).
    pub fn leave(peer_id: &CanaryPeerID) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(bitchat_msg_type::LEAVE);
        pkt.extend_from_slice(&peer_id.0);
        pkt
    }

    /// Build a public message packet (MessageType.message = 0x02).
    pub fn public_message(
        peer_id: &CanaryPeerID,
        nickname: &str,
        content: &str,
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(bitchat_msg_type::MESSAGE);
        pkt.extend_from_slice(&peer_id.0);
        pkt.push(ttl);
        let nick = nickname.as_bytes();
        pkt.push(nick.len().min(255) as u8);
        pkt.extend_from_slice(&nick[..nick.len().min(255)]);
        let content_bytes = content.as_bytes();
        pkt.extend_from_slice(&(content_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(content_bytes);
        pkt
    }

    /// Fragment a large packet into BLE-MTU-sized chunks.
    /// Returns fragment packets ready for transmission.
    pub fn fragment(transfer_id: u32, data: &[u8]) -> Vec<Vec<u8>> {
        let chunk_size = BLE_FRAGMENT_SIZE - FRAGMENT_HEADER_SIZE;
        let total = ((data.len() + chunk_size - 1) / chunk_size) as u16;
        let mut fragments = Vec::new();

        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let mut pkt = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
            pkt.push(bitchat_msg_type::FRAGMENT);
            pkt.extend_from_slice(&transfer_id.to_be_bytes());
            pkt.extend_from_slice(&(i as u16).to_be_bytes());
            pkt.extend_from_slice(&total.to_be_bytes());
            pkt.extend_from_slice(chunk);
            fragments.push(pkt);
        }

        fragments
    }
}

// ---------------------------------------------------------------------------
// Noise Handshake Stubs
// ---------------------------------------------------------------------------

/// Noise_XX_25519_ChaChaPoly_SHA256 handshake state.
/// Stub — actual implementation would use snow or noise-protocol crate.
#[derive(Clone, Debug)]
pub enum NoiseHandshakeState {
    /// No handshake initiated.
    None,
    /// Initiator: sent first message, waiting for response.
    InitSent,
    /// Responder: received init, sent response, waiting for final.
    RespSent,
    /// Handshake complete — transport keys established.
    Established {
        /// Remote peer's static Noise public key.
        remote_static: [u8; 32],
    },
    /// Handshake failed.
    Failed,
}

/// Minimal Noise session for canary <-> bitchat peer communication.
pub struct NoiseSession {
    pub state: NoiseHandshakeState,
    pub local_static_pubkey: [u8; 32],
    // Stub: actual session would hold CipherState pairs for send/receive
}

impl NoiseSession {
    pub fn new(local_static_pubkey: [u8; 32]) -> Self {
        Self {
            state: NoiseHandshakeState::None,
            local_static_pubkey,
        }
    }

    /// Initiate a Noise_XX handshake (build first message).
    pub fn initiate(&mut self) -> Result<Vec<u8>, CanaryError> {
        // Stub — actual impl uses snow::Builder
        self.state = NoiseHandshakeState::InitSent;
        let mut msg = Vec::new();
        msg.push(bitchat_msg_type::NOISE_HANDSHAKE);
        msg.extend_from_slice(&self.local_static_pubkey);
        // TODO: Actual Noise XX message 1 (ephemeral key)
        Ok(msg)
    }

    /// Process an incoming handshake message.
    pub fn process_handshake(&mut self, _data: &[u8]) -> Result<Option<Vec<u8>>, CanaryError> {
        // Stub — advance handshake FSM
        match self.state {
            NoiseHandshakeState::None => {
                // We're responder — build response
                self.state = NoiseHandshakeState::RespSent;
                let mut msg = Vec::new();
                msg.push(bitchat_msg_type::NOISE_HANDSHAKE);
                msg.extend_from_slice(&self.local_static_pubkey);
                Ok(Some(msg))
            }
            NoiseHandshakeState::InitSent => {
                // Received response — handshake complete
                self.state = NoiseHandshakeState::Established {
                    remote_static: [0u8; 32], // TODO: extract from message
                };
                Ok(None) // No more messages needed
            }
            _ => Err(CanaryError::TransportError(TransportErrorKind::HandshakeFailed)),
        }
    }

    /// Encrypt a payload for the established session.
    pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, CanaryError> {
        match self.state {
            NoiseHandshakeState::Established { .. } => {
                // Stub — actual impl uses CipherState.encrypt_with_ad()
                Ok(Vec::new())
            }
            _ => Err(CanaryError::TransportError(TransportErrorKind::HandshakeFailed)),
        }
    }

    /// Decrypt a payload from the established session.
    pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, CanaryError> {
        match self.state {
            NoiseHandshakeState::Established { .. } => {
                // Stub — actual impl uses CipherState.decrypt_with_ad()
                Ok(Vec::new())
            }
            _ => Err(CanaryError::TransportError(TransportErrorKind::HandshakeFailed)),
        }
    }
}

// ---------------------------------------------------------------------------
// Mesh Transport Manager
// ---------------------------------------------------------------------------

/// Manages the BLE mesh transport for a canary node.
/// Handles:
///   - Dual-role BLE (advertising + scanning)
///   - Fragment assembly/disassembly
///   - Noise session management per peer
///   - Relay queue with TTL enforcement
///   - Deduplication (ingress record matching bitchat pattern)
pub struct MeshTransport {
    /// Local peer identity.
    pub local_peer_id: CanaryPeerID,
    /// Active fragment assemblies.
    assemblies: Vec<FragmentAssembly>,
    /// Noise sessions indexed by peer.
    noise_sessions: Vec<(CanaryPeerID, NoiseSession)>,
    /// Recent packet hashes for deduplication.
    /// Ring buffer of (hash, timestamp_ms).
    dedup_ring: Vec<([u8; 8], u64)>,
    /// Maximum dedup entries (TransportConfig.messageDedupMaxCount).
    dedup_capacity: usize,
    /// Next transfer ID for outgoing fragments.
    next_transfer_id: u32,
}

impl MeshTransport {
    pub fn new(local_peer_id: CanaryPeerID) -> Self {
        Self {
            local_peer_id,
            assemblies: Vec::new(),
            noise_sessions: Vec::new(),
            dedup_ring: Vec::new(),
            dedup_capacity: 1000,
            next_transfer_id: 1,
        }
    }

    /// Process an incoming BLE notification (raw bytes from a peer).
    /// Returns reassembled/decoded data if a complete message is ready.
    pub fn process_incoming(
        &mut self,
        data: &[u8],
        from_peer: CanaryPeerID,
        now_ms: u64,
    ) -> Option<(CanaryPeerID, Vec<u8>)> {
        if data.is_empty() {
            return None;
        }

        // Deduplication check
        let pkt_hash = quick_hash(data);
        if self.is_duplicate(&pkt_hash, now_ms) {
            return None;
        }
        self.record_seen(pkt_hash, now_ms);

        match data[0] {
            bitchat_msg_type::FRAGMENT => {
                self.handle_fragment(data, from_peer, now_ms)
            }
            bitchat_msg_type::NOISE_HANDSHAKE => {
                self.handle_noise_handshake(data, from_peer);
                None // Handshake messages are consumed, not passed up
            }
            _ => {
                // Pass through non-fragment, non-handshake packets
                Some((from_peer, data.to_vec()))
            }
        }
    }

    /// Send data to a peer, fragmenting if necessary.
    pub fn send(
        &mut self,
        data: &[u8],
        _to_peer: CanaryPeerID,
    ) -> Vec<Vec<u8>> {
        if data.len() <= BLE_FRAGMENT_SIZE {
            vec![data.to_vec()]
        } else {
            let tid = self.next_transfer_id;
            self.next_transfer_id = self.next_transfer_id.wrapping_add(1);
            PacketBuilder::fragment(tid, data)
        }
    }

    fn handle_fragment(
        &mut self,
        data: &[u8],
        from_peer: CanaryPeerID,
        now_ms: u64,
    ) -> Option<(CanaryPeerID, Vec<u8>)> {
        if data.len() < FRAGMENT_HEADER_SIZE {
            return None;
        }

        let transfer_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let frag_index = u16::from_be_bytes([data[5], data[6]]);
        let total_frags = u16::from_be_bytes([data[7], data[8]]);
        let payload = data[FRAGMENT_HEADER_SIZE..].to_vec();

        // Evict stale assemblies
        self.assemblies.retain(|a| !a.is_stale(now_ms));

        // Cap in-flight assemblies
        if self.assemblies.len() >= MAX_IN_FLIGHT_ASSEMBLIES {
            self.assemblies.remove(0);
        }

        // Find or create assembly
        let assembly = if let Some(a) = self
            .assemblies
            .iter_mut()
            .find(|a| a.transfer_id == transfer_id)
        {
            a
        } else {
            self.assemblies
                .push(FragmentAssembly::new(transfer_id, total_frags, now_ms));
            self.assemblies.last_mut().unwrap()
        };

        if assembly.insert(frag_index, payload) {
            let reassembled = assembly.reassemble()?;
            let tid = transfer_id;
            self.assemblies.retain(|a| a.transfer_id != tid);
            Some((from_peer, reassembled))
        } else {
            None
        }
    }

    fn handle_noise_handshake(&mut self, data: &[u8], from_peer: CanaryPeerID) {
        let session = if let Some((_, s)) = self
            .noise_sessions
            .iter_mut()
            .find(|(p, _)| *p == from_peer)
        {
            s
        } else {
            let s = NoiseSession::new([0u8; 32]); // TODO: use actual local static key
            self.noise_sessions.push((from_peer, s));
            &mut self.noise_sessions.last_mut().unwrap().1
        };

        // Process handshake (response packets would be queued for sending)
        let _ = session.process_handshake(data);
    }

    fn is_duplicate(&self, hash: &[u8; 8], now_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(300_000); // 5 min window
        self.dedup_ring
            .iter()
            .any(|(h, t)| h == hash && *t > cutoff)
    }

    fn record_seen(&mut self, hash: [u8; 8], now_ms: u64) {
        if self.dedup_ring.len() >= self.dedup_capacity {
            self.dedup_ring.remove(0);
        }
        self.dedup_ring.push((hash, now_ms));
    }
}

/// Quick 8-byte hash for deduplication (not cryptographic).
fn quick_hash(data: &[u8]) -> [u8; 8] {
    let mut h = [0u8; 8];
    for (i, b) in data.iter().enumerate() {
        h[i % 8] ^= b;
    }
    h
}
