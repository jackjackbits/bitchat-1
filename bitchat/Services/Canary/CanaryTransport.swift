//
// CanaryTransport.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//
// Canary node integration adapted from SecuraCV (Apache-2.0):
//   - Privacy-witness kernel patterns
//   - Gated response engine
//   - Break-glass quorum authorization
//   - Sealed log hash chains
//

///
/// # CanaryTransport
///
/// Bridges ESP32 canary infrastructure nodes into the bitchat mesh.
///
/// Canary nodes are stationary BLE devices that:
///   1. Relay mesh traffic (extend bitchat range)
///   2. Emit gated harm-reduction tweets (opt-in, policy-checked)
///   3. Provide privacy-preserving environmental awareness
///   4. Maintain tamper-evident audit logs (SecuraCV sealed log pattern)
///
/// ## Integration with bitchat
/// Canary nodes appear as regular bitchat peers with a special `isCanary` flag.
/// Their announce packets carry a canary marker (0x01 flag byte) so that
/// bitchat clients can distinguish infrastructure nodes from human users.
///
/// Gated tweets appear as standard public messages (MessageType.message = 0x02)
/// with a `[canary:zN]` prefix that canary-aware clients can parse for
/// structured data while remaining human-readable for standard clients.
///
/// ## SecuraCV Invariants Honored
/// - I:   No raw sensor data ever leaves the canary node
/// - II:  No identity substrate (no face/plate detection, only coarse object classes)
/// - III: Metadata minimization (5-minute time buckets, zone IDs not GPS)
/// - IV:  Local ownership (sealed log on-device)
/// - V:   Break-glass by quorum for sensitive content tiers
/// - VI:  No retroactive expansion (ruleset hash binds sealed log entries)
/// - VII: Non-queryable (sequential review only)
///

import Foundation
import Combine

// MARK: - Canary Peer Identity

/// Represents a canary infrastructure node discovered via BLE.
struct CanaryPeer: Equatable, Hashable {
    /// Standard bitchat peer ID (8-byte truncated Noise pubkey).
    let peerID: PeerID
    /// Canary-specific nickname (e.g., "canary", "relay", "hrnode").
    let nickname: String
    /// Whether this node supports harm-reduction responses.
    let isHarmReductionCapable: Bool
    /// Zone ID the canary is assigned to.
    let zoneID: UInt8
    /// Last time we heard from this canary.
    var lastSeen: Date
    /// BLE RSSI at last contact.
    var lastRSSI: Int?
}

// MARK: - Canary Message Types

/// Extended message classification for canary-originated content.
/// These ride inside standard bitchat public messages (0x02) with a prefix.
enum CanaryMessageType {
    /// A gated harm-reduction tweet.
    case gatedTweet(zone: UInt8, content: String)
    /// A chirp community alert.
    case chirpAlert(zone: UInt8, alertType: ChirpAlertType, summary: String)
    /// Canary heartbeat (liveness).
    case heartbeat(zone: UInt8)
    /// Regular bitchat message relayed through canary (pass-through).
    case relayedMessage
}

/// Chirp alert types (mirrors firmware/common/chirp/mod.rs).
enum ChirpAlertType: UInt8 {
    case environmental = 0x01
    case resourceUpdate = 0x02
    case harmReductionStatus = 0x03
    case safetyAlert = 0x04
    case nodeStatus = 0x05

    var displayName: String {
        switch self {
        case .environmental: return "Environmental"
        case .resourceUpdate: return "Resource"
        case .harmReductionStatus: return "Harm Reduction"
        case .safetyAlert: return "Safety"
        case .nodeStatus: return "Node Status"
        }
    }
}

// MARK: - Canary Message Parser

/// Parses canary-specific content from standard bitchat public messages.
struct CanaryMessageParser {

    /// Canary message prefix pattern: [canary:zN]
    private static let prefixPattern = "\\[canary:z(\\d+)\\]\\s*(.*)"

    /// Try to parse a canary message from a public bitchat message.
    /// Returns nil if the message is not from a canary node.
    static func parse(content: String) -> CanaryMessageType? {
        guard content.hasPrefix("[canary:") else { return nil }

        guard let regex = try? NSRegularExpression(pattern: prefixPattern),
              let match = regex.firstMatch(
                  in: content,
                  range: NSRange(content.startIndex..., in: content)
              ),
              let zoneRange = Range(match.range(at: 1), in: content),
              let bodyRange = Range(match.range(at: 2), in: content),
              let zone = UInt8(content[zoneRange]) else {
            return nil
        }

        let body = String(content[bodyRange])

        // Classify by body content
        if body.hasPrefix("ALERT:") {
            return .chirpAlert(zone: zone, alertType: .safetyAlert, summary: body)
        } else if body.hasPrefix("Environmental:") {
            return .chirpAlert(zone: zone, alertType: .environmental, summary: body)
        } else if body.hasPrefix("Harm reduction:") || body.hasPrefix("Resource available:") {
            return .gatedTweet(zone: zone, content: body)
        } else if body == "Node heartbeat" {
            return .heartbeat(zone: zone)
        } else {
            return .gatedTweet(zone: zone, content: body)
        }
    }
}

// MARK: - Consent State (client-side)

/// Tracks whether the local user has opted into receiving harm-reduction
/// content from canary nodes in specific zones.
class CanaryConsentManager {

    /// Key prefix for UserDefaults.
    private static let consentKeyPrefix = "canary.consent.zone."

    /// Check if the user has opted in to canary content for a zone.
    static func isOptedIn(zoneID: UInt8) -> Bool {
        UserDefaults.standard.bool(forKey: "\(consentKeyPrefix)\(zoneID)")
    }

    /// Set opt-in status for a zone.
    static func setOptIn(zoneID: UInt8, optedIn: Bool) {
        UserDefaults.standard.set(optedIn, forKey: "\(consentKeyPrefix)\(zoneID)")
    }

    /// Get all zones the user has opted into.
    static func allOptedInZones() -> [UInt8] {
        // Scan zones 0-255
        (0...UInt8.max).filter { isOptedIn(zoneID: $0) }
    }
}

// MARK: - Canary Transport Service

/// Manages the client-side integration of canary nodes into the bitchat mesh.
///
/// This service:
///   1. Tracks discovered canary peers separately from human peers
///   2. Parses canary-specific messages from the public timeline
///   3. Manages opt-in consent for harm-reduction content display
///   4. Provides filtered feeds of canary content by zone/type
///
/// It works alongside the existing BLEService (Transport protocol),
/// not as a replacement — canary nodes are regular BLE peers that happen
/// to emit structured content.
class CanaryTransportService {

    // MARK: - Properties

    /// Discovered canary peers.
    private(set) var canaryPeers: [PeerID: CanaryPeer] = [:]

    /// Received gated tweets (newest first).
    private(set) var gatedTweets: [GatedTweet] = []

    /// Maximum gated tweets to retain.
    private let maxTweets: Int = 100

    /// Publisher for canary peer updates.
    let canaryPeersPublisher = PassthroughSubject<[CanaryPeer], Never>()

    /// Publisher for new gated tweets.
    let gatedTweetPublisher = PassthroughSubject<GatedTweet, Never>()

    /// Chirp subscription filter.
    var chirpSubscription: ChirpSubscription = .all

    // MARK: - Initialization

    init() {}

    // MARK: - Peer Management

    /// Process a bitchat announce packet to detect canary nodes.
    /// Called by the main Transport/BLEService when an announce is received.
    func processAnnounce(peerID: PeerID, nickname: String, rawPayload: Data) {
        // Check for canary flag byte at end of announce payload
        guard rawPayload.count > 0,
              rawPayload.last == 0x01 else {
            // Not a canary node — remove from tracking if previously seen
            canaryPeers.removeValue(forKey: peerID)
            return
        }

        let peer = CanaryPeer(
            peerID: peerID,
            nickname: nickname,
            isHarmReductionCapable: nickname.hasPrefix("hr") || nickname == "canary",
            zoneID: extractZoneFromNickname(nickname),
            lastSeen: Date(),
            lastRSSI: nil
        )

        canaryPeers[peerID] = peer
        canaryPeersPublisher.send(Array(canaryPeers.values))
    }

    /// Process a bitchat leave packet.
    func processLeave(peerID: PeerID) {
        canaryPeers.removeValue(forKey: peerID)
        canaryPeersPublisher.send(Array(canaryPeers.values))
    }

    // MARK: - Message Processing

    /// Process a public bitchat message to extract canary content.
    /// Called by the main ChatViewModel when a public message arrives.
    func processPublicMessage(
        from peerID: PeerID,
        nickname: String,
        content: String,
        timestamp: Date
    ) {
        // Only process messages from known canary peers
        guard canaryPeers[peerID] != nil else { return }

        guard let canaryMsg = CanaryMessageParser.parse(content: content) else { return }

        switch canaryMsg {
        case .gatedTweet(let zone, let tweetContent):
            handleGatedTweet(
                from: peerID,
                zone: zone,
                content: tweetContent,
                timestamp: timestamp
            )

        case .chirpAlert(let zone, let alertType, let summary):
            handleChirpAlert(
                from: peerID,
                zone: zone,
                alertType: alertType,
                summary: summary,
                timestamp: timestamp
            )

        case .heartbeat(let zone):
            // Update peer's lastSeen and zone
            if var peer = canaryPeers[peerID] {
                peer.lastSeen = timestamp
                canaryPeers[peerID] = peer
            }

        case .relayedMessage:
            break // Pass-through, nothing to do
        }
    }

    /// Handle a gated harm-reduction tweet.
    private func handleGatedTweet(
        from peerID: PeerID,
        zone: UInt8,
        content: String,
        timestamp: Date
    ) {
        // Consent check: only store/display if user opted in for this zone
        guard CanaryConsentManager.isOptedIn(zoneID: zone) else { return }

        let tweet = GatedTweet(
            id: UUID().uuidString,
            sourcePeerID: peerID,
            zoneID: zone,
            content: content,
            timestamp: timestamp
        )

        gatedTweets.insert(tweet, at: 0)
        if gatedTweets.count > maxTweets {
            gatedTweets.removeLast()
        }

        gatedTweetPublisher.send(tweet)
    }

    /// Handle a chirp community alert.
    private func handleChirpAlert(
        from peerID: PeerID,
        zone: UInt8,
        alertType: ChirpAlertType,
        summary: String,
        timestamp: Date
    ) {
        // Apply subscription filter
        let chirp = ChirpAlert(zone: zone, alertType: alertType, summary: summary)
        guard chirpSubscription.matches(chirp) else { return }

        // Treat chirp alerts as gated tweets for the display pipeline
        handleGatedTweet(from: peerID, zone: zone, content: summary, timestamp: timestamp)
    }

    // MARK: - Helpers

    private func extractZoneFromNickname(_ nickname: String) -> UInt8 {
        // Convention: canary nicknames may end with zone number (e.g., "canary3")
        let digits = nickname.reversed().prefix(while: { $0.isNumber })
        if let zone = UInt8(String(digits.reversed())) {
            return zone
        }
        return 0 // Default zone
    }
}

// MARK: - Data Models

/// A harm-reduction tweet that passed the gating pipeline on the canary node.
struct GatedTweet: Identifiable {
    let id: String
    let sourcePeerID: PeerID
    let zoneID: UInt8
    let content: String
    let timestamp: Date
}

/// A chirp community alert.
struct ChirpAlert {
    let zone: UInt8
    let alertType: ChirpAlertType
    let summary: String
}

/// Subscription filter for chirp alerts (client-side, mirrors firmware).
struct ChirpSubscription {
    let zoneIDs: [UInt8]  // Empty = all zones
    let alertTypes: [ChirpAlertType]  // Empty = all types

    static var all: ChirpSubscription {
        ChirpSubscription(zoneIDs: [], alertTypes: [])
    }

    func matches(_ alert: ChirpAlert) -> Bool {
        let zoneOK = zoneIDs.isEmpty || zoneIDs.contains(alert.zone)
        let typeOK = alertTypes.isEmpty || alertTypes.contains(alert.alertType)
        return zoneOK && typeOK
    }
}
