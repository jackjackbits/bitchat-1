//
// CanaryConsentView.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//
// Consent flow adapted from SecuraCV's break-glass consent patterns (Apache-2.0).
//

///
/// # CanaryConsentView
///
/// Stub for the opt-in consent UI that allows users to enable
/// harm-reduction content from canary infrastructure nodes.
///
/// ## Consent Model (from SecuraCV)
/// - Consent is explicit, per-zone, and auditable
/// - Consent can be revoked at any time
/// - Consent has an optional expiry (must be renewed)
/// - All consent changes are recorded in the sealed log
///
/// ## User Flow
/// 1. User discovers canary nodes in their mesh neighborhood
/// 2. User taps a canary node to see its zone and capabilities
/// 3. User toggles "Receive harm-reduction updates" for that zone
/// 4. Consent is stored locally (UserDefaults) and sent to canary via BLE
/// 5. Canary records consent in its sealed log
///

import SwiftUI

struct CanaryConsentView: View {
    let canaryPeer: CanaryPeer
    @State private var isOptedIn: Bool = false
    @State private var showRevokeConfirmation: Bool = false

    var body: some View {
        Form {
            Section(header: Text("Canary Node")) {
                LabeledContent("Name", value: canaryPeer.nickname)
                LabeledContent("Zone", value: "Zone \(canaryPeer.zoneID)")
                LabeledContent("Type", value: canaryPeer.isHarmReductionCapable
                    ? "Harm Reduction Responder"
                    : "Relay Only")
            }

            if canaryPeer.isHarmReductionCapable {
                Section(header: Text("Harm Reduction Opt-In")) {
                    Toggle("Receive updates from Zone \(canaryPeer.zoneID)", isOn: $isOptedIn)
                        .onChange(of: isOptedIn) { _, newValue in
                            if !newValue {
                                showRevokeConfirmation = true
                            } else {
                                CanaryConsentManager.setOptIn(
                                    zoneID: canaryPeer.zoneID,
                                    optedIn: true
                                )
                            }
                        }

                    Text("When enabled, you will see harm-reduction messages from canary nodes in this zone. These include resource availability, safety information, and community alerts.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section(header: Text("Privacy")) {
                    Text("Canary nodes never store your identity or location. All observations use 5-minute time buckets and zone IDs — never precise timestamps or GPS coordinates.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Text("You can revoke consent at any time. Revocation is recorded in the canary's tamper-evident audit log.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Canary Details")
        .onAppear {
            isOptedIn = CanaryConsentManager.isOptedIn(zoneID: canaryPeer.zoneID)
        }
        .alert("Revoke Consent?", isPresented: $showRevokeConfirmation) {
            Button("Revoke", role: .destructive) {
                CanaryConsentManager.setOptIn(
                    zoneID: canaryPeer.zoneID,
                    optedIn: false
                )
                isOptedIn = false
            }
            Button("Cancel", role: .cancel) {
                isOptedIn = true
            }
        } message: {
            Text("You will no longer receive harm-reduction updates from Zone \(canaryPeer.zoneID). This change is recorded in the canary's audit log.")
        }
    }
}
