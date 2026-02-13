// firmware/common/witness/mod.rs
//
// Sealed Log & Hash Chain — ported from SecuraCV's storage.rs
//
// Provides tamper-evident append-only logging for canary events.
// Each entry is chained via prev_hash and signed with Ed25519 using
// domain-separated signing (SecuraCV pattern).
//
// Invariants honored:
//   IV  — Local ownership: log stored on-device, never remote-indexed
//   VI  — No retroactive expansion: ruleset_hash binds entries to config
//   VII — Non-queryable: sequential review only, no bulk selectors
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

use super::core::{CanaryEvent, TimeBucket, sign_domain};

// ---------------------------------------------------------------------------
// Sealed Log Entry
// ---------------------------------------------------------------------------

/// A single entry in the tamper-evident sealed log.
/// Mirrors SecuraCV's `SealedLogEntry` with adaptations for bitchat canary events.
#[derive(Clone, Debug)]
pub struct SealedLogEntry {
    /// Sequential index (0-based).
    pub index: u64,
    /// SHA-256 hash of the previous entry (zeros for genesis).
    pub prev_hash: [u8; 32],
    /// Hash of the active ruleset/config at time of sealing.
    pub ruleset_hash: [u8; 32],
    /// Coarse time bucket (never a precise timestamp).
    pub bucket: TimeBucket,
    /// The event payload (serialized CanaryEvent).
    pub event_bytes: Vec<u8>,
    /// SHA-256(domain_prefix || entry_data) — the entry's own hash.
    pub entry_hash: [u8; 32],
    /// Ed25519 signature over domain-separated entry hash.
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Sealed Log Store (trait — implementations provided by HAL backends)
// ---------------------------------------------------------------------------

/// Append-only sealed log store.
/// Follows SecuraCV's `SealedLogStore` trait pattern.
pub trait SealedLogStore {
    type Error;

    /// Append a new entry. Implementations MUST verify chain continuity.
    fn append(&mut self, entry: SealedLogEntry) -> Result<(), Self::Error>;

    /// Read entry by index (sequential access only — Invariant VII).
    fn read(&self, index: u64) -> Result<Option<SealedLogEntry>, Self::Error>;

    /// Total number of sealed entries.
    fn len(&self) -> u64;

    /// Read the most recent entry (for chaining).
    fn latest(&self) -> Result<Option<SealedLogEntry>, Self::Error>;

    /// Verify the full chain from genesis to tip.
    fn verify_chain(&self) -> Result<bool, Self::Error>;
}

// ---------------------------------------------------------------------------
// In-Memory Sealed Log (for testing and constrained devices)
// ---------------------------------------------------------------------------

/// Simple in-memory sealed log — mirrors SecuraCV's `InMemorySealedLogStore`.
pub struct InMemorySealedLog {
    entries: Vec<SealedLogEntry>,
    /// Maximum entries before oldest are evicted (ring buffer on ESP32).
    capacity: usize,
}

impl InMemorySealedLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }
}

impl SealedLogStore for InMemorySealedLog {
    type Error = SealedLogError;

    fn append(&mut self, entry: SealedLogEntry) -> Result<(), Self::Error> {
        // Verify chain continuity
        if let Some(last) = self.entries.last() {
            if entry.prev_hash != last.entry_hash {
                return Err(SealedLogError::ChainBreak {
                    expected: last.entry_hash,
                    got: entry.prev_hash,
                });
            }
            if entry.index != last.index + 1 {
                return Err(SealedLogError::IndexGap);
            }
        } else if entry.index != 0 {
            return Err(SealedLogError::IndexGap);
        }

        // SecuraCV Invariant VI: reject if ruleset_hash changed mid-bucket
        if let Some(last) = self.entries.last() {
            if last.bucket == entry.bucket && last.ruleset_hash != entry.ruleset_hash {
                return Err(SealedLogError::RulesetMismatch);
            }
        }

        // Evict oldest if at capacity (ESP32 RAM constraint)
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }

        self.entries.push(entry);
        Ok(())
    }

    fn read(&self, index: u64) -> Result<Option<SealedLogEntry>, Self::Error> {
        Ok(self.entries.iter().find(|e| e.index == index).cloned())
    }

    fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    fn latest(&self) -> Result<Option<SealedLogEntry>, Self::Error> {
        Ok(self.entries.last().cloned())
    }

    fn verify_chain(&self) -> Result<bool, Self::Error> {
        if self.entries.is_empty() {
            return Ok(true);
        }
        for window in self.entries.windows(2) {
            if window[1].prev_hash != window[0].entry_hash {
                return Ok(false);
            }
        }
        // TODO: verify Ed25519 signatures when crypto backend is wired
        Ok(true)
    }
}

#[derive(Debug)]
pub enum SealedLogError {
    ChainBreak { expected: [u8; 32], got: [u8; 32] },
    IndexGap,
    RulesetMismatch,
    StorageFull,
    IoError,
}

// ---------------------------------------------------------------------------
// Checkpoint (periodic chain summaries for pruning)
// ---------------------------------------------------------------------------

/// Periodic checkpoint for sealed log pruning.
/// Allows constrained devices to discard old entries while maintaining
/// verifiability of the remaining chain.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    /// Index of the last entry covered by this checkpoint.
    pub up_to_index: u64,
    /// Hash of the entry at `up_to_index`.
    pub tip_hash: [u8; 32],
    /// Aggregate signature over all entries in range.
    pub aggregate_signature: [u8; 64],
    /// Bucket at checkpoint creation.
    pub bucket: TimeBucket,
}

// ---------------------------------------------------------------------------
// Chain Builder (helper for creating correctly-chained entries)
// ---------------------------------------------------------------------------

/// Builds sealed log entries with correct chaining.
pub struct ChainBuilder {
    pub next_index: u64,
    pub prev_hash: [u8; 32],
    pub ruleset_hash: [u8; 32],
}

impl ChainBuilder {
    pub fn new(ruleset_hash: [u8; 32]) -> Self {
        Self {
            next_index: 0,
            prev_hash: [0u8; 32],
            ruleset_hash,
        }
    }

    /// Resume from existing chain tip.
    pub fn resume(next_index: u64, prev_hash: [u8; 32], ruleset_hash: [u8; 32]) -> Self {
        Self {
            next_index,
            prev_hash,
            ruleset_hash,
        }
    }

    /// Build a new entry. Caller must provide:
    ///   - `event_bytes`: serialized CanaryEvent
    ///   - `bucket`: coarse time bucket
    ///   - `sign_fn`: closure that signs domain-separated hash
    ///
    /// Returns the entry and advances internal state.
    pub fn build_entry<F>(
        &mut self,
        bucket: TimeBucket,
        event_bytes: Vec<u8>,
        sign_fn: F,
    ) -> SealedLogEntry
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        // Compute entry hash: SHA-256(domain || index || prev_hash || ruleset_hash || event_bytes)
        // Stub: in production, use actual SHA-256
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(sign_domain::SEALED_LOG_ENTRY);
        hash_input.extend_from_slice(&self.next_index.to_be_bytes());
        hash_input.extend_from_slice(&self.prev_hash);
        hash_input.extend_from_slice(&self.ruleset_hash);
        hash_input.extend_from_slice(&event_bytes);

        // Placeholder hash — replace with SHA-256 in production build
        let entry_hash = stub_sha256(&hash_input);

        let signature = sign_fn(&entry_hash);

        let entry = SealedLogEntry {
            index: self.next_index,
            prev_hash: self.prev_hash,
            ruleset_hash: self.ruleset_hash,
            bucket,
            event_bytes,
            entry_hash,
            signature,
        };

        // Advance chain state
        self.prev_hash = entry_hash;
        self.next_index += 1;

        entry
    }
}

/// Stub SHA-256 — returns truncated input hash. Replace with real impl.
fn stub_sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
}
