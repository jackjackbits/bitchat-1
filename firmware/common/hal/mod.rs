// firmware/common/hal/mod.rs
//
// Hardware Abstraction Layer stubs for ESP32 canary devices.
//
// Follows SecuraCV's strict firmware layering:
//   common/ never imports boards/ or configs/
//   Board-specific pin maps live in boards/esp32/
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// GPIO abstraction
// ---------------------------------------------------------------------------

/// Pin mode for GPIO configuration.
#[derive(Clone, Copy, Debug)]
pub enum PinMode {
    Input,
    Output,
    InputPullUp,
    InputPullDown,
    Analog,
}

/// Abstract GPIO pin — board crate supplies concrete pin numbers.
pub trait GpioPin {
    fn pin_number(&self) -> u8;
    fn set_mode(&mut self, mode: PinMode);
    fn read_digital(&self) -> bool;
    fn write_digital(&mut self, high: bool);
    fn read_analog(&self) -> u16;
}

// ---------------------------------------------------------------------------
// BLE Radio abstraction
// ---------------------------------------------------------------------------

/// BLE advertising data matching bitchat's service UUID.
pub const BITCHAT_SERVICE_UUID: [u8; 16] = [
    0xF4, 0x7B, 0x5E, 0x2D, 0x4A, 0x9E, 0x4C, 0x5A,
    0x9B, 0x3F, 0x8E, 0x1D, 0x2C, 0x3A, 0x4B, 0x5C,
];

pub const BITCHAT_CHARACTERISTIC_UUID: [u8; 16] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x4A, 0x5B,
    0x8C, 0x9D, 0x0E, 0x1F, 0x2A, 0x3B, 0x4C, 0x5D,
];

/// BLE radio abstraction. ESP32 BLE driver implements this.
pub trait BleRadio {
    type Error;

    /// Start advertising as a bitchat peripheral (dual-role like BLEService).
    fn start_advertising(&mut self, local_name: &[u8]) -> Result<(), Self::Error>;

    /// Stop advertising.
    fn stop_advertising(&mut self) -> Result<(), Self::Error>;

    /// Start scanning for bitchat service UUID.
    fn start_scan(&mut self) -> Result<(), Self::Error>;

    /// Stop scanning.
    fn stop_scan(&mut self) -> Result<(), Self::Error>;

    /// Write data to a connected peer's characteristic.
    fn write_to_peer(&mut self, peer: &[u8; 8], data: &[u8]) -> Result<(), Self::Error>;

    /// Read incoming notification data (non-blocking).
    fn poll_notification(&mut self) -> Option<(/* peer */ [u8; 8], /* data */ Vec<u8>)>;

    /// Get RSSI for a connected peer.
    fn peer_rssi(&self, peer: &[u8; 8]) -> Option<i8>;

    /// Number of currently connected peers.
    fn connected_peer_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Non-Volatile Storage abstraction
// ---------------------------------------------------------------------------

/// NVS abstraction for sealed log persistence and consent records.
pub trait NonVolatileStorage {
    type Error;

    fn read(&self, namespace: &str, key: &str, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn write(&mut self, namespace: &str, key: &str, data: &[u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, namespace: &str, key: &str) -> Result<(), Self::Error>;
    fn erase_namespace(&mut self, namespace: &str) -> Result<(), Self::Error>;
}

// ---------------------------------------------------------------------------
// Cryptographic RNG
// ---------------------------------------------------------------------------

/// Hardware RNG abstraction (ESP32 has a true RNG peripheral).
pub trait CryptoRng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
    fn random_u32(&mut self) -> u32;
}

// ---------------------------------------------------------------------------
// Timer / Clock
// ---------------------------------------------------------------------------

/// Monotonic clock for duty cycling and timeouts.
pub trait MonotonicClock {
    /// Milliseconds since boot.
    fn millis(&self) -> u64;
}

/// Wall clock (epoch seconds) — only for TimeBucket computation.
/// Precision is intentionally coarse (SecuraCV Invariant III).
pub trait WallClock {
    fn epoch_secs(&self) -> u64;
}

// ---------------------------------------------------------------------------
// LED indicator
// ---------------------------------------------------------------------------

/// Status LED for canary node operational state.
pub trait StatusLed {
    fn set_color(&mut self, r: u8, g: u8, b: u8);
    fn blink(&mut self, on_ms: u32, off_ms: u32, count: u8);
    fn off(&mut self);
}

// ---------------------------------------------------------------------------
// Sensor abstraction (for environmental harm-reduction alerts)
// ---------------------------------------------------------------------------

/// Environmental sensor reading.
#[derive(Clone, Debug)]
pub struct SensorReading {
    pub metric: super::super::common::core::EnvironmentalMetric,
    pub value_centi: i32, // value * 100 for fixed-point
}

/// Generic sensor interface.
pub trait EnvironmentalSensor {
    type Error;
    fn read_all(&mut self) -> Result<Vec<SensorReading>, Self::Error>;
}

// Re-export for convenience within firmware crate.
// NOTE: In actual ESP32 build, these would be implemented by esp-idf-hal.
