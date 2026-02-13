// firmware/boards/esp32/mod.rs
//
// ESP32 board-specific pin maps and peripheral configuration.
//
// Follows SecuraCV's strict layering rule:
//   boards/ contains ONLY pin maps and peripheral initialization.
//   boards/ never imports common/ or configs/ directly.
//   All composition happens in projects/.
//
// Supported boards:
//   - ESP32-S3 (BLE 5.0, camera, PSRAM)
//   - ESP32-C3 (BLE 5.0, RISC-V, low-power)
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// ESP32-S3 Pin Map (e.g., Seeed XIAO ESP32S3 Sense)
// ---------------------------------------------------------------------------

pub mod esp32s3 {
    /// GPIO pins for the ESP32-S3 canary board.
    pub struct PinMap {
        /// Status LED (RGB or single-color).
        pub led_pin: u8,
        /// I2C SDA for environmental sensors.
        pub i2c_sda: u8,
        /// I2C SCL for environmental sensors.
        pub i2c_scl: u8,
        /// SD card chip select (for sealed log persistence).
        pub sd_cs: u8,
        /// SD card SPI clock.
        pub sd_sck: u8,
        /// SD card SPI MOSI.
        pub sd_mosi: u8,
        /// SD card SPI MISO.
        pub sd_miso: u8,
        /// Camera data pins (S3 only).
        pub cam_d0: u8,
        pub cam_d1: u8,
        pub cam_d2: u8,
        pub cam_d3: u8,
        pub cam_d4: u8,
        pub cam_d5: u8,
        pub cam_d6: u8,
        pub cam_d7: u8,
        pub cam_xclk: u8,
        pub cam_pclk: u8,
        pub cam_vsync: u8,
        pub cam_href: u8,
        pub cam_sda: u8,
        pub cam_scl: u8,
    }

    /// Default pin map for XIAO ESP32S3 Sense.
    pub fn xiao_s3_sense() -> PinMap {
        PinMap {
            led_pin: 21,
            i2c_sda: 5,
            i2c_scl: 6,
            sd_cs: 21,
            sd_sck: 7,
            sd_mosi: 9,
            sd_miso: 8,
            cam_d0: 15,
            cam_d1: 17,
            cam_d2: 18,
            cam_d3: 16,
            cam_d4: 14,
            cam_d5: 12,
            cam_d6: 11,
            cam_d7: 48,
            cam_xclk: 10,
            cam_pclk: 13,
            cam_vsync: 38,
            cam_href: 47,
            cam_sda: 40,
            cam_scl: 39,
        }
    }
}

// ---------------------------------------------------------------------------
// ESP32-C3 Pin Map
// ---------------------------------------------------------------------------

pub mod esp32c3 {
    /// GPIO pins for the ESP32-C3 canary board (minimal, BLE-only).
    pub struct PinMap {
        /// Status LED.
        pub led_pin: u8,
        /// I2C SDA for environmental sensors.
        pub i2c_sda: u8,
        /// I2C SCL for environmental sensors.
        pub i2c_scl: u8,
        /// UART TX (for debug/console).
        pub uart_tx: u8,
        /// UART RX (for debug/console).
        pub uart_rx: u8,
    }

    /// Default pin map for generic ESP32-C3 board.
    pub fn default_c3() -> PinMap {
        PinMap {
            led_pin: 8,
            i2c_sda: 4,
            i2c_scl: 5,
            uart_tx: 21,
            uart_rx: 20,
        }
    }
}
