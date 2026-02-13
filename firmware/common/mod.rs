// firmware/common/mod.rs
//
// Root module for board-agnostic canary firmware.
// Follows SecuraCV's strict layering: common/ never imports boards/ or configs/.
//
// SPDX-License-Identifier: Unlicense AND Apache-2.0

pub mod core;
pub mod hal;
pub mod witness;
pub mod canary;
pub mod gated_response;
pub mod harm_reduction;
pub mod transport;
pub mod chirp;
pub mod health;
