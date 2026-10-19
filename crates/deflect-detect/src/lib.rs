//! Traffic-rate monitoring and attack triggering for deflect-rs.
//!
//! [`SlidingWindow`] is an exact integer rate counter; [`Trigger`] layers dual
//! watermarks over packet and byte windows to produce a stable [`Phase`] with
//! hysteresis, the signal that gates whether mitigation stages are engaged.
#![forbid(unsafe_code)]

mod trigger;
mod window;

pub use trigger::{Phase, Trigger, Watermarks};
pub use window::SlidingWindow;
