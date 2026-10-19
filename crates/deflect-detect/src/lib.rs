//! Traffic-rate monitoring and attack triggering for deflect-rs.
//!
//! [`SlidingWindow`] is an exact integer rate counter; [`Trigger`] layers dual
//! watermarks over packet and byte windows to produce a stable [`Phase`] with
//! hysteresis, the signal that gates whether mitigation stages are engaged.
//!
//! ```
//! use deflect_detect::{Phase, Trigger, Watermarks};
//!
//! // Engage at 1000 pps; stay engaged until the rate falls below 400 pps.
//! let marks = Watermarks { pps_high: 1000, pps_low: 400, bps_high: u64::MAX, bps_low: u64::MAX };
//! let mut trigger = Trigger::new(1_000_000_000, 10, marks);
//!
//! // Drive ~2000 pps across a full window: the high watermark engages mitigation.
//! let mut now = 0u64;
//! for _ in 0..2000 {
//!     trigger.observe(64, now);
//!     now += 500_000;
//! }
//! assert_eq!(trigger.phase(), Phase::Mitigating);
//!
//! // Idle past the window so the rate decays below the low watermark: back to calm.
//! now += 2_000_000_000;
//! assert_eq!(trigger.reassess(now), Phase::Calm);
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod trigger;
mod window;

pub use trigger::{Phase, Trigger, Watermarks};
pub use window::SlidingWindow;
