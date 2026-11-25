//! SLH-DSA (FIPS 205) at security category 1 with SHA-256 as the underlying
//! signature of the blind signature, in the parameter set SLH-DSA-SHA2-128-24
//! of the draft SP 800-230. `native` signs and verifies,
//! `gadget` verifies in the circuit, `commit` is the Halevi–Micali commitment
//! on SHA-256, and `protocol` wires them into the blind-signature flow of
//! `crate::protocol`, so the whole scheme uses SHA-256 alone.

pub mod commit;
pub mod gadget;
pub mod native;
pub mod params;
pub mod protocol;
pub mod serialize;

pub use params::{SLH_DSA_SHA2_128_24, SlhParams};
