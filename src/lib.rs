//! Shared library for the `on-device` agent.
//!
//! Exposes [`integrity`] so both the agent and the offline `sign` helper use the
//! same self-signature verification logic.

pub mod integrity;
