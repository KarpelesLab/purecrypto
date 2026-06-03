//! LMS / HSS stateful hash-based signatures (RFC 8554, NIST SP 800-208).
//!
//! **Stateful:** the private key advances a one-time-key index on every
//! signature and must be re-persisted after each sign; reuse of an index is
//! catastrophic.
//!
//! Placeholder module — the implementation lands in a follow-up commit.
