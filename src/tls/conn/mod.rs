//! Connection state machines over the sans-I/O [`ConnectionCore`].

mod client;
mod common;

#[allow(unused_imports)]
pub use client::{ClientConfig, ClientConnection};
