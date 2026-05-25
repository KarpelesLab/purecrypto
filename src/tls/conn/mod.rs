//! Connection state machines over the sans-I/O [`ConnectionCore`].

mod client;
mod common;
mod server;

#[allow(unused_imports)]
pub use client::{ClientConfig, ClientConnection};
#[allow(unused_imports)]
pub use server::{ServerConfig, ServerConnection};
