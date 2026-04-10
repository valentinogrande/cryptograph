//! # Cryptography Module
//!
//! A collection of classical and educational cryptographic algorithms
//! implemented in pure Rust.
//!
//! # Overview
//!
//! This module includes:
//!
//! - **Caesar Cipher** — Simple shift-based substitution cipher
//! - **Affine Cipher** — Linear transformation using modular arithmetic
//! - **DES** — Block cipher based on the Feistel network
//! - **Stream Ciphers** — Bitwise XOR-based encryption utilities
//!
//! # Use Cases
//!
//! These algorithms are useful for:
//!
//! - Learning cryptographic fundamentals
//! - Understanding modular arithmetic
//! - Exploring block vs stream cipher design
//! - Educational demonstrations
//!
//! # ⚠️ Security Warning
//!
//! Most algorithms in this module are **not secure for production use**.
//!
//! - Caesar and Affine ciphers are easily breakable
//! - DES is considered cryptographically obsolete
//! - Stream ciphers here may lack cryptographic guarantees
//!
//! For production environments, use audited libraries such as:
//!
//! - RustCrypto
//! - ring
//! - libsodium
//!
//! # Mathematical Background
//!
//! ## Caesar Cipher
//!
//! ```text
//! E(x) = (x + k) mod n
//! ```
//!
//! ## Affine Cipher
//!
//! ```text
//! E(x) = (a·x + b) mod n
//! ```
//!
//! where:
//!
//! ```text
//! gcd(a, n) = 1
//! ```
//!
//! ## Stream Cipher
//!
//! ```text
//! C = P ⊕ K
//! ```
//!
//! where:
//!
//! - `P` = plaintext
//! - `K` = keystream
//! - `⊕` = XOR
//!
//! # Modules
//!
//! - [`cesar`] — Caesar cipher implementation
//! - [`affine`] — Affine cipher
//! - [`des`] — Data Encryption Standard implementation
//! - [`streams_ciphers`] — Stream cipher utilities
//!
//! # Design Goals
//!
//! - Educational clarity
//! - Minimal dependencies
//! - Bit-level implementations
//! - Pure Rust
//!
//! # Notes
//!
//! These implementations prioritize understanding over performance
//! and security.
pub mod affine;
pub mod cesar;
pub mod des;
pub mod streams_ciphers;
