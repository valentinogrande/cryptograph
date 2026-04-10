//! Data Encryption Standard (DES)
//!
//! A pure Rust implementation of the DES block cipher.
//!
//! # Overview
//!
//! This module implements the full DES encryption pipeline:
//!
//! - Initial permutation
//! - Key schedule (PC-1, shifts, PC-2)
//! - 16 Feistel rounds
//! - Expansion permutation (E-box)
//! - Substitution (S-box)
//! - Round function (F)
//!
//! # Module Structure
//!
//! - `encrypt` — DES encryption implementation
//! - `f` — Feistel round function
//! - `key` — Key schedule (PC-1, PC-2, shifts)
//! - `permutation` — Initial and final permutations
//! - `e_box` — Expansion permutation (32 → 48 bits)
//! - `s_box` — Substitution boxes
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::des::encrypt::Des;
//!
//! let plaintext = 0x0123456789ABCDEF;
//! let key = 0x133457799BBCDFF1;
//!
//! let des = Des::new(plaintext);
//! let encrypted = des.encrypt(key);
//!
//! println!("{:016X}", encrypted);
//! ```
//!
//! # Notes
//!
//! - Operates on 64-bit blocks
//! - Uses 56-bit keys (64-bit with parity bits)
//! - Educational implementation
//!
//! # References
//!
//! - FIPS 46-3 DES Standard

pub mod e_box;
pub mod encrypt;
pub mod f;
pub mod key;
pub mod permutation;
pub mod s_box;
