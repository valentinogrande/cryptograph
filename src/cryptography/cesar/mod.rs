//! # Caesar Cipher Module
//!
//! This module provides an implementation of the classical **Caesar cipher**,
//! one of the simplest and most well-known substitution ciphers.
//!
//! # Overview
//!
//! The Caesar cipher works by shifting each character in the plaintext
//! by a fixed number of positions in the alphabet.
//!
//! ```text
//! E(x) = (x + k) mod n
//! D(x) = (x - k) mod n
//! ```
//!
//! where:
//! - `x` = character index
//! - `k` = shift (key)
//! - `n` = size of the alphabet
//!
//! # Components
//!
//! - [`encrypt`] - Applies a forward shift to produce ciphertext.
//! - [`decrypt`] - Applies the inverse shift to recover plaintext.
//!
//! # Example
//!
//! ```text
//! Plaintext:  HELLO
//! Shift (k):  3
//! Ciphertext: KHOOR
//! ```
//!
//! # ⚠️ Security Warning
//!
//! The Caesar cipher is **not secure** and should never be used in real-world applications.
//!
//! It is vulnerable to:
//!
//! - Brute-force attacks (only `n` possible keys)
//! - Frequency analysis
//!
//! # Use Cases
//!
//! - Learning basic cryptography concepts
//! - Understanding modular arithmetic
//! - Educational demonstrations
//!
//! # Notes
//!
//! - Typically operates on ASCII or alphabetic characters.
//! - Behavior depends on how non-alphabetic characters are handled.
pub mod decrypt;
pub mod encrypt;
