//! # Affine Cipher Module
//!
//! This module provides an implementation of the **Affine cipher**,
//! a classical substitution cipher based on modular arithmetic.
//!
//! # Overview
//!
//! The Affine cipher transforms each character using a linear function:
//!
//! ```text
//! E(x) = (a·x + b) mod n
//! D(x) = a⁻¹ · (x - b) mod n
//! ```
//!
//! where:
//! - `x` = character index
//! - `a`, `b` = keys
//! - `n` = alphabet size
//! - `a⁻¹` = modular multiplicative inverse of `a mod n`
//!
//! # Requirements
//!
//! - `gcd(a, n) = 1`
//!
//! This condition ensures that `a` has a modular inverse, which is
//! required for decryption.
//!
//! # Components
//!
//! - [`encrypt`] - Applies the affine transformation to produce ciphertext.
//! - [`decrypt`] - Uses the modular inverse to recover plaintext.
//!
//! # Mathematical Background
//!
//! The decryption step relies on computing the multiplicative inverse:
//!
//! ```text
//! a · a⁻¹ ≡ 1 (mod n)
//! ```
//!
//! This is typically computed using the **Extended Euclidean Algorithm**,
//! which may be implemented in [`crate::math::multiplicative_inverse`].
//!
//! # Example
//!
//! ```text
//! Alphabet size (n): 26
//! a = 5, b = 8
//!
//! Plaintext:  HELLO
//! Ciphertext: RCLLA
//! ```
//!
//! # ⚠️ Security Warning
//!
//! The Affine cipher is **not secure** and should not be used in production.
//!
//! It is vulnerable to:
//!
//! - Frequency analysis
//! - Known-plaintext attacks
//!
//! # Use Cases
//!
//! - Learning modular arithmetic in cryptography
//! - Understanding linear transformations over finite sets
//! - Educational purposes
//!
//! # Notes
//!
//! - Works over finite alphabets (commonly size 26).
//! - Behavior depends on how characters are mapped to numeric values.

pub mod decrypt;
pub mod encrypt;
