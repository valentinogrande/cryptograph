//! # Cryptography Module
//!
//! This module provides implementations of classical and stream-based
//! encryption algorithms, primarily for educational and experimental purposes.
//!
//! # Overview
//!
//! The module includes:
//!
//! - **Caesar Cipher**: A simple substitution cipher based on shifting characters.
//! - **Affine Cipher**: A linear transformation cipher over modular arithmetic.
//! - **Stream Ciphers**: Bitwise encryption using keystreams and XOR operations.
//!
//! # Use Cases
//!
//! These algorithms are useful for:
//!
//! - Learning cryptographic fundamentals
//! - Understanding modular arithmetic in practice
//! - Prototyping encryption schemes
//! - Educational demonstrations
//!
//! # ⚠️ Security Warning
//!
//! Most algorithms in this module (e.g., Caesar, Affine) are **not secure**
//! for real-world use. They are easily breakable with modern techniques.
//!
//! Stream ciphers included here may also lack proper cryptographic guarantees
//! unless explicitly designed and audited.
//!
//! 👉 For production use, prefer well-established libraries such as RustCrypto.
//!
//! # Mathematical Background
//!
//! - **Caesar Cipher**:
//!
//! ```text
//! E(x) = (x + k) mod n
//! ```
//!
//! - **Affine Cipher**:
//!
//! ```text
//! E(x) = (a·x + b) mod n
//! ```
//!
//! where `gcd(a, n) = 1` for invertibility.
//!
//! - **Stream Cipher**:
//!
//! ```text
//! C = P ⊕ K
//! ```
//!
//! where:
//! - `P` = plaintext
//! - `K` = keystream
//! - `⊕` = XOR
//!
//! # Modules
//!
//! - [`cesar`] - Caesar cipher implementation.
//! - [`affine`] - Affine cipher using modular arithmetic.
//! - [`streams_ciphers`] - Bitwise stream cipher utilities.
//!
//! # Notes
//!
//! - Emphasis is placed on clarity and understanding over performance.
//! - Some implementations may operate at the bit level (`bool`) for learning purposes.
pub mod affine;
pub mod cesar;
pub mod des;
pub mod streams_ciphers;
