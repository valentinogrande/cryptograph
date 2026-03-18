//! # Stream Cipher Module
//!
//! This module provides a basic implementation of stream cipher components,
//! including encryption, decryption, and keystream generation.
//!
//! # Overview
//!
//! A stream cipher encrypts data by combining the plaintext with a keystream,
//! typically using the XOR operation.
//!
//! ```text
//! C = P ⊕ K
//! P = C ⊕ K
//! ```
//!
//! where:
//! - `P` = plaintext
//! - `C` = ciphertext
//! - `K` = keystream
//! - `⊕` = bitwise XOR
//!
//! # Components
//!
//! - [`encrypt`] - Applies XOR between plaintext and keystream to produce ciphertext.
//! - [`decrypt`] - Recovers plaintext using the same keystream (XOR is symmetric).
//! - [`generete_seed`] - Generates the initial seed used to derive the keystream.
//!
//! # Properties
//!
//! - Encryption and decryption are **identical operations** (XOR symmetry).
//! - Security depends entirely on the **quality of the keystream**.
//!
//! # ⚠️ Security Warning
//!
//! This implementation is intended for **educational purposes only**.
//!
//! A secure stream cipher must ensure:
//!
//! - Cryptographically secure keystream generation (CSPRNG)
//! - No keystream reuse (never reuse the same seed/key)
//! - Resistance to statistical and known-plaintext attacks
//!
//! This module does **not guarantee** those properties.
//!
//! # Notes
//!
//! - May operate at the bit level (`bool`) for clarity.
//! - Real-world implementations typically operate on bytes (`u8`) for performance.
//!
//! # See Also
//!
//! - [`crate::math`] for number theory utilities used in key generation.
pub mod decrypt;
pub mod encrypt;
pub mod generete_seed;
