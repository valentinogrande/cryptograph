//! Cryptoanalysis utilities.
//!
//! This module contains tools and algorithms used for
//! cryptanalytic attacks against classical pseudorandom
//! generators and stream ciphers.
//!
//! Currently implemented:
//! - `reverse_lfsr`: Recover the initial state of an LFSR
//!   from observed output bits.
pub mod reverse_lfsr;
