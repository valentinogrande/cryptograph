//! # Math Module
//!
//! This module provides fundamental algorithms from number theory,
//! commonly used in cryptography, modular arithmetic, and algebra.
//!
//! # Overview
//!
//! The module includes implementations for:
//!
//! - **Euclidean Algorithm**: Computes the greatest common divisor (GCD).
//! - **Bézout's Identity**: Finds coefficients that express the GCD as a linear combination.
//! - **Multiplicative Inverse**: Computes modular inverses using the extended Euclidean algorithm.
//!
//! # Use Cases
//!
//! These algorithms are essential in:
//!
//! - Cryptography (RSA, ECC, stream ciphers)
//! - Modular arithmetic systems
//! - Solving Diophantine equations
//! - Number theory applications
//!
//! # Mathematical Background
//!
//! Given integers `a` and `b`, Bézout's identity states:
//!
//! ```text
//! ax + by = gcd(a, b)
//! ```
//!
//! The multiplicative inverse of `a mod m` exists if and only if:
//!
//! ```text
//! gcd(a, m) = 1
//! ```
//!
//! # Modules
//!
//! - [`euclides`] - Implements the Euclidean algorithm for GCD computation.
//! - [`bezout`] - Computes Bézout coefficients using the extended Euclidean algorithm.
//! - [`multiplicative_inverse`] - Calculates modular inverses in ℤₙ.
//!
//! # Notes
//!
//! - All algorithms are deterministic and operate in logarithmic time complexity.
//! - Designed to be efficient and suitable for cryptographic contexts.
pub mod bezout;
pub mod euclides;
pub mod multiplicative_inverse;
