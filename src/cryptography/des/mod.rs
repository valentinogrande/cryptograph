//! Data Encryption Standard (DES)
//!
//! A pure Rust implementation of the DES block cipher.
//!
//! # Overview
//!
//! DES is a symmetric-key block cipher that operates on 64-bit blocks using a 56-bit key
//! (stored as 64 bits with 8 parity bits). It applies 16 rounds of a Feistel network,
//! combining expansion, substitution, and permutation to achieve confusion and diffusion.
//!
//! # Algorithm Summary
//!
//! ```text
//! Plaintext (64-bit)
//!     ↓
//! Initial Permutation (IP)
//!     ↓
//! ┌─────────────────────┐
//! │  16 Feistel Rounds  │  ← subkeys K1..K16 derived from PC-1 + shifts + PC-2
//! └─────────────────────┘
//!     ↓
//! Swap (L16, R16)
//!     ↓
//! Final Permutation (IP⁻¹)
//!     ↓
//! Ciphertext (64-bit)
//! ```
//!
//! Decryption follows the same structure with subkeys applied in reverse order (K16..K1).
//!
//! # Module Structure
//!
//! - `decrypt`    — DES decryption (16 rounds, inverse key schedule)
//! - `encrypt`    — DES encryption (16 rounds, forward key schedule)
//! - `f`          — Feistel round function
//! - `key`        — Key schedule (PC-1, PC-2, shifts, inverse shifts)
//! - `permutation`— Initial and final permutations (IP, IP⁻¹)
//! - `e_box`      — Expansion permutation (32 → 48 bits)
//! - `s_box`      — Eight 6-to-4 bit substitution boxes
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::des::encrypt::Des;
//!
//! let plaintext = 0x0123456789ABCDEF;
//! let key       = 0x133457799BBCDFF1;
//!
//! let des = Des::new(plaintext);
//! let ciphertext = des.encrypt(key);
//! let recovered  = Des::decrypt(ciphertext, key);
//!
//! assert_eq!(plaintext, recovered);
//! ```
//!
//! # Security Warning
//!
//! DES is cryptographically broken. Its 56-bit key space is exhaustible by brute force
//! and it is vulnerable to differential and linear cryptanalysis. Do not use in production.
//!
//! Recommended alternatives: AES-128, AES-256, ChaCha20.
//!
//! # References
//!
//! - FIPS 46-3 DES Standard
//! - Feistel, H. (1973). *Cryptography and Computer Privacy*
//! - Stinson, D. *Cryptography: Theory and Practice*
pub mod decrypt;
pub mod e_box;
pub mod encrypt;
pub mod f;
pub mod key;
pub mod permutation;
pub mod s_box;

#[cfg(test)]
mod tests {
    use super::encrypt::Des;

    #[test]
    fn test_des_roundtrip() {
        let cases = [
            (0x0123_4567_89AB_CDEF, 0x1334_5779_9BBC_DFF1),
            (0xFEDC_BA98_7654_3210, 0x0E32_9232_EA6D_0D73),
            (0x0000_0000_0000_0000, 0x0000_0000_0000_0000),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0x1111_1111_1111_1111, 0x2222_2222_2222_2222),
        ];

        for (plaintext, key) in cases {
            let ciphertext = Des::new(plaintext).encrypt(key);
            let recovered = Des::decrypt(ciphertext, key);

            assert_eq!(plaintext, recovered);
        }
    }

    #[test]
    fn test_des_known_answer_vector() {
        let plaintext = 0x0123_4567_89AB_CDEF;
        let key = 0x1334_5779_9BBC_DFF1;
        let expected_ciphertext = 0x7D98_30B4_6112_24D2;

        let ciphertext = Des::new(plaintext).encrypt(key);
        assert_eq!(expected_ciphertext, ciphertext);

        let recovered = Des::decrypt(expected_ciphertext, key);
        assert_eq!(plaintext, recovered);
    }

    #[test]
    fn test_des_known_answer_vectors_additional() {
        let cases = [
            (
                0xFEDC_BA98_7654_3210,
                0x0E32_9232_EA6D_0D73,
                0xBC01_4F67_CA16_5622,
            ),
            (
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0xE779_65DA_E28A_E2F8,
            ),
            (
                0xFFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF,
                0x1886_9A25_1D75_1D07,
            ),
            (
                0x1111_1111_1111_1111,
                0x2222_2222_2222_2222,
                0x125D_26FB_F68C_A4A4,
            ),
        ];

        for (plaintext, key, expected_ciphertext) in cases {
            let ciphertext = Des::new(plaintext).encrypt(key);
            assert_eq!(expected_ciphertext, ciphertext);

            let recovered = Des::decrypt(expected_ciphertext, key);
            assert_eq!(plaintext, recovered);
        }
    }

    #[test]
    fn test_des_encrypt_is_deterministic() {
        let plaintext = 0x0123_4567_89AB_CDEF;
        let key = 0x1334_5779_9BBC_DFF1;

        let first = Des::new(plaintext).encrypt(key);
        let second = Des::new(plaintext).encrypt(key);

        assert_eq!(first, second);
    }

    #[test]
    fn test_des_different_inputs_change_ciphertext() {
        let key = 0x1334_5779_9BBC_DFF1;
        let first_plaintext = 0x0123_4567_89AB_CDEF;
        let second_plaintext = 0x0123_4567_89AB_CDEE;

        let first_ciphertext = Des::new(first_plaintext).encrypt(key);
        let second_ciphertext = Des::new(second_plaintext).encrypt(key);
        assert_ne!(first_ciphertext, second_ciphertext);

        let plaintext = 0x0123_4567_89AB_CDEF;
        let first_key = 0x1334_5779_9BBC_DFF1;
        let second_key = 0x0E32_9232_EA6D_0D73;

        let with_first_key = Des::new(plaintext).encrypt(first_key);
        let with_second_key = Des::new(plaintext).encrypt(second_key);
        assert_ne!(with_first_key, with_second_key);
    }

    #[test]
    fn test_des_wrong_key_does_not_roundtrip() {
        let plaintext = 0x0123_4567_89AB_CDEF;
        let key = 0x1334_5779_9BBC_DFF1;
        let wrong_key = 0x0E32_9232_EA6D_0D73;

        let ciphertext = Des::new(plaintext).encrypt(key);
        let recovered = Des::decrypt(ciphertext, wrong_key);

        assert_ne!(plaintext, recovered);
    }
}
