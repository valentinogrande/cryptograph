//! AES decryption implementation.
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::aes::{Aes, AesEncryptionType};
//!
//! let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
//! let ciphertext = 0x69C4E0D86A7B0430D8CDB78070B4C55A;
//!
//! let plaintext = Aes::decrypt(ciphertext, key);
//! assert_eq!(plaintext, 0x00112233445566778899AABBCCDDEEFF);
//! ```

use crate::cryptography::aes::{
    encrypt::{Aes, AesEncryptionType, add_round_key, inverse_sub_bytes_state},
    key::expand_key,
    mix_column::inverse_mix_columns_state,
    shift_rows::inverse_shift_rows_state,
};

impl Aes {
    /// Decrypts one AES block with the provided key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cryptograph::cryptography::aes::{Aes, AesEncryptionType};
    ///
    /// let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
    /// let ciphertext = 0x69C4E0D86A7B0430D8CDB78070B4C55A;
    ///
    /// let plaintext = Aes::decrypt(ciphertext, key);
    /// assert_eq!(plaintext, 0x00112233445566778899AABBCCDDEEFF);
    /// ```
    pub fn decrypt(y: u128, security: AesEncryptionType) -> u128 {
        let round_keys = expand_key(security);
        let mut state = y.to_be_bytes();

        add_round_key(&mut state, round_keys[security.rounds()]);

        for round in (1..security.rounds()).rev() {
            inverse_shift_rows_state(&mut state);
            inverse_sub_bytes_state(&mut state);
            add_round_key(&mut state, round_keys[round]);
            inverse_mix_columns_state(&mut state);
        }

        inverse_shift_rows_state(&mut state);
        inverse_sub_bytes_state(&mut state);
        add_round_key(&mut state, round_keys[0]);

        u128::from_be_bytes(state)
    }
}
