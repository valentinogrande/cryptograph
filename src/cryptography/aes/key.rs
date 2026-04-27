use crate::cryptography::aes::{bite_sub::SBOX, encrypt::AesEncryptionType};

const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1B00_0000,
    0x3600_0000,
];

fn substitute_byte(byte: u8) -> u8 {
    SBOX[(byte >> 4) as usize][(byte & 0x0F) as usize]
}

fn rotate_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn sub_word(word: u32) -> u32 {
    u32::from_be_bytes(word.to_be_bytes().map(substitute_byte))
}

fn rcon(round: usize) -> u32 {
    RCON[round - 1]
}

/// Expands an AES key into one 128-bit round key per round.
///
/// The returned vector contains `Nr + 1` entries where `Nr` is the AES round
/// count for the selected key size.
///
/// # Example
///
/// ```rust
/// use cryptograph::cryptography::aes::{AesEncryptionType, key::expand_key};
///
/// let round_keys = expand_key(AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F));
///
/// assert_eq!(round_keys.len(), 11);
/// assert_eq!(round_keys[0], 0x000102030405060708090A0B0C0D0E0F);
/// ```
pub fn expand_key(security: AesEncryptionType) -> Vec<u128> {
    let key_bytes = security.key_bytes();
    let nk = key_bytes.len() / 4;
    let nr = security.rounds();
    let total_words = 4 * (nr + 1);

    let mut words = Vec::with_capacity(total_words);

    for chunk in key_bytes.chunks_exact(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        words.push(u32::from_be_bytes(word));
    }

    for i in nk..total_words {
        let mut temp = words[i - 1];

        if i % nk == 0 {
            temp = sub_word(rotate_word(temp)) ^ rcon(i / nk);
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }

        words.push(words[i - nk] ^ temp);
    }

    words
        .chunks_exact(4)
        .map(|chunk| {
            ((chunk[0] as u128) << 96)
                | ((chunk[1] as u128) << 64)
                | ((chunk[2] as u128) << 32)
                | (chunk[3] as u128)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::expand_key;
    use crate::cryptography::aes::encrypt::{AesEncryptionType, U192, U256};

    #[test]
    fn expands_expected_number_of_round_keys() {
        assert_eq!(
            expand_key(AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F)).len(),
            11
        );
        assert_eq!(
            expand_key(AesEncryptionType::Medium(U192::new([
                0x0001020304050607,
                0x08090A0B0C0D0E0F,
                0x1011121314151617,
            ])))
            .len(),
            13
        );
        assert_eq!(
            expand_key(AesEncryptionType::High(U256::new([
                0x0001020304050607,
                0x08090A0B0C0D0E0F,
                0x1011121314151617,
                0x18191A1B1C1D1E1F,
            ])))
            .len(),
            15
        );
    }

    #[test]
    fn aes_128_key_schedule_matches_fips_round_keys() {
        let round_keys = expand_key(AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F));

        assert_eq!(round_keys[0], 0x000102030405060708090A0B0C0D0E0F);
        assert_eq!(round_keys[10], 0x13111D7FE3944A17F307A78B4D2B30C5);
    }
}
