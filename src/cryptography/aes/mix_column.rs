use crate::cryptography::aes::bite_sub::Gf256Rijndael;

fn gf_mul(left: u8, right: u8) -> u8 {
    Gf256Rijndael::new(left).mul(Gf256Rijndael::new(right)).0
}

/// Applies the AES `MixColumns` step to a full 128-bit state.
///
/// # Example
///
/// ```rust
/// use cryptograph::cryptography::aes::mix_column::mix_column;
///
/// let mixed = mix_column(0xDB135345000000000000000000000000);
/// assert_eq!(mixed, 0x8E4DA1BC000000000000000000000000);
/// ```
pub fn mix_column(x: u128) -> u128 {
    let mut state = x.to_be_bytes();
    mix_columns_state(&mut state);
    u128::from_be_bytes(state)
}

/// Applies the inverse AES `MixColumns` step to a full 128-bit state.
pub fn inverse_mix_column(x: u128) -> u128 {
    let mut state = x.to_be_bytes();
    inverse_mix_columns_state(&mut state);
    u128::from_be_bytes(state)
}

pub(crate) fn mix_columns_state(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let s0 = state[offset];
        let s1 = state[offset + 1];
        let s2 = state[offset + 2];
        let s3 = state[offset + 3];

        state[offset] = gf_mul(s0, 0x02) ^ gf_mul(s1, 0x03) ^ s2 ^ s3;
        state[offset + 1] = s0 ^ gf_mul(s1, 0x02) ^ gf_mul(s2, 0x03) ^ s3;
        state[offset + 2] = s0 ^ s1 ^ gf_mul(s2, 0x02) ^ gf_mul(s3, 0x03);
        state[offset + 3] = gf_mul(s0, 0x03) ^ s1 ^ s2 ^ gf_mul(s3, 0x02);
    }
}

pub(crate) fn inverse_mix_columns_state(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let s0 = state[offset];
        let s1 = state[offset + 1];
        let s2 = state[offset + 2];
        let s3 = state[offset + 3];

        state[offset] = gf_mul(s0, 0x0E) ^ gf_mul(s1, 0x0B) ^ gf_mul(s2, 0x0D) ^ gf_mul(s3, 0x09);
        state[offset + 1] =
            gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0E) ^ gf_mul(s2, 0x0B) ^ gf_mul(s3, 0x0D);
        state[offset + 2] =
            gf_mul(s0, 0x0D) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0E) ^ gf_mul(s3, 0x0B);
        state[offset + 3] =
            gf_mul(s0, 0x0B) ^ gf_mul(s1, 0x0D) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0E);
    }
}

#[cfg(test)]
mod tests {
    use super::{inverse_mix_column, mix_column};

    #[test]
    fn mix_column_matches_fips_example_column() {
        let input = 0xDB135345000000000000000000000000;
        let expected = 0x8E4DA1BC000000000000000000000000;

        assert_eq!(mix_column(input), expected);
    }

    #[test]
    fn inverse_mix_column_restores_original_state() {
        let input = 0x6353E08C0960E104CD70B751BACAD0E7;
        let mixed = mix_column(input);

        assert_eq!(inverse_mix_column(mixed), input);
    }
}
