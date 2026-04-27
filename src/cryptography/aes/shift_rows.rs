/// Applies the AES `ShiftRows` step to one 128-bit state.
///
/// The input and output use the standard AES byte ordering, where the first
/// four bytes form the first column of the state matrix.
///
/// # Example
///
/// ```rust
/// use cryptograph::cryptography::aes::shift_rows::shift_rows;
///
/// let shifted = shift_rows(0x63CAB7040953D051CD60E0E7BA70E18C);
/// assert_eq!(shifted, 0x6353E08C0960E104CD70B751BACAD0E7);
/// ```
pub fn shift_rows(x: u128) -> u128 {
    let mut state = x.to_be_bytes();
    shift_rows_state(&mut state);
    u128::from_be_bytes(state)
}

/// Applies the inverse AES `ShiftRows` step to one 128-bit state.
pub fn inverse_shift_rows(x: u128) -> u128 {
    let mut state = x.to_be_bytes();
    inverse_shift_rows_state(&mut state);
    u128::from_be_bytes(state)
}

pub(crate) fn shift_rows_state(state: &mut [u8; 16]) {
    let original = *state;

    for row in 0..4 {
        for col in 0..4 {
            state[col * 4 + row] = original[((col + row) % 4) * 4 + row];
        }
    }
}

pub(crate) fn inverse_shift_rows_state(state: &mut [u8; 16]) {
    let original = *state;

    for row in 0..4 {
        for col in 0..4 {
            state[col * 4 + row] = original[((col + 4 - row) % 4) * 4 + row];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{inverse_shift_rows, shift_rows};

    #[test]
    fn shift_rows_matches_fips_example() {
        let input = 0x63CAB7040953D051CD60E0E7BA70E18C;
        let expected = 0x6353E08C0960E104CD70B751BACAD0E7;

        assert_eq!(shift_rows(input), expected);
    }

    #[test]
    fn inverse_shift_rows_restores_original_state() {
        let input = 0x63CAB7040953D051CD60E0E7BA70E18C;
        let shifted = shift_rows(input);

        assert_eq!(inverse_shift_rows(shifted), input);
    }
}
