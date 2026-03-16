/// Encrypts a message using the Caesar cipher.
///
/// # Arguments
///
/// * `msg` - The plaintext message to encrypt
/// * `shift` - Number of positions to shift each byte
///
/// # Examples
///
/// ```
/// use cryptograph::cesar_encrypt;
///
/// let result = cesar_encrypt("hello", 3).unwrap();
/// assert_eq!(result, "khoor");
/// ```
///
/// # Errors
///
/// Returns `Err` if the resulting bytes are not valid UTF-8.
pub fn cesar_encrypt(msg: &str, shift: u8) -> Result<String, std::string::FromUtf8Error> {
    let encrypted_msg: Vec<u8> = {
        let mut enc = vec![];
        for character in msg.as_bytes() {
            enc.push(character.wrapping_add(shift));
        }
        enc
    };

    String::from_utf8(encrypted_msg)
}
