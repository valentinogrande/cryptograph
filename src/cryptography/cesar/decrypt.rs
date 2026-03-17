/// Decrypts a message using the Caesar cipher.
///
/// # Arguments
///
/// * `msg` - The message to decrypt
/// * `shift` - Number of positions to shift each byte
///
/// # Examples
///
/// ```
/// use cryptograph::cryptography::cesar::decrypt::cesar_decrypt;
///
/// let result = cesar_decrypt("khoor", 3).unwrap();
/// assert_eq!(result, "hello");
/// ```
///
/// # Errors
///
/// Returns `Err` if the resulting bytes are not valid UTF-8.
pub fn cesar_decrypt(msg: &str, shift: u8) -> Result<String, std::string::FromUtf8Error> {
    let encrypted_msg: Vec<u8> = {
        let mut enc = vec![];
        for character in msg.as_bytes() {
            enc.push(character.wrapping_sub(shift));
        }
        enc
    };

    String::from_utf8(encrypted_msg)
}
