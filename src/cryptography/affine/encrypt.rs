/// Encrypts a string using the affine cipher.
///
/// Each byte of the input is transformed using the formula:
///
/// ```text
/// E(x) = a · x + b mod 256
/// ```
///
/// # Arguments
///
/// * `x` - Plaintext to encrypt
/// * `a` - Multiplicative key. Must be odd (coprimo con 256) to allow decryption.
/// * `b` - Additive key
///
/// # Returns
///
/// * `Ok(String)` - Encrypted ciphertext
/// * `Err(FromUtf8Error)` - If the resulting bytes are not valid UTF-8
///
/// # Examples
///
/// ```
/// use cryptograph::cryptography::affine::encrypt::affine_encrypt;
/// use cryptograph::cryptography::affine::decrypt::affine_decrypt;
///
/// let encrypted = affine_encrypt("hola", 3, 7).unwrap();
/// let decrypted = affine_decrypt(&encrypted, 3, 7).unwrap();
/// assert_eq!(decrypted, "hola");
/// ```
pub fn affine_encrypt(x: &str, a: u8, b: u8) -> Result<String, std::string::FromUtf8Error> {
    let y = {
        let mut y: Vec<u8> = vec![];
        for character in x.as_bytes() {
            let mut i = character.wrapping_mul(a);
            i = i.wrapping_add(b);
            y.push(i);
        }
        y
    };
    String::from_utf8(y)
}
