use crate::math::multiplicative_inverse::multiplicative_inverse;
/// Decrypts a string encoded with the affine cipher.
///
/// Given a ciphertext `y`, reverses the affine encryption using the formula:
///
/// ```text
/// D(y) = a⁻¹ · (y - b) mod 256
/// ```
///
/// where `a⁻¹` is the multiplicative inverse of `a` mod 256.
///
/// # Arguments
///
/// * `y` - Ciphertext to decrypt
/// * `a` - Multiplicative key. Must be odd otherwise `multiplicative_inverse` returns `None` and the function panics.
/// * `b` - Additive key
///
/// # Returns
///
/// * `Ok(String)` - Decrypted plaintext
/// * `Err(FromUtf8Error)` - If the resulting bytes are not valid UTF-8
///
/// # Panics
///
/// Panics if `a` has no multiplicative inverse mod 256 (i.e. `a` is even).
///
/// # Examples
///
/// ```
/// use cryptograph::cryptography::affine::decrypt::affine_decrypt;
/// use cryptograph::cryptography::affine::encrypt::affine_encrypt;
/// let encrypted = affine_encrypt("hola", 3, 7);
/// let decrypted = affine_decrypt(&encrypted.unwrap(), 3, 7).unwrap();
/// assert_eq!(decrypted, "hola");
/// ```
pub fn affine_decrypt(y: &str, a: i32, b: u8) -> Result<String, std::string::FromUtf8Error> {
    let x = {
        let mut x: Vec<u8> = vec![];
        for character in y.as_bytes() {
            let mut i = character.wrapping_sub(b);
            i = i.wrapping_mul(multiplicative_inverse(a, 256).unwrap() as u8);
            x.push(i);
        }
        x
    };
    String::from_utf8(x)
}
