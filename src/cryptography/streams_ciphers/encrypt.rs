use futures::{StreamExt, stream};

/// Encrypts and decrypts a message using bitwise XOR with a seed (stream cipher).
///
/// Since XOR is symmetric, the same function serves for both encryption and decryption.
///
/// # Arguments
/// * `x` - Message in bits to encrypt/decrypt
/// * `seed` - Keystream of the same length as `x`
///
/// # Panics
/// If `x` and `seed` have different lengths.
///
/// # Example
/// ```
/// use cryptograph::cryptography::streams_ciphers::encrypt::stream_cipher_crypt;
///
/// let message = vec![true, false, true];
/// let seed    = vec![true, true, false];
/// let cipher  = stream_cipher_crypt(message.clone(), seed.clone());
/// let original = stream_cipher_crypt(cipher, seed);
/// assert_eq!(original, message);
/// ```
pub fn stream_cipher_crypt(x: Vec<bool>, seed: Vec<bool>) -> Vec<bool> {
    assert_eq!(
        x.len(),
        seed.len(),
        "seed debe tener el mismo largo que el mensaje"
    );
    let mut y = vec![];
    for (bit, s) in x.iter().zip(seed) {
        y.push(bit ^ s)
    }
    y
}

/// Lazy version of [`stream_cipher_encrypt`] that returns a [`Stream`] of bits.
///
/// Unlike the synchronous version, it does not allocate the output `Vec` —
/// each bit is computed only when the stream is consumed.
///
/// # Arguments
/// * `x` - Message in bits to encrypt/decrypt
/// * `seed` - Keystream of the same length as `x`
///
/// # Panics
/// If `x` and `seed` have different lengths.
///
/// # Example
/// ```
/// use futures::StreamExt;
/// use cryptograph::cryptography::streams_ciphers::encrypt::fut_stream_cipher_encrypt;
///
/// tokio_test::block_on(async {
///     let message = vec![true, false, true];
///     let seed    = vec![true, true, false];
///     let mut stream = fut_stream_cipher_encrypt(message, seed);
///
///     while let Some(bit) = stream.next().await {
///         println!("{}", bit);
///     }
/// });
/// ```
pub fn fut_stream_cipher_encrypt(x: Vec<bool>, seed: Vec<bool>) -> impl StreamExt<Item = bool> {
    assert_eq!(
        x.len(),
        seed.len(),
        "seed debe tener el mismo largo que el mensaje"
    );

    stream::iter(x.into_iter().zip(seed).map(|(b, s)| b ^ s))
}
