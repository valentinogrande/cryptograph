use futures::StreamExt;

/// Lazy async version of [`stream_cipher_decrypt`] that consumes a [`Stream`] of bits.
///
/// Decrypts each bit as it arrives from the stream, without requiring the full
/// ciphertext to be allocated upfront. Stops when either the stream or the seed
/// is exhausted.
///
/// # Arguments
/// * `y` - Stream of encrypted bits
/// * `seed` - Keystream used during encryption
///
/// # Example
/// ```
/// use futures::stream;
/// use cryptograph::cryptography::streams_ciphers::decrypt::fut_stream_cipher_decrypt;
///
/// tokio_test::block_on(async {
///     let encrypted = vec![false, true, true];
///     let seed      = vec![true, true, false];
///     let stream    = stream::iter(encrypted);
///     let decrypted = fut_stream_cipher_decrypt(stream, seed).await;
///     println!("{:?}", decrypted);
/// });
/// ```
pub async fn fut_stream_cipher_decrypt(
    mut y: impl StreamExt<Item = bool> + Unpin,
    seed: Vec<bool>,
) -> Vec<bool> {
    let mut x = vec![];
    let mut seed = seed.into_iter();
    while let (Some(b), Some(s)) = (y.next().await, seed.next()) {
        x.push(b ^ s);
    }
    x
}
