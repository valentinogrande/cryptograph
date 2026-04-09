use crate::pseudorandom_generator::lfsr::Lfsr;
use crate::tools::flip_flop::FlipFlop;

/// Reconstructs the original message from a sequence encrypted using an LFSR.
///
/// This function performs a reverse operation on a stream cipher that uses a
/// Linear Feedback Shift Register (LFSR). Given:
///
/// - `y`: the encrypted sequence
/// - `x`: the known plaintext (or known keystream portion)
/// - `n`: the number of flip-flops (LFSR size)
/// - `rule`: the feedback function used by the LFSR
///
/// The function first reconstructs the initial LFSR state using the XOR
/// between the known plaintext and the encrypted sequence. Then, it rebuilds
/// the keystream using the LFSR and decrypts the entire message.
///
/// # Arguments
///
/// * `y` - The encrypted sequence as a vector of `FlipFlop`s
/// * `n` - The number of flip-flops in the LFSR
/// * `x` - Known plaintext or known keystream prefix
/// * `rule` - Feedback function used by the LFSR
///
/// # Returns
///
/// Returns a `Result` containing:
///
/// * `Ok(Vec<FlipFlop>)` — The reconstructed original message
/// * `Err` — If the known plaintext is shorter than the LFSR size
///
/// # Errors
///
/// Returns an error if:
///
/// * `x.len() < n`, meaning there is not enough known data to reconstruct
///   the initial LFSR state.
///
/// # Example
///
/// ```
/// use cryptograph::tools::flip_flop::FlipFlop;
/// use cryptograph::pseudorandom_generator::lfsr::Lfsr;
/// use cryptograph::cryptoanalysis::reverse_lfsr::reverse_lfsr;
///
/// let y = vec![
///     FlipFlop::new(true),
///     FlipFlop::new(false),
///     FlipFlop::new(true),
/// ];
///
/// let x = vec![
///     FlipFlop::new(false),
///     FlipFlop::new(true),
///     FlipFlop::new(false),
/// ];
///
/// let result = reverse_lfsr(
///     y,
///     3,
///     x,
///     |ff| ff[0].get() ^ ff[ff.len() - 1].get(),
/// );
///
/// assert!(result.is_ok());
/// ```
pub fn reverse_lfsr<R: Fn(&[FlipFlop]) -> bool>(
    y: Vec<FlipFlop>,
    n: usize,
    x: Vec<FlipFlop>,
    rule: R,
) -> Result<Vec<FlipFlop>, Box<dyn std::error::Error>> {
    type F = Vec<FlipFlop>;

    if x.len() < n {
        return Err("No enough X".into());
    }

    let mut s: F = Vec::new();

    for (ys, xs) in x.iter().zip(y.iter()) {
        s.push(FlipFlop::new(ys.get() ^ xs.get()));
    }

    let sn = Vec::from(&s[0..n]);

    let mut lfsr = Lfsr::new(sn, rule);

    let mut msg: F = Vec::new();
    for ys in y {
        let s = lfsr.rotate();
        msg.push(FlipFlop::new(ys.get() ^ s.get()));
    }

    Ok(msg)
}
