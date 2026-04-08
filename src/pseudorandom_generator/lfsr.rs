use crate::tools::flip_flop::FlipFlop;

/// A Linear Feedback Shift Register (LFSR) generator.
///
/// LFSR produces a sequence of pseudorandom bits using a vector of flip-flops
/// and a feedback function that defines which bits are XORed to produce the next state.
pub struct Lsfr<F: Fn(&[FlipFlop]) -> bool> {
    /// The vector of flip-flops representing the current state.
    pub ff: Vec<FlipFlop>,

    /// The feedback function used to calculate the new input bit.
    pub fb: F,
}

impl<F> Lsfr<F>
where
    F: Fn(&[FlipFlop]) -> bool,
{
    /// Creates a new LFSR with the given flip-flops.
    ///
    /// The default feedback function XORs the first and last flip-flops.
    ///
    /// # Example
    /// ```
    /// use cryptograph::tools::flip_flop::FlipFlop;
    /// use cryptograph::pseudorandom_generator::lfsr::Lsfr;
    ///
    /// let ff = vec![
    ///     FlipFlop::new(true),
    ///     FlipFlop::new(false),
    ///     FlipFlop::new(true),
    /// ];
    /// let lfsr = Lsfr::new(ff,|ff| ff[0].get() ^ ff[ff.len() -1].get());
    /// assert_eq!(lfsr.get().len(), 3);
    /// ```
    pub fn new(ff: Vec<FlipFlop>, rule: F) -> Self {
        Self { ff, fb: rule }
    }

    /// Performs one rotation of the LFSR.
    ///
    /// Shifts all flip-flops to the right and sets the first flip-flop
    /// using the feedback function.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///use cryptograph::pseudorandom_generator::lfsr::Lsfr;
    ///
    /// let mut lfsr = Lsfr::new(vec![
    ///     FlipFlop::new(true),
    ///     FlipFlop::new(false),
    ///     FlipFlop::new(true),
    /// ],
    /// |ff| ff[0].get() ^ ff[ff.len() -1].get(),
    /// );
    /// lfsr.rotate();
    /// ```
    pub fn rotate(&mut self) -> &mut FlipFlop {
        let fb = (self.fb)(&self.ff);

        for i in (1..self.ff.len()).rev() {
            let val = self.ff[i - 1].get();
            self.ff[i].put(val);
        }

        self.ff[0].set(fb)
    }

    /// Returns the rotated Flip Flop.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///use cryptograph::pseudorandom_generator::lfsr::Lsfr;
    ///
    /// let lfsr = Lsfr::new(vec![
    ///     FlipFlop::new(true),
    ///     FlipFlop::new(false),
    /// ],
    /// |ff| ff[0].get() ^ ff[ff.len() -1].get(),
    /// );
    /// let state = lfsr.get();
    /// assert_eq!(state[0].get(), true);
    /// ```
    pub fn get(&self) -> &[FlipFlop] {
        &self.ff
    }

    /// Calculates the total number of possible states for this LFSR.
    ///
    /// For `n` flip-flops, the maximum number of unique states is `2^n - 1`.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///use cryptograph::pseudorandom_generator::lfsr::Lsfr;
    ///
    /// let lfsr = Lsfr::new(vec![
    ///     FlipFlop::new(true),
    ///     FlipFlop::new(false),
    ///     FlipFlop::new(true),
    /// ],
    /// |ff| ff[0].get() ^ ff[ff.len() -1].get(),
    /// );
    /// assert_eq!(lfsr.calculate_possibilities(), 7); // 2^3 - 1
    /// ```
    pub fn calculate_possibilities(&self) -> usize {
        (1 << self.ff.len()) - 1
    }
}
