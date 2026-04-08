/// A single-bit memory cell, commonly known as a flip-flop.
///
/// FlipFlop can store a boolean value (`true` or `false`) and provides
/// methods to read, toggle, and set its state.
#[derive(Clone)]
pub struct FlipFlop {
    /// The internal state of the flip-flop.
    flag: bool,
}

impl FlipFlop {
    /// Creates a new flip-flop with an initial value.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let ff = FlipFlop::new(true);
    /// assert_eq!(ff.get(), true);
    /// ```
    pub fn new(flag: bool) -> Self {
        Self { flag }
    }

    /// Returns the current state of the flip-flop.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let ff = FlipFlop::new(false);
    /// assert_eq!(ff.get(), false);
    /// ```
    pub fn get(&self) -> bool {
        self.flag
    }

    /// Toggles the current state of the flip-flop.
    ///
    /// If it was `true`, it becomes `false`. If it was `false`, it becomes `true`.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let mut ff = FlipFlop::new(false);
    /// ff.mutate();
    /// assert_eq!(ff.get(), true);
    /// ```
    pub fn mutate(&mut self) {
        self.flag = !self.flag;
    }

    /// Toggles the state of the flip-flop and returns the new value.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let mut ff = FlipFlop::new(false);
    /// let new_val = ff.mutate_and_get();
    /// assert_eq!(new_val, true);
    /// ```
    pub fn mutate_and_get(&mut self) -> bool {
        self.flag = !self.flag;
        self.flag
    }

    /// Sets the flip-flop to a specific boolean value.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let mut ff = FlipFlop::new(false);
    /// ff.put(true);
    /// assert_eq!(ff.get(), true);
    /// ```
    pub fn put(&mut self, f: bool) {
        self.flag = f;
    }

    /// Sets the flip-flop to a specific boolean value and returns itself.
    ///
    /// # Example
    /// ```
    ///use cryptograph::tools::flip_flop::FlipFlop;
    ///
    /// let mut ff = FlipFlop::new(false);
    /// let f = ff.set(true);
    /// assert_eq!(f.get(), true);
    /// ```
    pub fn set(&mut self, f: bool) -> &mut Self {
        self.flag = f;
        self
    }
}
