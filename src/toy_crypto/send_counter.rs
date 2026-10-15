//! Monotonic packet-counter allocation for unique send nonces.
//!
//! ChaCha20-Poly1305 must never reuse a nonce with the same key. One counter is
//! therefore owned by each sending direction and is never allowed to wrap.
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure to allocate another unique counter under the current key.
pub enum SendCounterError {
    /// Every `u64` counter has been consumed; a fresh key is required.
    Exhausted,
}

impl fmt::Display for SendCounterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => {
                write!(formatter, "send counter is exhausted")
            }
        }
    }
}

impl Error for SendCounterError {}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Allocates strictly increasing counters for one directional traffic key.
pub struct SendCounter {
    /// `Some` contains the next value; `None` permanently marks exhaustion.
    next: Option<u64>,
}

impl SendCounter {
    /// Creates a counter whose first allocated value is one.
    pub const fn new() -> Self {
        Self { next: Some(1) }
    }

    /// Returns the current counter and advances without ever wrapping to zero.
    ///
    /// `u64::MAX` is returned once. Its checked increment produces `None`, so
    /// every later call reports exhaustion instead of reusing a nonce.
    pub fn take_next(&mut self) -> Result<u64, SendCounterError> {
        let counter = self.next.ok_or(SendCounterError::Exhausted)?;

        self.next = counter.checked_add(1);

        Ok(counter)
    }
}

impl Default for SendCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{SendCounter, SendCounterError};

    #[test]
    fn allocates_increasing_counters() {
        let mut counters = SendCounter::new();

        assert_eq!(counters.take_next(), Ok(1));
        assert_eq!(counters.take_next(), Ok(2));
        assert_eq!(counters.take_next(), Ok(3));
    }

    #[test]
    fn never_wraps_after_the_maximum_counter() {
        let mut counters = SendCounter {
            next: Some(u64::MAX),
        };

        assert_eq!(counters.take_next(), Ok(u64::MAX));
        assert_eq!(counters.take_next(), Err(SendCounterError::Exhausted),);
    }

    #[test]
    fn exhausted_error_has_a_readable_message() {
        assert_eq!(
            SendCounterError::Exhausted.to_string(),
            "send counter is exhausted",
        );
    }
}
