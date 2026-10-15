//! Monotonic packet-counter allocation for unique send nonces.
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendCounterError {
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
pub struct SendCounter {
    next: Option<u64>,
}

impl SendCounter {
    pub const fn new() -> Self {
        Self { next: Some(1) }
    }

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
