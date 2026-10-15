//! Sliding-window detection for replayed packet counters.
//!
//! UDP packets may arrive out of order, so accepting only counters larger than
//! the last one would reject legitimate traffic. A 64-bit bitmap remembers the
//! newest counter and the previous 63 counters: bit 0 represents `highest`, bit
//! 1 represents `highest - 1`, and so on.
//!
//! Callers must authenticate a packet before recording its counter.

use std::{error::Error, fmt};

/// Number of recent packet counters tracked in the bitmap.
pub const REPLAY_WINDOW_SIZE: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reasons an authenticated packet counter cannot be accepted.
pub enum ReplayError {
    /// The exact counter is already marked in the current window.
    Duplicate,
    /// The counter fell behind the oldest position retained by the window.
    TooOld,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => {
                write!(formatter, "packet counter has already been received")
            }
            Self::TooOld => {
                write!(formatter, "packet counter is outside the replay window")
            }
        }
    }
}

impl Error for ReplayError {}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Replay state for one receive direction and one traffic key.
pub struct ReplayWindow {
    /// Largest authenticated counter observed so far, or `None` before any packet.
    highest: Option<u64>,
    /// Bitmap of received counters relative to `highest`.
    seen: u64,
}

impl ReplayWindow {
    /// Creates an empty replay window.
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: 0,
        }
    }

    /// Checks whether `counter` is fresh and records it atomically when accepted.
    pub fn check_and_record(&mut self, counter: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            // The first packet becomes bit 0 and establishes the reference point.
            self.highest = Some(counter);
            self.seen = 1;
            return Ok(());
        };

        if counter > highest {
            let shift = counter - highest;

            // A jump of 64 or more makes every old bit irrelevant. A smaller
            // jump moves the history left, then bit 0 records the new counter.
            self.seen = if shift >= REPLAY_WINDOW_SIZE {
                1
            } else {
                (self.seen << shift) | 1
            };

            self.highest = Some(counter);
            return Ok(());
        }

        // Older packets are allowed when their corresponding bit is still in range.
        let distance = highest - counter;

        if distance >= REPLAY_WINDOW_SIZE {
            return Err(ReplayError::TooOld);
        }

        let counter_bit = 1_u64 << distance;

        if self.seen & counter_bit != 0 {
            return Err(ReplayError::Duplicate);
        }

        self.seen |= counter_bit;

        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayError, ReplayWindow};

    #[test]
    fn accepts_the_first_counter() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(1), Ok(()));
    }

    #[test]
    fn rejects_a_duplicate_counter() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(7), Ok(()));
        assert_eq!(window.check_and_record(7), Err(ReplayError::Duplicate),);
    }

    #[test]
    fn accepts_out_of_order_counters_once() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(10), Ok(()));
        assert_eq!(window.check_and_record(12), Ok(()));
        assert_eq!(window.check_and_record(11), Ok(()));

        assert_eq!(window.check_and_record(11), Err(ReplayError::Duplicate),);
    }

    #[test]
    fn accepts_the_oldest_counter_inside_the_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(100), Ok(()));
        assert_eq!(window.check_and_record(37), Ok(()));

        assert_eq!(window.check_and_record(37), Err(ReplayError::Duplicate),);
    }

    #[test]
    fn rejects_a_counter_just_outside_the_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(100), Ok(()));

        assert_eq!(window.check_and_record(36), Err(ReplayError::TooOld),);
    }

    #[test]
    fn large_forward_jump_starts_a_fresh_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.check_and_record(1), Ok(()));
        assert_eq!(window.check_and_record(100), Ok(()));

        assert_eq!(window.check_and_record(1), Err(ReplayError::TooOld),);
        assert_eq!(window.check_and_record(100), Err(ReplayError::Duplicate),);
    }

    #[test]
    fn replay_errors_have_readable_messages() {
        assert_eq!(
            ReplayError::Duplicate.to_string(),
            "packet counter has already been received",
        );

        assert_eq!(
            ReplayError::TooOld.to_string(),
            "packet counter is outside the replay window",
        );
    }
}
