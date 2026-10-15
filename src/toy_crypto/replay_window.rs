//! Sliding-window detection for replayed packet counters.

use std::{error::Error, fmt};

pub const REPLAY_WINDOW_SIZE: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    Duplicate,
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
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: 0,
        }
    }

    pub fn check_and_record(&mut self, counter: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.seen = 1;
            return Ok(());
        };

        if counter > highest {
            let shift = counter - highest;

            self.seen = if shift >= REPLAY_WINDOW_SIZE {
                1
            } else {
                (self.seen << shift) | 1
            };

            self.highest = Some(counter);
            return Ok(());
        }

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
}
