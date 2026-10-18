//! Tracks missed authenticated keepalive responses.
//!
//! This module contains no sockets or threads. The runtime calls
//! `on_interval_elapsed` whenever its keepalive timer expires.

use std::num::NonZeroU8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessAction {
    SendKeepalive,
    PeerTimedOut,
}

#[derive(Debug)]
pub struct LivenessTracker {
    maximum_missed_responses: NonZeroU8,
    missed_responses: u8,
    awaiting_response: bool,
}

impl LivenessTracker {
    pub const fn new(maximum_missed_responses: NonZeroU8) -> Self {
        Self {
            maximum_missed_responses,
            missed_responses: 0,
            awaiting_response: false,
        }
    }

    pub fn on_interval_elapsed(&mut self) -> LivenessAction {
        if self.awaiting_response {
            self.missed_responses = self.missed_responses.saturating_add(1);

            if self.missed_responses >= self.maximum_missed_responses.get() {
                return LivenessAction::PeerTimedOut;
            }
        }

        self.awaiting_response = true;

        LivenessAction::SendKeepalive
    }

    pub fn record_authenticated_activity(&mut self) {
        self.missed_responses = 0;
        self.awaiting_response = false;
    }

    pub const fn missed_responses(&self) -> u8 {
        self.missed_responses
    }

    pub const fn is_awaiting_response(&self) -> bool {
        self.awaiting_response
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU8;

    use super::{LivenessAction, LivenessTracker};

    fn tracker() -> LivenessTracker {
        LivenessTracker::new(NonZeroU8::new(3).unwrap())
    }

    #[test]
    fn first_interval_sends_a_keepalive() {
        let mut tracker = tracker();

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::SendKeepalive);

        assert!(tracker.is_awaiting_response());
        assert_eq!(tracker.missed_responses(), 0);
    }

    #[test]
    fn unanswered_keepalives_eventually_time_out() {
        let mut tracker = tracker();

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::SendKeepalive);

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::SendKeepalive);

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::SendKeepalive);

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::PeerTimedOut);

        assert_eq!(tracker.missed_responses(), 3);
    }

    #[test]
    fn authenticated_activity_resets_missed_responses() {
        let mut tracker = tracker();

        tracker.on_interval_elapsed();
        tracker.on_interval_elapsed();

        assert_eq!(tracker.missed_responses(), 1);

        tracker.record_authenticated_activity();

        assert_eq!(tracker.missed_responses(), 0);
        assert!(!tracker.is_awaiting_response());
    }

    #[test]
    fn next_interval_after_activity_starts_a_fresh_probe() {
        let mut tracker = tracker();

        tracker.on_interval_elapsed();
        tracker.on_interval_elapsed();
        tracker.record_authenticated_activity();

        assert_eq!(tracker.on_interval_elapsed(), LivenessAction::SendKeepalive);

        assert_eq!(tracker.missed_responses(), 0);
    }
}
