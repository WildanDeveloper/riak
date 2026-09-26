//! Nonce generation helpers for the experimental RIAK wrappers.
//!
//! The stateless wrapper APIs still accept caller-supplied nonces for
//! compatibility. For multiple messages under one key, use
//! [`NonceSequence`] and persist its random prefix; never restart the counter
//! with the same prefix.

use std::fmt;

/// Errors returned by a nonce sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// The 64-bit counter space was exhausted.
    CounterExhausted,
}

impl fmt::Display for NonceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterExhausted => formatter.write_str("nonce counter exhausted"),
        }
    }
}

impl std::error::Error for NonceError {}

/// A counter-based 96-bit nonce generator for one key.
///
/// The nonce layout is an 8-byte caller-supplied random prefix followed by a
/// 4-byte big-endian counter. One prefix supports up to `2^32` nonces before
/// exhaustion; uniqueness is guaranteed only within one prefix, so callers
/// must persist the prefix and issued counter (or rotate the prefix) per key.
pub struct NonceSequence {
    prefix: [u8; 8],
    counter: u32,
    exhausted: bool,
}

impl NonceSequence {
    /// Create a sequence from a random per-key prefix.
    pub fn new(prefix: [u8; 8]) -> Self {
        Self {
            prefix,
            counter: 0,
            exhausted: false,
        }
    }

    /// Resume a sequence after a restart using a persisted issued count.
    ///
    /// If the prefix is ever uncertain after a crash, rotate to a new random
    /// prefix instead of resuming from zero.
    pub fn resume(prefix: [u8; 8], issued: u32) -> Self {
        Self {
            prefix,
            counter: issued,
            exhausted: false,
        }
    }

    /// Return the per-key prefix.
    pub fn prefix(&self) -> [u8; 8] {
        self.prefix
    }

    /// Return the number of nonces already issued.
    pub fn issued(&self) -> u32 {
        self.counter
    }

    /// Issue the next unique nonce.
    pub fn next(&mut self) -> Result<[u8; 12], NonceError> {
        if self.exhausted {
            return Err(NonceError::CounterExhausted);
        }
        let counter = self.counter;
        if counter == u32::MAX {
            self.exhausted = true;
        } else {
            self.counter += 1;
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.prefix);
        nonce[8..].copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_unique_and_deterministic_for_a_prefix() {
        let mut sequence = NonceSequence::new([0x11; 8]);
        let first = sequence.next().unwrap();
        let second = sequence.next().unwrap();
        assert_eq!(first[..8], [0x11; 8]);
        assert_eq!(first[8..], 0u32.to_be_bytes());
        assert_eq!(second[8..], 1u32.to_be_bytes());
        assert_ne!(first, second);
        assert_eq!(sequence.prefix(), [0x11; 8]);
        assert_eq!(sequence.issued(), 2);
        let mut resumed = NonceSequence::resume([0x11; 8], sequence.issued());
        assert_eq!(resumed.next().unwrap()[8..], 2u32.to_be_bytes());
    }

    #[test]
    fn sequence_stops_before_wrapping() {
        let mut sequence = NonceSequence {
            prefix: [3; 8],
            counter: u32::MAX,
            exhausted: false,
        };
        assert_eq!(sequence.next().unwrap()[8..], u32::MAX.to_be_bytes());
        assert_eq!(sequence.next(), Err(NonceError::CounterExhausted));
    }

    #[test]
    fn separate_prefixes_are_separate_sequences() {
        let mut first = NonceSequence::new([1; 8]);
        let mut second = NonceSequence::new([2; 8]);
        assert_ne!(first.next().unwrap(), second.next().unwrap());
    }
}
