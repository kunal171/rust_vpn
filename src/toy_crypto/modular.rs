//! Modular arithmetic on `u64`, the number system behind Diffie-Hellman.
//!
//! This is a learning implementation. It is not constant-time, so it must
//! never handle real secrets: use an audited crate for that.

/// Returns `(a * b) mod modulus` without overflowing.
///
/// Panics if `modulus` is zero.
pub fn mod_mul(a:u64 b : u64, modulus: u64) -> u64 {
    // The product of two u64 values needs up to 128 bits. The remainder is
    // below `modulus`, so narrowing it back to u64 cannot lose anything.
    ((u128::from(a) * u128::from(b)) % u128::from(modulus)) as u64
}

/// Returns `base^exponent mod modulus` using square-and-multiply.
///
/// Panics if `modulus` is zero.
pub fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    // Everything is congruent to 0 mod 1, including base^0.
    if modulus == 1 {
        return 0;
    }

    let mut result = 1;
    // Holds base^1, base^2, base^4, ... as the loop walks the exponent's bits.
    let mut square = base % modulus;
    let mut remaining = exponent;

    while remaining > 0 {
        if remaining & 1 == 1 {
            result = mod_mul(result, square, modulus);
        }
        square = mod_mul(square, square, modulus);
        remaining >>= 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::{mod_mul, mod_pow};

    /// 2^64 - 59, the largest prime that fits in a u64.
    const LARGEST_U64_PRIME: u64 = 18_446_744_073_709_551_557;

    #[test]
    fn computes_the_worked_example() {
        assert_eq!(mod_pow(3, 13, 7), 3);
    }

    #[test]
    fn matches_repeated_multiplication() {
        let expected = (0..13).fold(1_u64, |product, _| product * 3 % 7);

        assert_eq!(mod_pow(3, 13, 7), expected);
    }

    #[test]
    fn handles_the_edge_cases() {
        assert_eq!(mod_pow(5, 0, 7), 1);
        assert_eq!(mod_pow(5, 3, 1), 0);
        assert_eq!(mod_pow(2, 10, 1000), 24);
    }

    #[test]
    fn satisfies_fermats_little_theorem() {
        // For a prime p and any a not divisible by p: a^(p-1) mod p == 1.
        assert_eq!(mod_pow(123_456_789, 1_000_000_006, 1_000_000_007), 1);
    }

    #[test]
    fn does_not_overflow_near_the_top_of_u64() {
        assert_eq!(
            mod_mul(LARGEST_U64_PRIME - 1, LARGEST_U64_PRIME - 1, LARGEST_U64_PRIME),
            1
        );
        assert_eq!(mod_pow(2, LARGEST_U64_PRIME - 1, LARGEST_U64_PRIME), 1);
    }
}