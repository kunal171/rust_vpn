//! Modular arithmetic on `u64`, the number system behind Diffie-Hellman.
//!
//! This is a learning implementation. It is not constant-time, so it must
//! never handle real secrets: use an audited crate for that.

/// Returns `(a * b) mod modulus` without overflowing.
///
/// Panics if `modulus` is zero.
pub fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
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

/// Returns the number that multiplies with `value` to give 1 mod `prime`.
///
/// Returns `None` when `value` is a multiple of `prime`, because zero has no
/// inverse. `prime` must be prime; the result is meaningless otherwise.
pub fn mod_inverse(value: u64, prime: u64) -> Option<u64> {
    if value.is_multiple_of(prime) {
        return None;
    }

    // Fermat's little theorem: value^(prime-1) == 1, so value^(prime-2) is
    // the number that, multiplied by value once more, gives 1.
    Some(mod_pow(value, prime - 2, prime))
}

/// Returns the smallest `k >= 1` with `element^k == 1 mod prime`.
///
/// Returns `None` when no such power exists, as for zero. This tries every
/// power in turn, so it is only usable with small moduli.
pub fn multiplicative_order(element: u64, prime: u64) -> Option<u64> {
    let element = element % prime;
    let mut power = element;

    for order in 1..prime {
        if power == 1 {
            return Some(order);
        }
        power = mod_mul(power, element, prime);
    }

    None
}

/// Returns true when the powers of `element` reach every value from 1 to `prime - 1`.
pub fn is_generator(element: u64, prime: u64) -> bool {
    multiplicative_order(element, prime) == Some(prime - 1)
}

#[cfg(test)]
mod tests {
    use super::{is_generator, mod_inverse, mod_mul, mod_pow, multiplicative_order};

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
            mod_mul(
                LARGEST_U64_PRIME - 1,
                LARGEST_U64_PRIME - 1,
                LARGEST_U64_PRIME
            ),
            1
        );
        assert_eq!(mod_pow(2, LARGEST_U64_PRIME - 1, LARGEST_U64_PRIME), 1);
    }

    #[test]
    fn finds_the_inverse_in_the_worked_example() {
        // 3 * 5 = 15, and 15 mod 7 = 1.
        assert_eq!(mod_inverse(3, 7), Some(5));
    }

    #[test]
    fn every_nonzero_value_has_an_inverse_mod_a_prime() {
        let prime = 101;

        for value in 1..prime {
            let inverse = mod_inverse(value, prime).unwrap();
            assert_eq!(mod_mul(value, inverse, prime), 1);
        }
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(mod_inverse(0, 7), None);
        assert_eq!(mod_inverse(14, 7), None);
    }

    #[test]
    fn a_composite_modulus_is_not_a_field() {
        // Mod 6, nothing multiplied by 2 gives 1, so 2 cannot be divided by.
        assert!((1..6).all(|candidate| mod_mul(2, candidate, 6) != 1));
        // Worse, two nonzero values multiply to zero.
        assert_eq!(mod_mul(2, 3, 6), 0);
    }

    #[test]
    fn computes_orders_mod_7() {
        assert_eq!(multiplicative_order(1, 7), Some(1));
        assert_eq!(multiplicative_order(6, 7), Some(2));
        assert_eq!(multiplicative_order(2, 7), Some(3));
        assert_eq!(multiplicative_order(3, 7), Some(6));
        assert_eq!(multiplicative_order(0, 7), None);
    }

    #[test]
    fn identifies_generators_mod_7() {
        let generators: Vec<u64> = (1..7).filter(|&element| is_generator(element, 7)).collect();

        assert_eq!(generators, vec![3, 5]);
    }

    #[test]
    fn every_order_divides_the_group_size() {
        let prime = 101;

        for element in 1..prime {
            let order = multiplicative_order(element, prime).unwrap();
            assert_eq!((prime - 1) % order, 0);
        }
    }
}
