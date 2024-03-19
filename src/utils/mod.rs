use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};

/// Computes the modular inverse of `a` modulo `m` using a brute-force approach.
/// 
/// # Arguments
/// 
/// * `a` - The number to find the inverse for, as a `BigUint`.
/// * `m` - The modulus, as a `BigUint`.
/// 
/// # Returns
/// 
/// An `Option<BigUint>` representing the modular inverse of `a` modulo `m` if it exists.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut x = BigUint::one();

    while &x < m {
        if (a * &x) % m == BigUint::one() {
            return Some(x);
        }
        x += 1u32;
    }

    None 
}

/// Extended Euclidean algorithm for computing the greatest common divisor (gcd) and Bezout coefficients.
/// 
/// # Arguments
/// 
/// * `a` - The first integer.
/// * `b` - The second integer.
/// 
/// # Returns
/// 
/// A tuple `(g, x, y)` representing the gcd of `a` and `b` (`g`), and the Bezout coefficients `x` and `y`.
pub fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b, Zero::zero(), One::one())
    } else {
        let (g, x, y) = egcd(b.clone() % a.clone(), a.clone());
        (g, y - (b / a.clone()) * x.clone(), x)
    }
}

/// Computes the modular multiplicative inverse of `a` modulo `m`.
/// 
/// # Arguments
/// 
/// * `a` - The number to find the inverse for, as a `BigUint`.
/// * `m` - The modulus, as a `BigUint`.
/// 
/// # Returns
/// 
/// An `Option<BigUint>` representing the modular multiplicative inverse of `a` modulo `m` if it exists.
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (g, x, _) = egcd(a.to_bigint().unwrap(), m.to_bigint().unwrap());
    if g == One::one() {
        let x_mod_m = ((x % m.to_bigint().unwrap()) + m.to_bigint().unwrap()) % m.to_bigint().unwrap();
        
        Some(x_mod_m.to_biguint().unwrap())
    } else {
        None
    }
}
