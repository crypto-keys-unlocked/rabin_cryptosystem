use crate::utils::egcd;
use num_bigint::{BigUint,ToBigInt};
use num_prime::{PrimalityTestConfig, RandPrime};
use rand::thread_rng;

/// Generates a pair of keys for the Rabin cryptosystem.
/// The generated private key (`p`, `q`) and public key `n` satisfy the condition `p ≡ q ≡ 3 (mod 4)`.
/// 
/// # Arguments
/// * `bit_size` - The size of the prime numbers to generate.
/// 
/// # Returns
/// A tuple containing the private key (a tuple of two `BigUint` primes) and the public key (`BigUint`).
pub fn generate_keys(bit_size: usize) -> ((BigUint, BigUint), BigUint) {
    let mut rng = thread_rng();
    let config = PrimalityTestConfig::default();
    let mut p = rng.gen_prime(bit_size, Some(config));
    let mut q = rng.gen_prime(bit_size, Some(config));
    let three = BigUint::from(3u32);
    let four = BigUint::from(4u32);

    while &p % &four != three {
        p = rng.gen_prime(bit_size, Some(config));
    }
    while &q % &four != three || p == q {
        q = rng.gen_prime(bit_size, Some(config));
    }

    let n = &p * &q;
    ((p, q), n)
}

/// Encrypts a message using the Rabin cryptosystem.
/// 
/// # Arguments
/// * `message` - The message to encrypt as a `BigUint`.
/// * `n` - The public key as a `BigUint`.
/// 
/// # Returns
/// The encrypted message as a `BigUint`.
pub fn encrypt(message: &BigUint, n: &BigUint) -> BigUint {
    message.modpow(&BigUint::from(2u32), n)
}

/// Decrypts a ciphertext using the Rabin cryptosystem.
/// 
/// # Arguments
/// * `ciphertext` - The ciphertext to decrypt as a `BigUint`.
/// * `private_key` - The private key as a tuple of two `BigUint` primes.
/// 
/// # Returns
/// A vector of four `BigUint` values, each a possible decryption of the ciphertext.
pub fn decrypt(ciphertext: &BigUint, private_key: &(BigUint, BigUint)) -> Vec<BigUint> {
    let (p, q) = private_key;
    let n = p * q;
    let p_bigint = p.to_bigint().unwrap();
    let q_bigint = q.to_bigint().unwrap();
    let c_bigint = ciphertext.to_bigint().unwrap();
    let mp = c_bigint.modpow(&((p_bigint.clone() + 1) >> 2), &p_bigint);
    let mq = c_bigint.modpow(&((q_bigint.clone() + 1) >> 2), &q_bigint);
    let (_, yp, yq) = egcd(p_bigint.clone(), q_bigint.clone());
    let n_bigint = n.to_bigint().unwrap();
    let yp_norm = (yp + &n_bigint) % &n_bigint;
    let yq_norm = (yq + &n_bigint) % &n_bigint;
    let yp = yp_norm.to_biguint().unwrap();
    let yq = yq_norm.to_biguint().unwrap();
    let mp = mp.to_biguint().unwrap();
    let mq = mq.to_biguint().unwrap();
    let r1 = (&yp * p * &mq + &yq * q * &mp) % &n;
    let r2 = (&n - &r1) % &n;
    let r3_bigint = (&yp.to_bigint().unwrap() * p_bigint * mq.to_bigint().unwrap() - &yq.to_bigint().unwrap() * q_bigint * mp.to_bigint().unwrap()) % &n_bigint;
    let r3 = ((r3_bigint + &n_bigint) % &n_bigint).to_biguint().unwrap();
    let r4 = (&n - &r3) % &n;

    vec![r1, r2, r3, r4]
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;
    
    /// Tests the Rabin cryptosystem by generating keys, encrypting a message, and then decrypting it
    /// to verify that the original message is recovered.
    #[test]
    fn test_rabin_cryptosystem() {
        let bit_size = 256;
        let (private_key, public_key) = generate_keys(bit_size);
        let message: BigUint = 12345678.to_biguint().unwrap();
        let ciphertext = encrypt(&message, &public_key);
        let decrypted_messages = decrypt(&ciphertext, &private_key);
        let original_message_len = message.to_bytes_be().len();
        let decrypted_message = select_correct_plaintext(&decrypted_messages, original_message_len)
            .expect("Failed to select the correct plaintext");
        
        assert_eq!(decrypted_message, message, "Decryption failed to recover the original message");
    }
    
    /// Selects the correct plaintext from the decrypted messages based on the original message length.
    fn select_correct_plaintext(decrypted_messages: &[BigUint], original_message_len: usize) -> Option<BigUint> {
        decrypted_messages
            .iter()
            .find(|&m| m.to_bytes_be().len() == original_message_len)
            .cloned()
    }
}
