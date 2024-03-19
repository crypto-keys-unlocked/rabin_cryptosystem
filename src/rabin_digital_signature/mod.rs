use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng}; 

/// Generates a Rabin digital signature for a given message using the private key.
/// 
/// # Arguments
/// * `message` - The message to be signed, as a `BigUint`.
/// * `private_key` - The private key `(p, q)` used for signing, where `p` and `q` are prime numbers.
/// 
/// # Returns
/// A tuple containing the signature and a random value used during the signing process.
pub fn sign(message: &BigUint, private_key: &(BigUint, BigUint)) -> (BigUint, Vec<u8>) {
    let (p, q) = private_key;
    let n = p * q;
    let mut rng = OsRng;
    let mut u;

    loop {
        u = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let mut hasher = Sha256::new();
        hasher.update(&message.to_bytes_be());
        hasher.update(&u);
        let hash = hasher.finalize();
        let c = BigUint::from_bytes_be(&hash.as_slice());

        if &c < &n {
            let decrypted_messages = crate::rabin::decrypt(&c, private_key);
            let r1 = decrypted_messages[0].clone();

            if crate::rabin::encrypt(&r1, &n) == c {
                return (r1, u);
            }
        }
    }
}

/// Verifies a Rabin digital signature.
/// 
/// # Arguments
/// * `message` - The original message that was signed, as a `BigUint`.
/// * `signature` - The signature `(r, u)` to be verified, where `r` is the signature and `u` is the random value used during signing.
/// * `public_key` - The public key `n` used for verification.
/// 
/// # Returns
/// `true` if the signature is valid; otherwise, `false`.
pub fn verify(message: &BigUint, signature: &(BigUint, Vec<u8>), public_key: &BigUint) -> bool {
    let (r, u) = signature;
    let mut hasher = Sha256::new();
    hasher.update(&message.to_bytes_be());
    hasher.update(u);
    let hash = hasher.finalize();
    let c = BigUint::from_bytes_be(&hash.as_slice());

    crate::rabin::encrypt(r, public_key) == c
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    /// Tests the Rabin digital signature functionality by signing and then verifying a message.
    #[test]
    fn test_rabin_signature() {
        let bit_size = 256;
        let (private_key, public_key) = crate::rabin::generate_keys(bit_size);
        let message = 12345678.to_biguint().unwrap();

        let (signature, u) = sign(&message, &private_key);
        assert!(verify(&message, &(signature, u), &public_key), "Signature verification failed");
    }
}
