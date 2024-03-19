use num_bigint::{BigUint, RandBigInt,ToBigUint};
use rand::thread_rng;
use rand::Rng;
use num_prime::{PrimalityTestConfig, RandPrime};
use num_traits::{One, Zero};

fn generate_prime(bitsize:usize) -> BigUint{
    let mut rng=thread_rng();
    let config = PrimalityTestConfig::default();
    rng.gen_prime(bitsize, Some(config))
}

fn gen_rand(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_range(&BigUint::one(), n)
}

fn carmicle_function(p:BigUint,q:BigUint) -> BigUint{
    (p-1u32)*(q-1u32)
}

fn send_encrypted_message(message: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    message.modpow(e, n)
}

fn send_random_square(n: &BigUint) -> BigUint {
    let x = gen_rand(n);
    x.modpow(&BigUint::from(2u32), n)
}

fn find_square_root(x_squared: &BigUint, private_key: &(BigUint, BigUint)) -> BigUint {
    let decrypted_roots = crate::rabin::decrypt(x_squared, private_key);
    let mut rng = rand::thread_rng();
    let i: usize = rng.gen_range(0..decrypted_roots.len()); // Use decrypted_roots.len() for safety, assuming it's always 4
    decrypted_roots[i].clone()
}

