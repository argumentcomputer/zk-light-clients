//! A simple program to be proven inside the zkVM.

#![no_main]
zkvm::entrypoint!(main);

pub fn main() {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    let n = zkvm::io::read::<u32>();

    let mut a: u128 = 0;
    let mut b: u128 = 1;
    let mut sum: u128;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    zkvm::io::write(&a);
    zkvm::io::write(&b);
}
