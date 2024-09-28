// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub mod error;
pub mod hash;

use std::fmt;
use std::iter::Sum;
use std::ops::{Add, Div, Mul, Sub};
use uint::construct_uint;

/// Size in bytes of a U256.
pub const U256_BYTES_LENGTH: usize = 32;

construct_uint! {
    pub struct U256(4);
}

impl U256 {
    /// Calculate the greatest common divisor of two U256 numbers.
    ///
    /// # Arguments
    ///
    /// * `other` - The other U256 number.
    ///
    /// # Returns
    ///
    /// The greatest common divisor of the two U256 numbers.
    fn gcd(&self, other: &Self) -> Self {
        let mut a = *self;
        let mut b = *other;
        while b != U256::zero() {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }
}

/// Basic data structure representing a rational number.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Rational {
    pub numerator: U256,
    pub denominator: U256,
}

impl Rational {
    /// Create a new `Rational` by dividing the numerator and
    /// denominator by their greatest common divisor.
    ///
    /// # Returns
    ///
    /// A new `Rational`.
    fn simplify(self) -> Self {
        let gcd = self.numerator.gcd(&self.denominator);
        Rational {
            numerator: self.numerator / gcd,
            denominator: self.denominator / gcd,
        }
    }

    /// Calculate the ceiling of the rational number.
    ///
    /// # Returns
    ///
    /// The ceiling of the rational number.
    pub fn ceil(self) -> U256 {
        let (quotient, remainder) = self.numerator.div_mod(self.denominator);
        if remainder == U256::zero() {
            quotient
        } else {
            quotient + U256::one()
        }
    }

    /// Calculate the floor of the rational number.
    ///
    /// # Returns
    ///
    /// The floor of the rational number.
    pub fn floor(self) -> U256 {
        let (quotient, _) = self.numerator.div_mod(self.denominator);
        quotient
    }
}

impl Div for Rational {
    type Output = Rational;

    fn div(self, rhs: Self) -> Self::Output {
        assert_ne!(
            rhs.numerator,
            U256::zero(),
            "Tried to divide a rational by zero"
        );

        Rational {
            numerator: self.numerator * rhs.denominator,
            denominator: self.denominator * rhs.numerator,
        }
        .simplify()
    }
}

impl Mul for Rational {
    type Output = Rational;

    fn mul(self, rhs: Self) -> Self::Output {
        Rational {
            numerator: self.numerator * rhs.numerator,
            denominator: self.denominator * rhs.denominator,
        }
        .simplify()
    }
}
impl Add for Rational {
    type Output = Rational;

    fn add(self, rhs: Self) -> Self::Output {
        Rational {
            numerator: self.numerator * rhs.denominator + rhs.numerator * self.denominator,
            denominator: self.denominator * rhs.denominator,
        }
        .simplify()
    }
}

impl Sub for Rational {
    type Output = Rational;

    fn sub(self, rhs: Self) -> Self::Output {
        Rational {
            numerator: self.numerator * rhs.denominator - rhs.numerator * self.denominator,
            denominator: self.denominator * rhs.denominator,
        }
        .simplify()
    }
}

impl Sum for Rational {
    fn sum<I: Iterator<Item = Rational>>(iter: I) -> Self {
        iter.fold(Rational::default(), |acc, x| acc + x)
    }
}

impl From<U256> for Rational {
    fn from(value: U256) -> Self {
        Rational {
            numerator: value,
            denominator: U256::one(),
        }
    }
}

impl From<u64> for Rational {
    fn from(value: u64) -> Self {
        Rational {
            numerator: U256::from(value),
            denominator: U256::one(),
        }
    }
}

impl fmt::Display for Rational {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Check if denominator is 1 (for whole numbers)
        if self.denominator == U256::from(1) {
            write!(f, "{}", self.numerator)
        } else {
            write!(f, "{}/{}", self.numerator, self.denominator)
        }
    }
}

impl Default for Rational {
    fn default() -> Self {
        Rational {
            numerator: U256::zero(),
            denominator: U256::one(),
        }
    }
}
