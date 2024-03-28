use crate::crypto::error::CryptoError;
use anyhow::Result;
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use getset::Getters;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn hash(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DST)
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pubkey: G1Affine,
}

impl PublicKey {
    pub fn aggregate(pubkeys: Vec<&Self>) -> anyhow::Result<PublicKey> {
        let aggregate = pubkeys
            .into_iter()
            .fold(G1Projective::identity(), |mut acc, pk| {
                acc += pk.pubkey;
                acc
            });

        Ok(PublicKey {
            pubkey: aggregate.into(),
        })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(self.pubkey.to_compressed().as_slice()),
        )
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // In order to preserve the Serde data model and help analysis tools,
        // make sure to wrap our value in a container with the same name
        // as the original type.
        #[derive(Deserialize, Debug)]
        #[serde(rename = "PublicKey")]
        struct Value<'a>(&'a [u8]);

        let value = Value::deserialize(deserializer)?;
        PublicKey::try_from(value.0)
            .map_err(|s| <D::Error as Error>::custom(format!("{} with {}", s, "PublicKey")))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            pubkey: G1Affine::from_compressed(<&[u8; 48]>::try_from(bytes).unwrap()).unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: G2Affine,
}

impl Signature {
    pub fn verify(&self, msg: &[u8], pubkey: &PublicKey) -> Result<(), CryptoError> {
        let msg: G2Projective = hash(msg);

        let g1 = G1Affine::generator();
        let lhs = pairing(&g1, &self.sig);
        let rhs = pairing(&pubkey.pubkey, &msg.into());

        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "Signature",
            serde_bytes::Bytes::new(self.sig.to_compressed().as_slice()),
        )
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // In order to preserve the Serde data model and help analysis tools,
        // make sure to wrap our value in a container with the same name
        // as the original type.
        #[derive(Deserialize, Debug)]
        #[serde(rename = "Signature")]
        struct Value<'a>(&'a [u8]);

        let value = Value::deserialize(deserializer)?;
        Signature::try_from(value.0)
            .map_err(|s| <D::Error as Error>::custom(format!("{} with {}", s, "Signature")))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = CryptoError;

    /// Deserializes a Signature from a sequence of bytes.
    ///
    /// WARNING: Does NOT subgroup-check the signature! Instead, this will be done implicitly when
    /// verifying the signature.
    fn try_from(bytes: &[u8]) -> std::result::Result<Signature, Self::Error> {
        Ok(Self {
            sig: G2Affine::from_compressed(<&[u8; 96]>::try_from(bytes).unwrap()).unwrap(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct BitVec {
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl BitVec {
    /// Number of buckets require for num_bits.
    pub fn required_buckets(num_bits: u16) -> usize {
        num_bits
            .checked_sub(1)
            .map_or(0, |pos| pos as usize / BUCKET_SIZE + 1)
    }

    /// Checks if the bit at position @pos is set.
    #[inline]
    pub fn is_set(&self, pos: u16) -> bool {
        // This is optimised to: let bucket = pos >> 3;
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            return false;
        }
        // This is optimized to: let bucket_pos = pos | 0x07;
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        (self.inner[bucket] & (0b1000_0000 >> bucket_pos as u8)) != 0
    }

    /// Return the number of buckets.
    pub fn num_buckets(&self) -> usize {
        self.inner.len()
    }

    /// Return an `Iterator` over all '1' bit indexes.
    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.inner.len() * BUCKET_SIZE).filter(move |idx| self.is_set(*idx as u16))
    }

    /// Returns the index of the last set bit.
    pub fn last_set_bit(&self) -> Option<u16> {
        self.inner
            .iter()
            .rev()
            .enumerate()
            .find(|(_, byte)| byte != &&0u8)
            .map(|(i, byte)| {
                (8 * (self.inner.len() - i) - byte.trailing_zeros() as usize - 1) as u16
            })
    }
}

impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "BitVec")]
        struct RawData {
            #[serde(with = "serde_bytes")]
            inner: Vec<u8>,
        }
        let v = RawData::deserialize(deserializer)?.inner;
        // Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
        // https://github.com/aptos-labs/aptos-core/blob/main/crates/aptos-bitvec/src/lib.rs#L19
        if v.len() > 8192 {
            return Err(D::Error::custom(format!("BitVec too long: {}", v.len())));
        }
        Ok(BitVec { inner: v })
    }
}

// Example structure for an aggregate signature.
#[derive(Debug, PartialEq, Eq, Getters, Serialize, Deserialize)]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    #[getset(get = "pub")]
    sig: Option<Signature>,
}

impl AggregateSignature {
    pub fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }
}
