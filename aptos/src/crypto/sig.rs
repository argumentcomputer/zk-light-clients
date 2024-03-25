// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::error::CryptoError;
use anyhow::format_err;
use blst::BLST_ERROR;
use getset::Getters;
use proptest::arbitrary::{any, Arbitrary};
use proptest::prelude::BoxedStrategy;
use proptest::strategy::Strategy;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use test_strategy::Arbitrary;

// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;

pub const DST_BLS_SIG_IN_G2_WITH_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Default, Debug, Clone, PartialEq, Eq, Copy)]
pub struct PublicKey {
    pub(crate) pubkey: blst::min_pk::PublicKey,
}

// for testing
impl Arbitrary for PublicKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let ikm = any::<[u8; 32]>();
        ikm.prop_map(|ikm| PublicKey {
            pubkey: blst::min_pk::SecretKey::key_gen_v3(&ikm[..], b"aptos test")
                .unwrap()
                .sk_to_pk(),
        })
        .boxed()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(self.pubkey.to_bytes().as_slice()),
        )
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            pubkey: blst::min_pk::PublicKey::from_bytes(bytes)
                .map_err(|_| Self::Error::PublicKeyDeserializationError)?,
        })
    }
}

impl PublicKey {
    /// Aggregates the public keys of several signers into an aggregate public key, which can be later
    /// used to verify a multisig aggregated from those signers.
    ///
    /// WARNING: This function assumes all public keys have had their proofs-of-possession verified
    /// and have thus been group-checked.
    pub fn aggregate(pubkeys: Vec<&Self>) -> anyhow::Result<PublicKey> {
        let blst_pubkeys: Vec<_> = pubkeys.iter().map(|pk| &pk.pubkey).collect();

        // CRYPTONOTE(Alin): We assume the PKs have had their PoPs verified and thus have also been subgroup-checked
        let aggpk = blst::min_pk::AggregatePublicKey::aggregate(&blst_pubkeys[..], false)
            .map_err(|e| format_err!("{:?}", e))?;

        Ok(PublicKey {
            pubkey: aggpk.to_public_key(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: blst::min_pk::Signature,
}

impl Signature {
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> anyhow::Result<()> {
        let result = self.sig.verify(
            true,
            message,
            DST_BLS_SIG_IN_G2_WITH_POP,
            &[],
            &public_key.pubkey,
            false,
        );
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(format_err!("{:?}", result))
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "Signature",
            serde_bytes::Bytes::new(self.sig.to_bytes().as_slice()),
        )
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
            sig: blst::min_pk::Signature::from_bytes(bytes)
                .map_err(|_| Self::Error::SignatureDeserializationError)?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Arbitrary)]
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

impl Arbitrary for Signature {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let ikm = any::<[u8; 32]>();
        ikm.prop_map(|ikm| {
            let sk = blst::min_pk::SecretKey::key_gen_v3(&ikm[..], b"aptos test").unwrap();
            let sig = sk.sign(b"test msg", DST_BLS_SIG_IN_G2_WITH_POP, &[]);
            Signature { sig }
        })
        .boxed()
    }
}

#[derive(Debug, PartialEq, Eq, Getters, Serialize, Deserialize, Arbitrary)]
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
