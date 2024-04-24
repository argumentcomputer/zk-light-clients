use crate::crypto::error::CryptoError;
use crate::types::error::TypesError;
use crate::types::utils::{read_leb128, write_leb128};
use anyhow::Result;
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const PUB_KEY_LEN: usize = 48;
pub const SIG_LEN: usize = 96;

#[must_use]
pub fn hash(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DST)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    compressed_pubkey: [u8; PUB_KEY_LEN],
    pubkey: Option<G1Affine>,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey: None,
        }
    }
}

impl PublicKey {
    fn pubkey(&mut self) -> G1Affine {
        self.pubkey.unwrap_or_else(|| {
            let pubkey = G1Affine::from_compressed(&self.compressed_pubkey).unwrap();
            self.pubkey = Some(pubkey);
            pubkey
        })
    }

    pub fn aggregate(pubkeys: Vec<&mut Self>) -> Result<PublicKey> {
        fn aggregate_step(mut acc: G1Projective, pk: &mut PublicKey) -> G1Projective {
            acc += pk.pubkey();
            acc
        }

        let aggregate = pubkeys
            .into_iter()
            .fold(G1Projective::identity(), aggregate_step);

        Ok(PublicKey {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey: Some(aggregate.into()),
        })
    }

    // TODO what if the compressed pubkey is not a real one?
    // Should be alright as we get all pubkeys from external source, apart from agg one (but we don't need it as bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        let pub_key_bytes = self.compressed_pubkey.to_vec();

        bytes.put_slice(&write_leb128(pub_key_bytes.len() as u64));
        bytes.put_slice(&pub_key_bytes);
        bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != PUB_KEY_LEN {
            return Err(TypesError::DeserializationError {
                structure: String::from("PublicKey"),
                source: "Invalid public key byte length".into(),
            });
        }

        let bytes_fixed = <&[u8; PUB_KEY_LEN]>::try_from(bytes).map_err(|e| {
            TypesError::DeserializationError {
                structure: String::from("PublicKey"),
                source: e.into(),
            }
        })?;

        Ok(Self {
            compressed_pubkey: *bytes_fixed,
            pubkey: None,
        })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(&self.compressed_pubkey),
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
            compressed_pubkey: <[u8; PUB_KEY_LEN]>::try_from(bytes).unwrap(),
            pubkey: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: G2Affine,
}

impl Signature {
    pub fn verify(&self, msg: &[u8], pubkey: &mut PublicKey) -> Result<(), CryptoError> {
        let msg: G2Projective = hash(msg);

        let g1 = G1Affine::generator();

        let lhs = pairing(&g1, &self.sig);
        let rhs = pairing(&pubkey.pubkey(), &msg.into());

        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        let sig_bytes = self.sig.to_compressed().to_vec();

        bytes.put_slice(&write_leb128(sig_bytes.len() as u64));
        bytes.put_slice(&sig_bytes);
        bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        println!("cycle-tracker-start: sig_from_bytes");
        if bytes.len() != SIG_LEN {
            return Err(TypesError::DeserializationError {
                structure: String::from("Signature"),
                source: "Invalid signature byte length".into(),
            });
        }

        let bytes_fixed =
            <&[u8; SIG_LEN]>::try_from(bytes).map_err(|e| TypesError::DeserializationError {
                structure: String::from("PublicKey"),
                source: e.into(),
            })?;

        let decompressed = G2Affine::from_compressed(bytes_fixed);

        if decompressed.is_none().into() {
            return Err(TypesError::DeserializationError {
                structure: String::from("PublicKey"),
                source: "G2Affine::from_compressed returned None".into(),
            });
        }
        println!("cycle-tracker-end: sig_from_bytes");

        Ok(Self {
            sig: decompressed.unwrap(),
        })
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
            sig: G2Affine::from_compressed(<&[u8; SIG_LEN]>::try_from(bytes).unwrap()).unwrap(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();

        bytes.put_u8(self.inner.len() as u8);
        bytes.put_slice(&self.inner);
        bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> BitVec {
        Self {
            inner: bytes.to_vec(),
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize, Deserialize)]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    #[getset(get = "pub")]
    sig: Option<Signature>,
}

impl AggregateSignature {
    pub const fn get_signers_bitvec(&self) -> &BitVec {
        &self.validator_bitmask
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.validator_bitmask.to_bytes());
        if let Some(sig) = &self.sig {
            bytes.put_u8(1); // Indicate that there is a signature
            bytes.put_slice(&sig.to_bytes());
        } else {
            bytes.put_u8(0); // Indicate that there is no signature
        }
        bytes.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let bitvec_len = bytes.get_u8() as usize;

        println!("cycle-tracker-start: bitvec_from_bytes");
        let validator_bitmask =
            BitVec::from_bytes(bytes.chunk().get(..bitvec_len).ok_or_else(|| {
                TypesError::DeserializationError {
                    structure: String::from("AggregateSignature"),
                    source: "Not enough data for BitVec".into(),
                }
            })?);
        println!("cycle-tracker-end: bitvec_from_bytes");

        bytes.advance(bitvec_len);

        let sig = match bytes.get_u8() {
            1 => {
                let (slice_len, bytes_read) =
                    read_leb128(bytes).map_err(|e| TypesError::DeserializationError {
                        structure: String::from("AggregateSignature"),
                        source: format!("Failed to read length of public_key: {e}").into(),
                    })?;
                bytes.advance(bytes_read);

                Some(Signature::from_bytes(
                    bytes.chunk().get(..slice_len as usize).ok_or_else(|| {
                        TypesError::DeserializationError {
                            structure: String::from("AggregateSignature"),
                            source: "Not enough data for Signature".into(),
                        }
                    })?,
                )?)
            }
            _ => None,
        };

        Ok(Self {
            validator_bitmask,
            sig,
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::sig::AggregateSignature;
        use crate::types::ledger_info::{AGG_SIGNATURE_LEN, OFFSET_SIGNATURE};
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let latest_li = aptos_wrapper.get_latest_li().unwrap();
        let agg_sig = latest_li.signatures();

        let bytes = bcs::to_bytes(&agg_sig).unwrap();
        let signature_bytes = &aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .skip(OFFSET_SIGNATURE)
            .take(AGG_SIGNATURE_LEN)
            .copied()
            .collect::<Vec<u8>>();
        assert_eq!(&bytes, signature_bytes);

        let intern_agg_sig = AggregateSignature::from_bytes(&bytes).unwrap();
        let intern_bytes = intern_agg_sig.to_bytes();

        assert_eq!(bytes, intern_bytes);
    }
}
