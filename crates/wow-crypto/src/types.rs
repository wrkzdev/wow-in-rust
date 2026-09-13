//! The fixed-size POD types from `src/crypto/crypto.h`.
//!
//! Sizes are asserted at compile time, matching the `static_assert` block in
//! `crypto.h` and the table in `specs/02-crypto.md` §2.1.
//!
//! These are deliberately transparent byte arrays: on the wire and in the
//! blockchain database they are raw bytes with no framing
//! (`specs/04-serialization.md` §1.2), and validation must be as permissive as
//! the C. A `PublicKey` is *not* proof that the bytes decode to a curve point —
//! use [`crate::ops::check_key`] for that, exactly where the C does.

use core::fmt;

/// A 32-byte Keccak hash. `crypto::hash`.
pub type Hash256 = [u8; 32];

/// The 8-byte encrypted payment id. `crypto::hash8`.
pub type Hash8 = [u8; 8];

macro_rules! byte_array_type {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;
            pub const ZERO: $name = $name([0u8; $len]);

            #[inline]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            #[inline]
            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }

            /// Parse from a slice. Returns `None` on a length mismatch rather
            /// than panicking — every parser in this workspace treats a bad
            /// length as a validation failure (`specs/04` §1.6).
            pub fn from_slice(s: &[u8]) -> Option<Self> {
                let a: [u8; $len] = s.try_into().ok()?;
                Some($name(a))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(a: [u8; $len]) -> Self {
                $name(a)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::ZERO
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), crate::hex::encode(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&crate::hex::encode(&self.0))
            }
        }
    };
}

byte_array_type!(
    PublicKey,
    32,
    "A compressed ed25519 point. `crypto::public_key`.\n\nThe bytes are *not* validated on construction, matching `ge_frombytes_vartime`'s permissiveness (`specs/02` §2, item 1)."
);
byte_array_type!(
    SecretKey,
    32,
    "A little-endian scalar, expected to be canonical (`< l`). `crypto::secret_key`.\n\nCanonicality is checked where the C checks it, not on construction."
);
byte_array_type!(
    KeyDerivation,
    32,
    "A compressed point, `8 * a * R`. `crypto::key_derivation`."
);
byte_array_type!(KeyImage, 32, "A compressed point. `crypto::key_image`.");
byte_array_type!(
    EcPoint,
    32,
    "An uninterpreted compressed point. `crypto::ec_point`."
);
byte_array_type!(
    EcScalar,
    32,
    "An uninterpreted scalar. `crypto::ec_scalar`."
);

/// A Schnorr signature `(c, r)`, 64 bytes on the wire: `c` then `r`.
///
/// `specs/02-crypto.md` §3.9. Used for message signing, tx proofs, reserve
/// proofs, ring signatures, and the HF 18 block-header miner signature.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Signature {
    pub c: EcScalar,
    pub r: EcScalar,
}

impl Signature {
    pub const LEN: usize = 64;
    pub const ZERO: Signature = Signature {
        c: EcScalar::ZERO,
        r: EcScalar::ZERO,
    };

    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.c.0);
        out[32..].copy_from_slice(&self.r.0);
        out
    }

    pub fn from_bytes(b: &[u8; 64]) -> Signature {
        Signature {
            c: EcScalar(b[..32].try_into().unwrap()),
            r: EcScalar(b[32..].try_into().unwrap()),
        }
    }

    pub fn from_slice(s: &[u8]) -> Option<Signature> {
        let a: [u8; 64] = s.try_into().ok()?;
        Some(Signature::from_bytes(&a))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", crate::hex::encode(&self.to_bytes()))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hex::encode(&self.to_bytes()))
    }
}

/// A one-byte view tag (HF 20+). `crypto::view_tag`.
///
/// `specs/02-crypto.md` §3.7: this is the **first** byte of the hash, and it is
/// exactly one byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ViewTag(pub u8);

/// A public address: the spend and view keys, in that order.
///
/// `specs/05-blocks-and-transactions.md` §6. Serialized as the two keys
/// back-to-back, 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AccountPublicAddress {
    pub spend_public_key: PublicKey,
    pub view_public_key: PublicKey,
}

impl AccountPublicAddress {
    pub const LEN: usize = 64;

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.spend_public_key.0);
        out[32..].copy_from_slice(&self.view_public_key.0);
        out
    }

    pub fn from_bytes(b: &[u8; 64]) -> Self {
        AccountPublicAddress {
            spend_public_key: PublicKey(b[..32].try_into().unwrap()),
            view_public_key: PublicKey(b[32..].try_into().unwrap()),
        }
    }
}

/// A subaddress index `(major, minor)`. `(0, 0)` is the main address.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
pub struct SubaddressIndex {
    pub major: u32,
    pub minor: u32,
}

impl SubaddressIndex {
    pub const MAIN: SubaddressIndex = SubaddressIndex { major: 0, minor: 0 };

    pub const fn new(major: u32, minor: u32) -> Self {
        SubaddressIndex { major, minor }
    }

    pub const fn is_main(&self) -> bool {
        self.major == 0 && self.minor == 0
    }
}

const _: () = {
    assert!(core::mem::size_of::<PublicKey>() == 32);
    assert!(core::mem::size_of::<SecretKey>() == 32);
    assert!(core::mem::size_of::<KeyDerivation>() == 32);
    assert!(core::mem::size_of::<KeyImage>() == 32);
    assert!(core::mem::size_of::<Signature>() == 64);
    assert!(core::mem::size_of::<ViewTag>() == 1);
};
