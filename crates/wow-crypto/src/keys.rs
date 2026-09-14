//! Key derivation, view tags and subaddresses.
//!
//! `specs/02-crypto.md` §3. Every buffer layout here is byte-exact: the C
//! builds packed structs and hashes `end - begin` bytes, so an extra pad byte
//! or a missing NUL changes every derived key.

use curve25519_dalek::scalar::Scalar;
use wow_serialize::varint::{write_varint_to, MAX_VARINT_LEN_U64};

use crate::hash::cn_fast_hash;
use crate::ops::{
    decode_point, decode_scalar, encode_point, hash_to_scalar, mul8, sc_add, sc_reduce32,
    scalarmult_base,
};
use crate::types::{
    AccountPublicAddress, EcScalar, KeyDerivation, PublicKey, SecretKey, SubaddressIndex, ViewTag,
};

/// `HASH_KEY_SUBADDRESS` — `"SubAddr"` **with its trailing NUL**, 8 bytes.
///
/// `specs/01-constants.md` §10 and `specs/02` §9. The C passes
/// `sizeof("SubAddr")`, which counts the NUL.
pub const HASH_KEY_SUBADDRESS: &[u8; 8] = b"SubAddr\0";

/// The view-tag salt — `"view_tag"`, 8 bytes, **no** trailing NUL.
///
/// The C does `memcpy(buf.salt, "view_tag", 8); // leave off null terminator`.
pub const VIEW_TAG_SALT: &[u8; 8] = b"view_tag";

/// `HASH_KEY_ENCRYPTED_PAYMENT_ID`.
pub const HASH_KEY_ENCRYPTED_PAYMENT_ID: u8 = 0x8d;

/// `generate_key_derivation(P, s)` = `D = 8 * (s * P)`.
///
/// `specs/02-crypto.md` §3.3. Returns `None` when `P` does not decode, which is
/// exactly when the C returns `false`. The multiply-by-8 clears the cofactor.
///
/// The C asserts `sc_check(s)`; we require it rather than proceeding on a
/// non-canonical scalar.
pub fn generate_key_derivation(pub_key: &PublicKey, sec: &SecretKey) -> Option<KeyDerivation> {
    let s = decode_scalar(&sec.0)?;
    let p = decode_point(&pub_key.0)?;
    Some(KeyDerivation(encode_point(&mul8(&(s * p)))))
}

/// `derivation_to_scalar(D, i)` = `hash_to_scalar(D || varint(i))`.
///
/// `specs/02-crypto.md` §3.4. The buffer is **exactly** `32 + varint_len` bytes
/// — the written varint length, with no padding, even though the C's struct
/// reserves 10 bytes for it.
pub fn derivation_to_scalar(d: &KeyDerivation, output_index: u64) -> EcScalar {
    let (buf, n) = derivation_index_buf(&d.0, output_index);
    hash_to_scalar(&buf[..n])
}

/// The same, as a dalek `Scalar`.
pub fn derivation_to_scalar_dalek(d: &KeyDerivation, output_index: u64) -> Scalar {
    let (buf, n) = derivation_index_buf(&d.0, output_index);
    Scalar::from_bytes_mod_order(cn_fast_hash(&buf[..n]))
}

/// Build `derivation || varint(output_index)`, returning the buffer and the
/// **used** length. Only `buf[..n]` is hashed: the C sizes the hash as
/// `end - begin`, where `end` is where `write_varint` stopped, so the struct's
/// 10-byte reservation is not part of the input.
#[inline]
fn derivation_index_buf(d: &[u8; 32], output_index: u64) -> ([u8; 32 + MAX_VARINT_LEN_U64], usize) {
    let mut buf = [0u8; 32 + MAX_VARINT_LEN_U64];
    buf[..32].copy_from_slice(d);
    let mut v = [0u8; MAX_VARINT_LEN_U64];
    let n = write_varint_to(&mut v, output_index);
    buf[32..32 + n].copy_from_slice(&v[..n]);
    (buf, 32 + n)
}

/// Length of the `derivation || varint(i)` buffer.
#[inline]
fn derivation_index_len(output_index: u64) -> usize {
    32 + wow_serialize::varint::varint_len(output_index)
}

/// `derive_public_key(D, i, B)` = `B + derivation_to_scalar(D, i) * G`.
///
/// `specs/02-crypto.md` §3.5. `None` when `B` does not decode.
pub fn derive_public_key(
    d: &KeyDerivation,
    output_index: u64,
    base: &PublicKey,
) -> Option<PublicKey> {
    let b = decode_point(&base.0)?;
    let s = derivation_to_scalar_dalek(d, output_index);
    Some(PublicKey(encode_point(&(b + scalarmult_base(&s)))))
}

/// `derive_secret_key(D, i, b)` = `b + derivation_to_scalar(D, i)  (mod l)`.
pub fn derive_secret_key(d: &KeyDerivation, output_index: u64, base: &SecretKey) -> SecretKey {
    let s = derivation_to_scalar(d, output_index);
    SecretKey(sc_add(&base.0, &s.0))
}

/// `derive_subaddress_public_key(out_key, D, i)` = `out_key - scalar*G`.
///
/// The wallet's scanning primitive: recovers the account spend key a one-time
/// output was derived from (`specs/12-wallet-core.md` §3.2).
pub fn derive_subaddress_public_key(
    out_key: &PublicKey,
    d: &KeyDerivation,
    output_index: u64,
) -> Option<PublicKey> {
    let p = decode_point(&out_key.0)?;
    let s = derivation_to_scalar_dalek(d, output_index);
    Some(PublicKey(encode_point(&(p - scalarmult_base(&s)))))
}

/// `derive_view_tag(D, i)` — the HF 20 view tag.
///
/// `specs/02-crypto.md` §3.7:
/// ```text
/// buf      = "view_tag" || derivation || varint(output_index)
/// view_tag = cn_fast_hash(buf)[0]        // FIRST byte only, 1 byte total
/// ```
/// Note the salt is 8 bytes with **no** trailing NUL, unlike `"SubAddr\0"`.
pub fn derive_view_tag(d: &KeyDerivation, output_index: u64) -> ViewTag {
    let mut buf = [0u8; 8 + 32 + MAX_VARINT_LEN_U64];
    buf[..8].copy_from_slice(VIEW_TAG_SALT);
    buf[8..40].copy_from_slice(&d.0);
    let mut v = [0u8; MAX_VARINT_LEN_U64];
    let n = write_varint_to(&mut v, output_index);
    buf[40..40 + n].copy_from_slice(&v[..n]);
    ViewTag(cn_fast_hash(&buf[..40 + n])[0])
}

/// The deterministic view key: `a = sc_reduce32(keccak256(b))`.
///
/// `specs/02-crypto.md` §3.2. Used by the daemon miner given `--spendkey`
/// (`miner::init`) and by every deterministic wallet. `is_deterministic()` is
/// exactly this relation holding (`specs/12` §1.2).
pub fn view_key_from_spend_key(spend: &SecretKey) -> SecretKey {
    SecretKey(sc_reduce32(&cn_fast_hash(&spend.0)))
}

/// `get_subaddress_secret_key`: `m = Hs("SubAddr\0" || a || major_le || minor_le)`.
///
/// `specs/02-crypto.md` §3.8.
pub fn subaddress_secret_key(view_secret: &SecretKey, index: SubaddressIndex) -> EcScalar {
    let mut buf = [0u8; 8 + 32 + 4 + 4];
    buf[..8].copy_from_slice(HASH_KEY_SUBADDRESS);
    buf[8..40].copy_from_slice(&view_secret.0);
    buf[40..44].copy_from_slice(&index.major.to_le_bytes());
    buf[44..48].copy_from_slice(&index.minor.to_le_bytes());
    hash_to_scalar(&buf)
}

/// Derive the public subaddress at `index`.
///
/// ```text
/// m = Hs("SubAddr\0" || a || major || minor)
/// D = B + m*G          // subaddress spend public key
/// C = a * D            // subaddress view public key
/// ```
///
/// `index == (0, 0)` returns the main address **unchanged** — the C does not
/// run the derivation for it, and doing so would produce a different address.
pub fn get_subaddress(
    keys: &AccountPublicAddress,
    view_secret: &SecretKey,
    index: SubaddressIndex,
) -> Option<AccountPublicAddress> {
    if index.is_main() {
        return Some(*keys);
    }
    let m = subaddress_secret_key(view_secret, index);
    let m = Scalar::from_bytes_mod_order(m.0);
    let b = decode_point(&keys.spend_public_key.0)?;
    let d = b + scalarmult_base(&m);
    let a = decode_scalar(&view_secret.0)?;
    let c = a * d;
    Some(AccountPublicAddress {
        spend_public_key: PublicKey(encode_point(&d)),
        view_public_key: PublicKey(encode_point(&c)),
    })
}

/// Encrypt or decrypt an 8-byte payment id (the operation is its own inverse).
///
/// `specs/02-crypto.md` §8, `device_default::encrypt_payment_id`:
/// ```text
/// key = cn_fast_hash(derivation || 0x8d)
/// out[i] = pid[i] XOR key[i]     for i in 0..8
/// ```
///
/// The key is the hash, not reduced to a scalar. Reduced, its first eight
/// bytes differ for fifteen hashes in sixteen, and a C++ wallet reads another
/// id than the one sent.
pub fn encrypt_payment_id(pid: &[u8; 8], derivation: &KeyDerivation) -> [u8; 8] {
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&derivation.0);
    buf[32] = HASH_KEY_ENCRYPTED_PAYMENT_ID;
    let key = cn_fast_hash(&buf);
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = pid[i] ^ key[i];
    }
    out
}

/// `_ = derivation_index_len` is used by the tests to pin the buffer length
/// rule; re-exported so the invariant is checkable from outside.
#[doc(hidden)]
pub fn __derivation_buf_len(output_index: u64) -> usize {
    derivation_index_len(output_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(b: u8) -> SecretKey {
        SecretKey(sc_reduce32(&[b; 32]))
    }

    /// `specs/02` §9: `derivation_to_scalar` hashes exactly `32 + varint_len`
    /// bytes — not 42, which is what a naive port of the C struct would do.
    #[test]
    fn derivation_buffer_is_exactly_32_plus_varint_len() {
        assert_eq!(__derivation_buf_len(0), 33);
        assert_eq!(__derivation_buf_len(127), 33);
        assert_eq!(__derivation_buf_len(128), 34);
        assert_eq!(__derivation_buf_len(16_384), 35);

        // Hashing the padded 42-byte buffer would give a different answer.
        let d = KeyDerivation([7u8; 32]);
        let correct = derivation_to_scalar(&d, 0);
        let mut padded = [0u8; 42];
        padded[..32].copy_from_slice(&d.0);
        let wrong = hash_to_scalar(&padded);
        assert_ne!(correct.0, wrong.0, "padding must change the result");
    }

    /// `specs/02` §9: `"SubAddr"` includes its trailing NUL; `"view_tag"` does
    /// not. Getting either wrong silently produces valid-looking but wrong keys.
    #[test]
    fn domain_separator_nul_handling() {
        assert_eq!(HASH_KEY_SUBADDRESS.len(), 8);
        assert_eq!(HASH_KEY_SUBADDRESS[7], 0);
        assert_eq!(VIEW_TAG_SALT.len(), 8);
        assert_eq!(VIEW_TAG_SALT, b"view_tag");
        assert_ne!(VIEW_TAG_SALT[7], 0);
    }

    #[test]
    fn view_tag_is_one_byte_and_the_first_one() {
        let d = KeyDerivation([3u8; 32]);
        let tag = derive_view_tag(&d, 5);
        let mut buf = Vec::new();
        buf.extend_from_slice(VIEW_TAG_SALT);
        buf.extend_from_slice(&d.0);
        buf.push(5);
        assert_eq!(tag.0, cn_fast_hash(&buf)[0]);
        assert_eq!(core::mem::size_of::<ViewTag>(), 1);
    }

    /// The whole point of the key-exchange: the sender's `r*A` and the
    /// receiver's `a*R` must agree, and the derived one-time keys must be a
    /// matching keypair.
    #[test]
    fn derivation_agrees_between_sender_and_receiver() {
        let a = sk(0x11); // receiver view secret
        let b = sk(0x22); // receiver spend secret
        let big_a = crate::ops::secret_key_to_public_key(&a).unwrap();
        let big_b = crate::ops::secret_key_to_public_key(&b).unwrap();

        let r = sk(0x33); // tx secret key
        let big_r = crate::ops::secret_key_to_public_key(&r).unwrap();

        let d_sender = generate_key_derivation(&big_a, &r).unwrap();
        let d_receiver = generate_key_derivation(&big_r, &a).unwrap();
        assert_eq!(d_sender, d_receiver);

        for i in [0u64, 1, 127, 128, 1000] {
            let p = derive_public_key(&d_sender, i, &big_b).unwrap();
            let x = derive_secret_key(&d_receiver, i, &b);
            assert_eq!(
                crate::ops::secret_key_to_public_key(&x).unwrap(),
                p,
                "one-time keypair mismatch at index {i}"
            );
            // The scanning direction recovers B from P.
            assert_eq!(
                derive_subaddress_public_key(&p, &d_receiver, i).unwrap(),
                big_b
            );
        }
    }

    /// `specs/02` §3.8: index (0,0) returns the main address unchanged. Running
    /// the derivation for it would hand out an address nobody can pay.
    #[test]
    fn subaddress_zero_zero_is_the_main_address() {
        let a = sk(0x44);
        let b = sk(0x55);
        let keys = AccountPublicAddress {
            spend_public_key: crate::ops::secret_key_to_public_key(&b).unwrap(),
            view_public_key: crate::ops::secret_key_to_public_key(&a).unwrap(),
        };
        assert_eq!(
            get_subaddress(&keys, &a, SubaddressIndex::MAIN).unwrap(),
            keys
        );
        // Any other index differs.
        for idx in [
            SubaddressIndex::new(0, 1),
            SubaddressIndex::new(1, 0),
            SubaddressIndex::new(2, 3),
        ] {
            assert_ne!(get_subaddress(&keys, &a, idx).unwrap(), keys);
        }
    }

    /// The subaddress view key must satisfy `C = a * D`, or the recipient
    /// cannot scan for the output.
    #[test]
    fn subaddress_view_key_relation() {
        let a = sk(0x66);
        let b = sk(0x77);
        let keys = AccountPublicAddress {
            spend_public_key: crate::ops::secret_key_to_public_key(&b).unwrap(),
            view_public_key: crate::ops::secret_key_to_public_key(&a).unwrap(),
        };
        let sub = get_subaddress(&keys, &a, SubaddressIndex::new(1, 2)).unwrap();
        let d = decode_point(&sub.spend_public_key.0).unwrap();
        let a_s = decode_scalar(&a.0).unwrap();
        assert_eq!(encode_point(&(a_s * d)), sub.view_public_key.0);
    }

    #[test]
    fn deterministic_view_key_matches_the_documented_relation() {
        let b = sk(0x88);
        let a = view_key_from_spend_key(&b);
        assert_eq!(a.0, sc_reduce32(&cn_fast_hash(&b.0)));
    }

    #[test]
    fn payment_id_encryption_is_an_involution() {
        let d = KeyDerivation([0x5au8; 32]);
        let pid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let enc = encrypt_payment_id(&pid, &d);
        assert_ne!(enc, pid);
        assert_eq!(encrypt_payment_id(&enc, &d), pid);
    }

    /// A known answer, computed outside this crate with Keccak-256 over
    /// `derivation || 0x8d`. The reduced key `hash_to_scalar` gives would
    /// encrypt these to `40b00cb4f2dd301b` and `41b20fb0f7db3713`.
    #[test]
    fn payment_id_encryption_matches_the_reference() {
        let d = KeyDerivation([0x5au8; 32]);
        assert_eq!(
            encrypt_payment_id(&[1, 2, 3, 4, 5, 6, 7, 8], &d),
            [0xce, 0xab, 0xd1, 0xd9, 0x90, 0x28, 0xa1, 0x2b]
        );
        // The dummy a transaction without an id carries.
        assert_eq!(
            encrypt_payment_id(&[0; 8], &d),
            [0xcf, 0xa9, 0xd2, 0xdd, 0x95, 0x2e, 0xa6, 0x23]
        );
    }

    #[test]
    fn derivation_fails_cleanly_on_a_bad_public_key() {
        // A y-coordinate with no matching x is not on the curve.
        let bad = PublicKey([0xffu8; 32]);
        assert!(!crate::ops::check_key(&bad));
        assert!(generate_key_derivation(&bad, &sk(1)).is_none());
        assert!(derive_public_key(&KeyDerivation([1u8; 32]), 0, &bad).is_none());
    }
}
