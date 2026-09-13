//! `tx_extra` parsing.
//!
//! `specs/05-blocks-and-transactions.md` §3.4.
//!
//! **`extra` is consensus-opaque.** For serialization it is a plain
//! `Vec<u8>`; a failure to parse it does **not** invalidate the transaction. A
//! wallet that cannot parse `extra` simply cannot find its outputs in that tx.
//! Only its *size* is constrained, and only as a relay rule
//! (`specs/06` §6.3) — never apply `MAX_TX_EXTRA_SIZE` here.

use wow_crypto::types::{Hash256, PublicKey};
use wow_serialize::varint::read_varint;

use crate::limits::{TX_EXTRA_NONCE_MAX_COUNT, TX_EXTRA_PADDING_MAX_COUNT};

/// `tx_extra` field tags (`specs/04` §1.3).
pub mod tag {
    pub const PADDING: u8 = 0x00;
    pub const PUBKEY: u8 = 0x01;
    pub const NONCE: u8 = 0x02;
    pub const MERGE_MINING: u8 = 0x03;
    pub const ADDITIONAL_PUBKEYS: u8 = 0x04;
    pub const MYSTERIOUS_MINERGATE: u8 = 0xDE;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxExtraField {
    /// Zero bytes, including the tag. Total length must be `<= 255`.
    Padding {
        len: usize,
    },
    Pubkey(PublicKey),
    /// Raw nonce bytes. `nonce[0] == 0x00` introduces a 32-byte plain payment
    /// id (total length 33); `nonce[0] == 0x01` an 8-byte encrypted one
    /// (length 9).
    Nonce(Vec<u8>),
    MergeMining {
        depth: u64,
        merkle_root: Hash256,
    },
    AdditionalPubkeys(Vec<PublicKey>),
    MysteriousMinergate(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxExtraError {
    /// A non-zero byte inside a padding run.
    BadPadding,
    /// A padding run longer than `TX_EXTRA_PADDING_MAX_COUNT`.
    PaddingTooLong,
    /// A nonce longer than `TX_EXTRA_NONCE_MAX_COUNT`.
    NonceTooLong,
    /// The buffer ended mid-field.
    Truncated,
    /// A malformed length varint.
    BadVarint,
}

/// The outcome of parsing `extra`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedExtra {
    pub fields: Vec<TxExtraField>,
    /// Set when an **unknown tag** was reached. The remainder is ignored, which
    /// is not an error: `parse_tx_extra` stops and returns what it has.
    pub stopped_at_unknown_tag: Option<u8>,
    /// Set when parsing hit a malformed field. The reference logs and returns
    /// `false`, keeping the fields it had already collected — and the caller
    /// treats that as "could not fully parse", never as tx invalidity.
    pub error: Option<TxExtraError>,
}

impl ParsedExtra {
    /// The first `TX_EXTRA_TAG_PUBKEY`, which is the transaction public key.
    pub fn tx_pubkey(&self) -> Option<PublicKey> {
        self.fields.iter().find_map(|f| match f {
            TxExtraField::Pubkey(k) => Some(*k),
            _ => None,
        })
    }

    /// `TX_EXTRA_TAG_ADDITIONAL_PUBKEYS`, one per output for subaddress sends.
    pub fn additional_pubkeys(&self) -> Option<&[PublicKey]> {
        self.fields.iter().find_map(|f| match f {
            TxExtraField::AdditionalPubkeys(k) => Some(k.as_slice()),
            _ => None,
        })
    }

    /// A 32-byte plain payment id, if a nonce carries one.
    pub fn payment_id(&self) -> Option<Hash256> {
        self.fields.iter().find_map(|f| match f {
            TxExtraField::Nonce(n) if n.len() == 33 && n[0] == 0x00 => {
                Some(n[1..].try_into().unwrap())
            }
            _ => None,
        })
    }

    /// An 8-byte encrypted payment id, if a nonce carries one.
    pub fn encrypted_payment_id(&self) -> Option<[u8; 8]> {
        self.fields.iter().find_map(|f| match f {
            TxExtraField::Nonce(n) if n.len() == 9 && n[0] == 0x01 => {
                Some(n[1..].try_into().unwrap())
            }
            _ => None,
        })
    }
}

/// `parse_tx_extra(extra, fields)`.
///
/// Never fails in the sense that matters: the return value always carries
/// whatever fields were recovered. Callers must not treat `error` as making the
/// transaction invalid.
pub fn parse_tx_extra(extra: &[u8]) -> ParsedExtra {
    let mut out = ParsedExtra {
        fields: Vec::new(),
        stopped_at_unknown_tag: None,
        error: None,
    };
    let mut i = 0usize;

    while i < extra.len() {
        let t = extra[i];
        let field_start = i;
        i += 1;

        match t {
            tag::PADDING => {
                // Read zeros until EOF or a non-zero byte.
                let mut n = 0usize;
                while i < extra.len() && extra[i] == 0 {
                    i += 1;
                    n += 1;
                }
                let total = i - field_start; // includes the tag byte
                if total > TX_EXTRA_PADDING_MAX_COUNT {
                    out.error = Some(TxExtraError::PaddingTooLong);
                    return out;
                }
                if i < extra.len() {
                    // A non-zero byte inside padding is an error.
                    out.error = Some(TxExtraError::BadPadding);
                    return out;
                }
                out.fields.push(TxExtraField::Padding { len: n + 1 });
            }
            tag::PUBKEY => {
                let Some(k) = extra.get(i..i + 32) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                i += 32;
                out.fields
                    .push(TxExtraField::Pubkey(PublicKey(k.try_into().unwrap())));
            }
            tag::NONCE => {
                let Ok((len, used)) = read_varint(&extra[i..]) else {
                    out.error = Some(TxExtraError::BadVarint);
                    return out;
                };
                i += used;
                let len = len as usize;
                if len > TX_EXTRA_NONCE_MAX_COUNT {
                    out.error = Some(TxExtraError::NonceTooLong);
                    return out;
                }
                let Some(n) = extra.get(i..i + len) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                i += len;
                out.fields.push(TxExtraField::Nonce(n.to_vec()));
            }
            tag::MERGE_MINING => {
                // A length-prefixed blob containing `varint depth` + 32 bytes.
                let Ok((blob_len, used)) = read_varint(&extra[i..]) else {
                    out.error = Some(TxExtraError::BadVarint);
                    return out;
                };
                i += used;
                let blob_len = blob_len as usize;
                let Some(body) = extra.get(i..i + blob_len) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                i += blob_len;
                let Ok((depth, d_used)) = read_varint(body) else {
                    out.error = Some(TxExtraError::BadVarint);
                    return out;
                };
                let Some(root) = body.get(d_used..d_used + 32) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                out.fields.push(TxExtraField::MergeMining {
                    depth,
                    merkle_root: root.try_into().unwrap(),
                });
            }
            tag::ADDITIONAL_PUBKEYS => {
                let Ok((count, used)) = read_varint(&extra[i..]) else {
                    out.error = Some(TxExtraError::BadVarint);
                    return out;
                };
                i += used;
                let count = count as usize;
                let Some(body) = extra.get(i..).and_then(|b| {
                    let need = count.checked_mul(32)?;
                    b.get(..need)
                }) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                i += count * 32;
                let keys = body
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .map(|c| PublicKey(*c))
                    .collect();
                out.fields.push(TxExtraField::AdditionalPubkeys(keys));
            }
            tag::MYSTERIOUS_MINERGATE => {
                let Ok((len, used)) = read_varint(&extra[i..]) else {
                    out.error = Some(TxExtraError::BadVarint);
                    return out;
                };
                i += used;
                let len = len as usize;
                let Some(body) = extra.get(i..i + len) else {
                    out.error = Some(TxExtraError::Truncated);
                    return out;
                };
                i += len;
                out.fields
                    .push(TxExtraField::MysteriousMinergate(body.to_vec()));
            }
            unknown => {
                // Stop parsing; the remainder is ignored. Not an error.
                out.stopped_at_unknown_tag = Some(unknown);
                return out;
            }
        }
    }
    out
}

/// `sort_tx_extra`: emit fields in ascending tag order.
///
/// Used when **building** a coinbase; not required on validation
/// (`specs/05` §3.4).
pub fn serialize_tx_extra(fields: &[TxExtraField], sorted: bool) -> Vec<u8> {
    let mut ordered: Vec<&TxExtraField> = fields.iter().collect();
    if sorted {
        ordered.sort_by_key(|f| field_tag(f));
    }
    let mut out = Vec::new();
    for f in ordered {
        write_field(&mut out, f);
    }
    out
}

fn field_tag(f: &TxExtraField) -> u8 {
    match f {
        TxExtraField::Padding { .. } => tag::PADDING,
        TxExtraField::Pubkey(_) => tag::PUBKEY,
        TxExtraField::Nonce(_) => tag::NONCE,
        TxExtraField::MergeMining { .. } => tag::MERGE_MINING,
        TxExtraField::AdditionalPubkeys(_) => tag::ADDITIONAL_PUBKEYS,
        TxExtraField::MysteriousMinergate(_) => tag::MYSTERIOUS_MINERGATE,
    }
}

fn write_field(out: &mut Vec<u8>, f: &TxExtraField) {
    use wow_serialize::varint::write_varint;
    out.push(field_tag(f));
    match f {
        TxExtraField::Padding { len } => {
            // `len` counts the tag byte.
            out.extend(std::iter::repeat_n(0u8, len.saturating_sub(1)));
        }
        TxExtraField::Pubkey(k) => out.extend_from_slice(&k.0),
        TxExtraField::Nonce(n) => {
            write_varint(out, n.len() as u64);
            out.extend_from_slice(n);
        }
        TxExtraField::MergeMining { depth, merkle_root } => {
            let mut body = Vec::new();
            write_varint(&mut body, *depth);
            body.extend_from_slice(merkle_root);
            write_varint(out, body.len() as u64);
            out.extend_from_slice(&body);
        }
        TxExtraField::AdditionalPubkeys(keys) => {
            write_varint(out, keys.len() as u64);
            for k in keys {
                out.extend_from_slice(&k.0);
            }
        }
        TxExtraField::MysteriousMinergate(b) => {
            write_varint(out, b.len() as u64);
            out.extend_from_slice(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_coinbase_extra() {
        let key = PublicKey([0xab; 32]);
        let extra = serialize_tx_extra(
            &[
                TxExtraField::Pubkey(key),
                TxExtraField::Nonce(vec![0xde, 0xad]),
            ],
            true,
        );
        // sort_tx_extra emits PUBKEY (0x01) before NONCE (0x02).
        assert_eq!(extra[0], tag::PUBKEY);
        let p = parse_tx_extra(&extra);
        assert_eq!(p.error, None);
        assert_eq!(p.tx_pubkey(), Some(key));
        assert_eq!(p.fields.len(), 2);
    }

    #[test]
    fn payment_id_forms() {
        let mut plain = vec![0x00u8];
        plain.extend_from_slice(&[7u8; 32]);
        let extra = serialize_tx_extra(&[TxExtraField::Nonce(plain)], false);
        assert_eq!(parse_tx_extra(&extra).payment_id(), Some([7u8; 32]));

        let mut enc = vec![0x01u8];
        enc.extend_from_slice(&[9u8; 8]);
        let extra = serialize_tx_extra(&[TxExtraField::Nonce(enc)], false);
        assert_eq!(
            parse_tx_extra(&extra).encrypted_payment_id(),
            Some([9u8; 8])
        );
        // The two forms must not be confused.
        assert_eq!(parse_tx_extra(&extra).payment_id(), None);
    }

    #[test]
    fn additional_pubkeys_roundtrip() {
        let keys: Vec<PublicKey> = (0u8..4).map(|i| PublicKey([i; 32])).collect();
        let extra = serialize_tx_extra(&[TxExtraField::AdditionalPubkeys(keys.clone())], false);
        let p = parse_tx_extra(&extra);
        assert_eq!(p.additional_pubkeys(), Some(keys.as_slice()));
    }

    /// An unknown tag stops parsing; the remainder is ignored and this is
    /// **not** an error (`specs/05` §3.4).
    #[test]
    fn unknown_tag_stops_without_error() {
        let mut extra = serialize_tx_extra(&[TxExtraField::Pubkey(PublicKey([1; 32]))], false);
        extra.push(0x77);
        extra.extend_from_slice(b"whatever follows is ignored");
        let p = parse_tx_extra(&extra);
        assert_eq!(p.error, None);
        assert_eq!(p.stopped_at_unknown_tag, Some(0x77));
        assert_eq!(p.tx_pubkey(), Some(PublicKey([1; 32])));
    }

    #[test]
    fn padding_rules() {
        // Trailing zeros are padding.
        let extra = vec![0x00u8, 0, 0, 0];
        let p = parse_tx_extra(&extra);
        assert_eq!(p.error, None);
        assert_eq!(p.fields, vec![TxExtraField::Padding { len: 4 }]);

        // A non-zero byte inside padding is an error.
        let extra = vec![0x00u8, 0, 1];
        assert_eq!(parse_tx_extra(&extra).error, Some(TxExtraError::BadPadding));

        // Padding longer than 255 bytes, tag included, is an error.
        let extra = vec![0u8; 256];
        assert_eq!(
            parse_tx_extra(&extra).error,
            Some(TxExtraError::PaddingTooLong)
        );
        // Exactly 255 is fine.
        let extra = vec![0u8; 255];
        assert_eq!(parse_tx_extra(&extra).error, None);
    }

    #[test]
    fn nonce_length_is_capped() {
        let mut extra = vec![tag::NONCE, 0xff, 0x01]; // varint 255
        extra.extend(std::iter::repeat_n(0u8, 255));
        assert_eq!(parse_tx_extra(&extra).error, None);

        let mut extra = vec![tag::NONCE, 0x80, 0x02]; // varint 256
        extra.extend(std::iter::repeat_n(0u8, 256));
        assert_eq!(
            parse_tx_extra(&extra).error,
            Some(TxExtraError::NonceTooLong)
        );
    }

    #[test]
    fn truncation_is_reported_not_panicked() {
        assert_eq!(
            parse_tx_extra(&[tag::PUBKEY, 1, 2, 3]).error,
            Some(TxExtraError::Truncated)
        );
        assert_eq!(
            parse_tx_extra(&[tag::NONCE, 0x05, 1, 2]).error,
            Some(TxExtraError::Truncated)
        );
        assert_eq!(
            parse_tx_extra(&[tag::NONCE]).error,
            Some(TxExtraError::BadVarint)
        );
    }

    /// `specs/15` §4.4: `tx_extra` is a listed fuzz target.
    #[test]
    fn never_panics() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for len in 0..300usize {
            let mut b = Vec::with_capacity(len);
            for _ in 0..len {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                b.push((x >> 33) as u8);
            }
            let _ = parse_tx_extra(&b);
        }
        // Every single-byte tag.
        for t in 0u16..=255 {
            let _ = parse_tx_extra(&[t as u8]);
            let _ = parse_tx_extra(&[t as u8, 0xff, 0xff, 0xff]);
        }
    }

    /// A parse failure must not be mistaken for tx invalidity; the fields
    /// recovered before the failure are still available.
    #[test]
    fn fields_before_a_failure_are_kept() {
        let mut extra = serialize_tx_extra(&[TxExtraField::Pubkey(PublicKey([5; 32]))], false);
        extra.push(tag::PUBKEY);
        extra.extend_from_slice(&[0u8; 10]); // truncated
        let p = parse_tx_extra(&extra);
        assert_eq!(p.error, Some(TxExtraError::Truncated));
        assert_eq!(p.tx_pubkey(), Some(PublicKey([5; 32])));
    }
}
