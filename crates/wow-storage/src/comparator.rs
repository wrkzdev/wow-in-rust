//! The three LMDB key comparators.
//!
//! `specs/10-storage-lmdb.md` §3.1, and the first thing `specs/15` §3.3 asks
//! for: "Comparator unit tests **first**".
//!
//! These decide the on-disk *ordering* of every table. A wrong comparator does
//! not corrupt anything — LMDB will happily store records in whatever order it
//! is told — but it puts them somewhere the C++ node will not look, so every
//! `MDB_GET_BOTH` lookup silently misses and a `data.mdb` written by this node
//! reads back empty in `wownerod`. `specs/10` §3.1 calls
//! [`compare_hash32`] "the single most likely subtle mistake in this chapter".
//!
//! # Host order is part of the format
//!
//! All three read multi-byte integers in **host** order, because the C++ ones
//! `memcpy` into a native integer. `specs/10` §3.3 spells out the consequence:
//! a big-endian build of the C++ node would produce an incompatible file too,
//! so this is a property of the format rather than a bug to route around. The
//! functions here use `from_ne_bytes` to say so, and [`assert_little_endian`]
//! is what a database open should call.

use std::cmp::Ordering;

/// The dummy key the five `zerokval` tables use (`specs/10` §3.2).
pub const ZEROKEY: [u8; 8] = [0; 8];

/// `mdb_cmp_default` / `compare_uint64` — eight bytes as a native `u64`.
///
/// Used for `MDB_INTEGERKEY` tables and for the dupsort prefix of `block_info`
/// and `output_txs`.
///
/// # Panics
///
/// Never: shorter inputs are zero-extended rather than read out of bounds. The
/// C++ would read past the end, but LMDB only ever hands it whole keys.
pub fn compare_uint64(a: &[u8], b: &[u8]) -> Ordering {
    read_u64(a).cmp(&read_u64(b))
}

/// `compare_hash32` — 32 bytes as eight native `u32`s, compared from the
/// **most significant word down**: word 7 first, then 6, … then 0.
///
/// This is **not** bytewise ordering, and not a plain big-endian or
/// little-endian integer comparison of the 32 bytes either. It is a
/// little-endian comparison at 4-byte granularity *within* each word and a
/// big-endian one *between* words.
///
/// Keys `block_heights`, `tx_indices` and `spent_keys`.
pub fn compare_hash32(a: &[u8], b: &[u8]) -> Ordering {
    for n in (0..8).rev() {
        let va = read_u32(a, n * 4);
        let vb = read_u32(b, n * 4);
        if va != vb {
            return va.cmp(&vb);
        }
    }
    Ordering::Equal
}

/// `compare_string` — `strncmp` over the shorter length, then shorter-first.
///
/// Used for the `properties` table, whose keys are NUL-terminated C strings,
/// so the terminator is part of the key and counts towards the length.
pub fn compare_string(a: &[u8], b: &[u8]) -> Ordering {
    let sz = a.len().min(b.len());
    match a[..sz].cmp(&b[..sz]) {
        Ordering::Equal => a.len().cmp(&b.len()),
        other => other,
    }
}

/// Read eight bytes in host order, zero-extending a short slice.
fn read_u64(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = s.len().min(8);
    buf[..n].copy_from_slice(&s[..n]);
    u64::from_ne_bytes(buf)
}

/// Read four bytes at `off` in host order, zero-extending past the end.
fn read_u32(s: &[u8], off: usize) -> u32 {
    let mut buf = [0u8; 4];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = s.get(off + i).copied().unwrap_or(0);
    }
    u32::from_ne_bytes(buf)
}

/// `specs/10` §3.3: every record is the raw memory image of a packed struct in
/// host byte order, so a big-endian host produces a *different*, self-consistent
/// file that the C++ node cannot read.
///
/// A database open should call this rather than silently producing one.
pub const fn is_little_endian() -> bool {
    cfg!(target_endian = "little")
}

/// Panic unless the host is little-endian.
///
/// Separate from [`is_little_endian`] so a caller that wants to *report* the
/// problem rather than abort can.
pub fn assert_little_endian() {
    assert!(
        is_little_endian(),
        "specs/10 §3.3: data.mdb records are packed structs in host byte order. \
         On a big-endian host this node would write a self-consistent file that \
         wownerod cannot read, which defeats the point of the format."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 32-byte hash from eight `u32` words, word 0 first in memory —
    /// the layout `compare_hash32` reads.
    fn words(w: [u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, v) in w.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        }
        out
    }

    /// The table of known orderings `specs/15` §3.3 asks for.
    #[test]
    fn compare_hash32_orders_by_the_top_word_first() {
        let base = words([0; 8]);

        // Word 7 dominates every lower word.
        let hi = words([0, 0, 0, 0, 0, 0, 0, 1]);
        let lo_max = words([
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            0,
        ]);
        assert_eq!(compare_hash32(&hi, &lo_max), Ordering::Greater);
        assert_eq!(compare_hash32(&lo_max, &hi), Ordering::Less);

        // Equal top words fall through to the next one down.
        let a = words([0, 0, 0, 0, 0, 0, 5, 9]);
        let b = words([9, 9, 9, 9, 9, 9, 4, 9]);
        assert_eq!(compare_hash32(&a, &b), Ordering::Greater, "word 6: 5 > 4");

        // Word 0 is the last resort.
        let a = words([2, 0, 0, 0, 0, 0, 0, 0]);
        let b = words([1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(compare_hash32(&a, &b), Ordering::Greater);

        assert_eq!(compare_hash32(&base, &base), Ordering::Equal);
    }

    /// The distinguishing test: `compare_hash32` must **disagree** with plain
    /// bytewise ordering. If it agreed everywhere, the whole section would be
    /// pointless — and an implementation that used `a.cmp(b)` would pass.
    #[test]
    fn compare_hash32_is_not_bytewise() {
        // Byte 0 is the low byte of word 0, the *least* significant position;
        // byte 31 is the high byte of word 7, the most significant.
        let mut a = [0u8; 32];
        a[0] = 0xff;
        let mut b = [0u8; 32];
        b[31] = 0x01;

        assert_eq!(
            a.as_slice().cmp(b.as_slice()),
            Ordering::Greater,
            "bytewise: a starts with 0xff"
        );
        assert_eq!(
            compare_hash32(&a, &b),
            Ordering::Less,
            "compare_hash32: b's word 7 is 1, a's is 0"
        );
    }

    /// Within a word the comparison is little-endian, which bytewise ordering
    /// also gets wrong — in the other direction.
    #[test]
    fn compare_hash32_is_little_endian_within_a_word() {
        // Both differ only inside word 0.
        let mut a = [0u8; 32];
        a[0] = 0x00;
        a[3] = 0x01; // word 0 == 0x01000000
        let mut b = [0u8; 32];
        b[0] = 0xff;
        b[3] = 0x00; // word 0 == 0x000000ff

        assert_eq!(compare_hash32(&a, &b), Ordering::Greater);
        assert_eq!(
            a.as_slice().cmp(b.as_slice()),
            Ordering::Less,
            "bytewise disagrees"
        );
    }

    /// A sort of real-looking hashes must be a total order and must be stable
    /// under the comparator's own definition.
    #[test]
    fn compare_hash32_is_a_total_order() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut hashes: Vec<[u8; 32]> = (0..200)
            .map(|_| {
                let mut h = [0u8; 32];
                for c in h.chunks_mut(8) {
                    c.copy_from_slice(&next().to_ne_bytes());
                }
                h
            })
            .collect();

        hashes.sort_by(|x, y| compare_hash32(x, y));
        for w in hashes.windows(2) {
            assert_ne!(
                compare_hash32(&w[0], &w[1]),
                Ordering::Greater,
                "sort did not produce a non-decreasing sequence"
            );
        }
        // Antisymmetry and reflexivity over the sample.
        for h in &hashes {
            assert_eq!(compare_hash32(h, h), Ordering::Equal);
        }
        for pair in hashes.chunks(2).filter(|c| c.len() == 2) {
            assert_eq!(
                compare_hash32(&pair[0], &pair[1]).reverse(),
                compare_hash32(&pair[1], &pair[0])
            );
        }
    }

    #[test]
    fn compare_uint64_is_numeric_not_bytewise() {
        let a = 0x0100u64.to_ne_bytes();
        let b = 0x00ffu64.to_ne_bytes();
        assert_eq!(compare_uint64(&a, &b), Ordering::Greater);
        // On a little-endian host the bytewise order disagrees.
        if is_little_endian() {
            assert_eq!(a.as_slice().cmp(b.as_slice()), Ordering::Less);
        }

        assert_eq!(compare_uint64(&a, &a), Ordering::Equal);
        assert_eq!(
            compare_uint64(&0u64.to_ne_bytes(), &u64::MAX.to_ne_bytes()),
            Ordering::Less
        );
    }

    /// Heights are the common case: they must sort ascending.
    #[test]
    fn compare_uint64_sorts_heights_ascending() {
        let mut keys: Vec<[u8; 8]> = [900_000u64, 0, 1, 514_000, 255, 256]
            .iter()
            .map(|h| h.to_ne_bytes())
            .collect();
        keys.sort_by(|a, b| compare_uint64(a, b));
        let back: Vec<u64> = keys.iter().map(|k| u64::from_ne_bytes(*k)).collect();
        assert_eq!(back, vec![0, 1, 255, 256, 514_000, 900_000]);
    }

    /// `specs/10` §3.1: `strncmp` over the shorter length, then shorter-first.
    #[test]
    fn compare_string_puts_the_shorter_first_on_a_prefix() {
        assert_eq!(compare_string(b"abc", b"abcd"), Ordering::Less);
        assert_eq!(compare_string(b"abcd", b"abc"), Ordering::Greater);
        assert_eq!(compare_string(b"abc", b"abc"), Ordering::Equal);
        // A difference inside the common prefix decides first.
        assert_eq!(compare_string(b"abd", b"abcd"), Ordering::Greater);
        assert_eq!(compare_string(b"", b"a"), Ordering::Less);
        assert_eq!(compare_string(b"", b""), Ordering::Equal);
    }

    /// The `properties` keys are NUL-terminated, so the terminator is part of
    /// the key — `"version\0"` is eight bytes, not seven.
    #[test]
    fn compare_string_counts_the_nul_terminator() {
        let with_nul = b"version\0";
        let without = b"version";
        assert_eq!(with_nul.len(), 8);
        assert_eq!(compare_string(with_nul, without), Ordering::Greater);
        assert_ne!(compare_string(with_nul, without), Ordering::Equal);
    }

    #[test]
    fn the_zerokey_is_eight_zero_bytes() {
        assert_eq!(ZEROKEY, [0u8; 8]);
        assert_eq!(ZEROKEY.len(), 8);
        assert_eq!(
            compare_uint64(&ZEROKEY, &0u64.to_ne_bytes()),
            Ordering::Equal
        );
    }

    #[test]
    fn the_host_is_little_endian() {
        assert!(is_little_endian(), "see specs/10 §3.3");
        assert_little_endian();
    }
}
