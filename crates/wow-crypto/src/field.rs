//! Arithmetic in GF(2^255 - 19), used only by `ge_fromfe_frombytes_vartime`.
//!
//! `specs/02-crypto.md` §1.3 says to port that map literally from
//! `src/crypto/crypto-ops.c`. The C uses a 10-limb radix-2^25.5 representation;
//! this module uses 5 limbs of 51 bits instead. That substitution is safe
//! because the map's only observable outputs are (a) the sign and zero tests
//! `fe_isnegative` / `fe_isnonzero`, both of which the C defines on the
//! **canonical** byte encoding, and (b) the final compressed point, which
//! `ge_tobytes` also canonicalises. Both are representation-independent, so
//! matching the C mathematically is sufficient — and the 371 `hash_to_point`
//! plus 256 `hash_to_ec` reference vectors prove it empirically.
//!
//! Everything here is variable-time. That is fine and matches the C: the inputs
//! are a public hash or a public key.

use core::ops::{Add, Mul, Neg, Sub};

const LOW_51: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19), as 5 limbs of 51 bits, little-endian.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// `fe_frombytes`: little-endian, **bit 255 masked off**, no canonicality
    /// check.
    ///
    /// This is the loader `ge_frombytes_vartime` uses — note its
    /// `(load_3(s + 29) & 8388607) << 2`, where the mask clears bit 255.
    ///
    /// `ge_fromfe_frombytes_vartime` uses [`Fe::from_bytes_unmasked`] instead.
    /// The two differ for exactly the inputs with bit 255 set, which is half of
    /// all Keccak outputs, so mixing them up breaks half the vectors.
    pub fn from_bytes(s: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & LOW_51,
            (load(6) >> 3) & LOW_51,
            (load(12) >> 6) & LOW_51,
            (load(19) >> 1) & LOW_51,
            // bits 204..=254; the mask drops bit 255.
            (load(24) >> 12) & LOW_51,
        ])
    }

    /// The loader inside `ge_fromfe_frombytes_vartime`, which writes
    /// `h9 = load_3(s + 29) << 2` with **no mask**.
    ///
    /// Bit 255 therefore contributes with weight `2^255`, and since
    /// `2^255 === 19 (mod p)` the whole 256-bit little-endian integer is
    /// reduced rather than truncated. Compare [`Fe::from_bytes`].
    pub fn from_bytes_unmasked(s: &[u8; 32]) -> Fe {
        let mut f = Fe::from_bytes(s);
        if s[31] & 0x80 != 0 {
            f.0[0] += 19;
        }
        f.weak_reduce()
    }

    /// `fe_tobytes`: the canonical 32-byte little-endian encoding, fully reduced.
    pub fn to_bytes(self) -> [u8; 32] {
        let l = self.reduce().0;
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(l[0] | (l[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((l[1] >> 13) | (l[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((l[2] >> 26) | (l[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((l[3] >> 39) | (l[4] << 12)).to_le_bytes());
        out
    }

    /// Fully reduce into `[0, p)`.
    fn reduce(self) -> Fe {
        let mut l = self.weak_reduce().0;
        // q = 1 iff the value is >= p. Computed by carrying (value + 19) and
        // seeing whether it overflows 2^255.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;

        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= LOW_51;
        l[2] += l[1] >> 51;
        l[1] &= LOW_51;
        l[3] += l[2] >> 51;
        l[2] &= LOW_51;
        l[4] += l[3] >> 51;
        l[3] &= LOW_51;
        l[4] &= LOW_51; // drop the 2^255 bit, i.e. subtract p
        Fe(l)
    }

    /// Carry-propagate so every limb is < 2^51. The value may still be >= p.
    fn weak_reduce(self) -> Fe {
        let mut l = self.0;
        l[1] += l[0] >> 51;
        l[0] &= LOW_51;
        l[2] += l[1] >> 51;
        l[1] &= LOW_51;
        l[3] += l[2] >> 51;
        l[2] &= LOW_51;
        l[4] += l[3] >> 51;
        l[3] &= LOW_51;
        l[0] += 19 * (l[4] >> 51);
        l[4] &= LOW_51;
        l[1] += l[0] >> 51;
        l[0] &= LOW_51;
        Fe(l)
    }

    /// `fe_isnonzero`: tested on the canonical encoding, as in the C.
    pub fn is_nonzero(self) -> bool {
        self.to_bytes() != [0u8; 32]
    }

    /// `fe_isnegative`: the low bit of the canonical encoding.
    pub fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub fn square(self) -> Fe {
        self.mul_inner(&self)
    }

    /// `fe_sq2`: `2 * self^2`.
    pub fn square2(self) -> Fe {
        let s = self.square();
        s + s
    }

    /// `self^(2^k)`.
    fn square_n(self, k: u32) -> Fe {
        let mut r = self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// `self^((p-5)/8)` = `self^(2^252 - 3)`. `fe_pow22523` in the C.
    pub fn pow_p58(self) -> Fe {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t1 = self * t1;
        let t0 = t0 * t1;
        let t0 = t0.square();
        let t0 = t1 * t0;
        let t1 = t0.square_n(5);
        let t0 = t1 * t0;
        let t1 = t0.square_n(10);
        let t1 = t1 * t0;
        let t2 = t1.square_n(20);
        let t1 = t2 * t1;
        let t1 = t1.square_n(10);
        let t0 = t1 * t0;
        let t1 = t0.square_n(50);
        let t1 = t1 * t0;
        let t2 = t1.square_n(100);
        let t1 = t2 * t1;
        let t1 = t1.square_n(50);
        let t0 = t1 * t0;
        let t0 = t0.square_n(2);
        t0 * self
    }

    /// `fe_invert`: `self^(p-2)`.
    pub fn invert(self) -> Fe {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t1 = self * t1;
        let t0 = t0 * t1;
        let t2 = t0.square();
        let t1 = t1 * t2;
        let t2 = t1.square_n(5);
        let t1 = t2 * t1;
        let t2 = t1.square_n(10);
        let t2 = t2 * t1;
        let t3 = t2.square_n(20);
        let t2 = t3 * t2;
        let t2 = t2.square_n(10);
        let t1 = t2 * t1;
        let t2 = t1.square_n(50);
        let t2 = t2 * t1;
        let t3 = t2.square_n(100);
        let t2 = t3 * t2;
        let t2 = t2.square_n(50);
        let t1 = t2 * t1;
        let t1 = t1.square_n(5);
        t1 * t0
    }

    #[inline]
    fn mul_inner(&self, rhs: &Fe) -> Fe {
        let a = self.0;
        let b = rhs.0;
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;

        let m = |x: u64, y: u128| (x as u128) * y;

        let c0 = m(a[0], b[0] as u128)
            + m(a[1], b4_19)
            + m(a[2], b3_19)
            + m(a[3], b2_19)
            + m(a[4], b1_19);
        let c1 = m(a[0], b[1] as u128)
            + m(a[1], b[0] as u128)
            + m(a[2], b4_19)
            + m(a[3], b3_19)
            + m(a[4], b2_19);
        let c2 = m(a[0], b[2] as u128)
            + m(a[1], b[1] as u128)
            + m(a[2], b[0] as u128)
            + m(a[3], b4_19)
            + m(a[4], b3_19);
        let c3 = m(a[0], b[3] as u128)
            + m(a[1], b[2] as u128)
            + m(a[2], b[1] as u128)
            + m(a[3], b[0] as u128)
            + m(a[4], b4_19);
        let c4 = m(a[0], b[4] as u128)
            + m(a[1], b[3] as u128)
            + m(a[2], b[2] as u128)
            + m(a[3], b[1] as u128)
            + m(a[4], b[0] as u128);

        let carry = |c: u128| (c >> 51) as u64;
        let low = |c: u128| (c as u64) & LOW_51;

        let mut out = [0u64; 5];
        let c1 = c1 + carry(c0) as u128;
        out[0] = low(c0);
        let c2 = c2 + carry(c1) as u128;
        out[1] = low(c1);
        let c3 = c3 + carry(c2) as u128;
        out[2] = low(c2);
        let c4 = c4 + carry(c3) as u128;
        out[3] = low(c3);
        out[4] = low(c4);
        out[0] += carry(c4) * 19;
        out[1] += out[0] >> 51;
        out[0] &= LOW_51;
        Fe(out)
    }
}

impl Add for Fe {
    type Output = Fe;
    fn add(self, rhs: Fe) -> Fe {
        Fe([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
        .weak_reduce()
    }
}

impl Sub for Fe {
    type Output = Fe;
    fn sub(self, rhs: Fe) -> Fe {
        let r = rhs.weak_reduce().0;
        // Add 2p first so no limb underflows: 2p = [2^52-38, 2^52-2, ...].
        Fe([
            self.0[0] + 0x000f_ffff_ffff_ffda - r[0],
            self.0[1] + 0x000f_ffff_ffff_fffe - r[1],
            self.0[2] + 0x000f_ffff_ffff_fffe - r[2],
            self.0[3] + 0x000f_ffff_ffff_fffe - r[3],
            self.0[4] + 0x000f_ffff_ffff_fffe - r[4],
        ])
        .weak_reduce()
    }
}

impl Mul for Fe {
    type Output = Fe;
    fn mul(self, rhs: Fe) -> Fe {
        self.mul_inner(&rhs)
    }
}

impl Neg for Fe {
    type Output = Fe;
    fn neg(self) -> Fe {
        Fe::ZERO - self
    }
}

/// Field constants from `src/crypto/crypto-ops-data.c`.
///
/// The C stores these as 10-limb radix-2^25.5 literals; the canonical
/// little-endian encodings below were converted from exactly those literals,
/// and `tests::constants_match_their_definitions` re-derives each one from its
/// documented algebraic definition as a cross-check.
pub mod consts {
    use super::Fe;

    macro_rules! fe_const {
        ($name:ident, $doc:expr, $bytes:expr) => {
            #[doc = $doc]
            pub fn $name() -> Fe {
                Fe::from_bytes(&$bytes)
            }
        };
    }

    fe_const!(
        sqrtm1,
        "`fe_sqrtm1` = sqrt(-1) mod p.",
        [
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18,
            0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f,
            0x80, 0x24, 0x83, 0x2b
        ]
    );
    fe_const!(
        ma,
        "`fe_ma` = -A, with the Montgomery coefficient A = 486662.",
        [
            0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f
        ]
    );
    fe_const!(
        ma2,
        "`fe_ma2` = -A^2.",
        [
            0xc9, 0xe3, 0x3d, 0xdb, 0xc8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f
        ]
    );
    fe_const!(
        fffb1,
        "`fe_fffb1` = sqrt(-2 * A * (A + 2)).",
        [
            0xee, 0x41, 0x1c, 0x32, 0x75, 0x69, 0xa7, 0x22, 0x8d, 0x73, 0x2a, 0xb9, 0xa8, 0x04,
            0x94, 0xd1, 0xe3, 0x19, 0xfb, 0x41, 0x37, 0xc5, 0xa9, 0x20, 0x17, 0x1b, 0xd6, 0xda,
            0xef, 0xfb, 0x71, 0x7e
        ]
    );
    fe_const!(
        fffb2,
        "`fe_fffb2` = sqrt(2 * A * (A + 2)).",
        [
            0xe0, 0x9a, 0x7c, 0x60, 0x83, 0x64, 0xde, 0xd2, 0xdf, 0xf7, 0x56, 0x04, 0x46, 0x03,
            0xde, 0x51, 0xbe, 0x5f, 0x16, 0xc0, 0xb7, 0x51, 0xd4, 0x91, 0xf6, 0x2c, 0x5a, 0x04,
            0x0a, 0x1e, 0x06, 0x4d
        ]
    );
    fe_const!(
        fffb3,
        "`fe_fffb3` = sqrt(-sqrt(-1) * A * (A + 2)).",
        [
            0x66, 0x2c, 0x30, 0x17, 0x87, 0x7d, 0x1b, 0x58, 0x29, 0x42, 0x96, 0xa5, 0x4e, 0xff,
            0x24, 0x40, 0xed, 0xa2, 0x0d, 0x3f, 0x40, 0x46, 0x95, 0xb8, 0xef, 0x08, 0xc2, 0x14,
            0x0d, 0x11, 0x4a, 0x67
        ]
    );
    fe_const!(
        fffb4,
        "`fe_fffb4` = sqrt(sqrt(-1) * A * (A + 2)).",
        [
            0x86, 0x91, 0xb3, 0xb6, 0x03, 0x19, 0x3d, 0x85, 0x49, 0x4a, 0x3f, 0xa1, 0x08, 0xfc,
            0x46, 0xee, 0x2e, 0x43, 0xf7, 0x7e, 0x88, 0xf4, 0xc0, 0x26, 0xf9, 0xdb, 0x67, 0x10,
            0x03, 0xf3, 0x43, 0x1a
        ]
    );
    fe_const!(
        d,
        "`fe_d` = the Edwards curve coefficient d = -121665/121666.",
        [
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52
        ]
    );
}

/// `fe_divpowm1(r, u, v)` = `u * v^3 * (u * v^7)^((p-5)/8)`.
///
/// Literal port of `fe_divpowm1` in `src/crypto/crypto-ops.c`. For a square
/// `u/v` this is `sqrt(u/v)` up to a factor of `sqrt(-1)`; the callers
/// disambiguate.
pub fn divpowm1(u: Fe, v: Fe) -> Fe {
    let v3 = v.square() * v;
    let uv7 = v3.square() * v * u;
    let t = uv7.pow_p58();
    t * v3 * u
}

#[cfg(test)]
mod tests {
    use super::consts::*;
    use super::*;

    fn small(n: u64) -> Fe {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&n.to_le_bytes());
        Fe::from_bytes(&b)
    }

    #[test]
    fn canonical_roundtrip() {
        for seed in 0u8..64 {
            let mut b = [seed; 32];
            b[31] &= 0x7f;
            let c = Fe::from_bytes(&b).to_bytes();
            assert_eq!(Fe::from_bytes(&c).to_bytes(), c);
        }
    }

    #[test]
    fn bit_255_is_ignored() {
        let mut a = [0x11u8; 32];
        let mut b = a;
        a[31] &= 0x7f;
        b[31] |= 0x80;
        assert_eq!(Fe::from_bytes(&a).to_bytes(), Fe::from_bytes(&b).to_bytes());
    }

    #[test]
    fn non_canonical_input_reduces() {
        // p itself, and p+1, must reduce to 0 and 1.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(!Fe::from_bytes(&p).is_nonzero());
        let mut p1 = p;
        p1[0] = 0xee;
        assert!(!(Fe::from_bytes(&p1) - Fe::ONE).is_nonzero());
    }

    #[test]
    fn arithmetic_identities() {
        for k in 1u64..64 {
            let x = small(k);
            assert!(!(x * x.invert() - Fe::ONE).is_nonzero());
            assert!(!(x.square() - x * x).is_nonzero());
            assert!(!(x.square2() - (x * x + x * x)).is_nonzero());
            assert!(!(x + (-x)).is_nonzero());
            assert!(!(x - x).is_nonzero());
        }
    }

    #[test]
    fn is_negative_is_the_lsb_of_the_canonical_form() {
        assert!(small(1).is_negative());
        assert!(!small(2).is_negative());
        // -1 = p - 1, which is even.
        assert!(!(-small(1)).is_negative());
    }

    /// Re-derive each hard-coded constant from its documented algebraic
    /// definition. Guards against a transcription slip in `consts`.
    #[test]
    fn constants_match_their_definitions() {
        let a = small(486_662);
        let two = small(2);
        let a_ap2 = a * (a + two);

        assert!(!(ma() + a).is_nonzero(), "ma != -A");
        assert!(!(ma2() + a * a).is_nonzero(), "ma2 != -A^2");
        assert!(
            !(sqrtm1().square() + Fe::ONE).is_nonzero(),
            "sqrtm1^2 != -1"
        );
        assert!(!(fffb1().square() + (a_ap2 + a_ap2)).is_nonzero(), "fffb1");
        assert!(!(fffb2().square() - (a_ap2 + a_ap2)).is_nonzero(), "fffb2");
        assert!(!(fffb3().square() + sqrtm1() * a_ap2).is_nonzero(), "fffb3");
        assert!(!(fffb4().square() - sqrtm1() * a_ap2).is_nonzero(), "fffb4");

        // d = -121665/121666
        assert!(
            !(d() * small(121_666) + small(121_665)).is_nonzero(),
            "d != -121665/121666"
        );
    }

    /// `divpowm1(u, v)^2 * v == (u/v)^((p+3)/4) * v`, which for `p === 5 (mod 8)`
    /// is one of `u`, `-u`, `i*u`, `-i*u`. Which of the four it is, is exactly
    /// what `ge_fromfe_frombytes_vartime`'s four-way branch tests for, so the
    /// property to pin is that the result is always one of them.
    /// Differential test against arbitrary-precision arithmetic.
    ///
    /// The 5-limb representation here replaces the C's 10-limb radix-2^25.5
    /// one, which is safe only if the arithmetic agrees exactly. The
    /// `hash_to_point` vectors exercise it heavily but indirectly; these
    /// vectors were generated from Python `int` arithmetic mod p and cover the
    /// carry-chain boundaries (0, 1, p-1, p-2, 2^51, 2^51-1, 2^204, 2^251) that
    /// random inputs almost never hit.
    ///
    /// Columns: `a`, `b`, `a+b`, `a-b`, `a*b`, `a^2`, `a^-1` — all canonical
    /// little-endian.
    #[test]
    fn matches_arbitrary_precision() {
        const VECTORS: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0100000000000000000000000000000000000000000000000000000000000000",
                "0000000000000800000000000000000000000000000000000000000000000000",
                "0100000000000800000000000000000000000000000000000000000000000000",
                "eefffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0000000000000800000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0200000000000000000000000000000000000000000000000000000000000000",
                "3a6d063ebafce90cda2d955ffc4d2540668cb8a06f9790bee9ca0f9a2258b263",
                "3c6d063ebafce90cda2d955ffc4d2540668cb8a06f9790bee9ca0f9a2258b263",
                "b592f9c1450316f325d26aa003b2dabf9973475f90686f411635f065dda74d1c",
                "87da0c7c74f9d319b45b2abff89b4a80cc187141df2e217dd3951f3445b06447",
                "0400000000000000000000000000000000000000000000000000000000000000",
                "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            ),
            (
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "ff58b61bba8c7fc3cd5d98942ee8803f2fbb7efe65420250d58b1ddca7cf0a2c",
                "fe58b61bba8c7fc3cd5d98942ee8803f2fbb7efe65420250d58b1ddca7cf0a2c",
                "eda649e44573803c32a2676bd1177fc0d04481019abdfdaf2a74e2235830f553",
                "eea649e44573803c32a2676bd1177fc0d04481019abdfdaf2a74e2235830f553",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "70f0a0f0d80b8344169c005780be105ebf78c4e808333dd4c58869cbf8f5dc44",
                "6ef0a0f0d80b8344169c005780be105ebf78c4e808333dd4c58869cbf8f5dc44",
                "7b0f5f0f27f47cbbe963ffa87f41efa140873b17f7ccc22b3a779634070a233b",
                "fa1ebe1e4ee8f976d3c7fe51ff82de43810e772eee99855774ee2c690e144676",
                "0400000000000000000000000000000000000000000000000000000000000000",
                "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            ),
            (
                "1300000000000000000000000000000000000000000000000000000000000000",
                "130325451463d43862989eb33731edc64742fdc9b3d40c86f36f4135c85b074d",
                "260325451463d43862989eb33731edc64742fdc9b3d40c86f36f4135c85b074d",
                "edfcdabaeb9c2bc79d67614cc8ce1239b8bd02364c2bf3790c90beca37a4f832",
                "3a3bbf21815ac3374a4fc55422a79ac353ebcbfd57c9f3f2124fdbf3dbcf8b37",
                "6901000000000000000000000000000000000000000000000000000000000000",
                "14ca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b282f",
            ),
            (
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "fb8eeff9a5a364f95bbcd0d1462e4480a0be21c9445440b5b4c2478c9cf3544a",
                "fa8eeff9a5a364f95bbcd0d1462e4480a0be21c9445440b5b4c2478c9cf3544a",
                "f17010065a5c9b06a4432f2eb9d1bb7f5f41de36bbabbf4a4b3db873630cab35",
                "f27010065a5c9b06a4432f2eb9d1bb7f5f41de36bbabbf4a4b3db873630cab35",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000008",
                "8b8de348f5b9e76f4d9b55844a652f6eaca901b0c249f6dbd0f74f77ec95ea60",
                "8b8de348f5b9e76f4d9b55844a652f6eaca901b0c249f6dbd0f74f77ec95ea68",
                "62721cb70a461890b264aa7bb59ad0915356fe4f3db609242f08b088136a1527",
                "1b388e46d32ce3f46ba8257d4848d8c27cf901319777340548f6aecd0892164b",
                "0000000000000000000000000000000000000000000000000000000000008009",
                "9fa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc8672",
            ),
            (
                "0000000000000000000000000000000000000000000000000010000000000000",
                "f23eaeada33b93cfde61408e30a67c50a3d9efd4f07f63ee92ce0ac1033e4a50",
                "f23eaeada33b93cfde61408e30a67c50a3d9efd4f07f63ee92de0ac1033e4a50",
                "fbc051525cc46c30219ebf71cf5983af5c26102b0f809c116d41f53efcc1b52f",
                "f62c71e8d851b30a28dfe3a4b9f9db4f2cf69caa79ea4853b0deefe3da3aba33",
                "0000000000000000000000000000000000000026000000000000000000000000",
                "f8ffffffffffd7505e43790de53594d7505e43790de53594d7505e43790de535",
            ),
            (
                "ffffffffffff0700000000000000000000000000000000000000000000000000",
                "0200000000000000000000000000000000000000000000000000000000000000",
                "0100000000000800000000000000000000000000000000000000000000000000",
                "fdffffffffff0700000000000000000000000000000000000000000000000000",
                "feffffffffff0f00000000000000000000000000000000000000000000000000",
                "010000000000f0ffffffffff3f00000000000000000000000000000000000000",
                "89e3388ee338721cc7711cc791e3388ee3388e1cc7711cc771e4388ee3388e23",
            ),
            (
                "0000000000000800000000000000000000000000000000000000000000000000",
                "ffffffffffff0700000000000000000000000000000000000000000000000000",
                "ffffffffffff0f00000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "000000000000f8ffffffffff3f00000000000000000000000000000000000000",
                "0000000000000000000000004000000000000000000000000000000000000000",
                "f5ffffffffffffffffffffffffffffffffffffffffffffffffafa1bc86f21a4a",
            ),
            (
                "0c334a24bd8eebdadb23009d51d85b68cac2313271f89e954cf49addd217f568",
                "af619dbf381838420fb412c1f92a5b472f7479241a76739dbafd27ccb84bc352",
                "ce94e7e3f5a6231debd7125e4b03b7aff936ab568b6e123307f2c2a98b63b83b",
                "5dd1ac648476b398cc6feddb57ad00219b4eb80d57822bf891f672111acc3116",
                "275f3fa15a378c045f68c3a50f8d49611247f74ee490fff70ed90d3ca68c4b50",
                "759f87c4c19f24841905ac65201881b8fc7fa3c54ba6f39cde2424288e19fb56",
                "957bdf2c5b25f3f882fbd2dc0203535aa9b9ac1ee8560e8588c4cc9f1d5a0a20",
            ),
            (
                "ddbd826ba4cb02a49ea3177bcd80754f86b26f9db945b0c8a7e051c350066567",
                "17d753354a9e3b48a6f6431aa52d0491bf88f2567c8e38cd44f5b13fd1d9be32",
                "0795d6a0ee693eec449a5b9572ae79e0453b62f435d4e895ecd5030322e0231a",
                "c6e62e365a2dc75bf8acd360285371bec6297d463db777fb62eb9f837f2ca634",
                "66243132fc5c71903749556b49771d447b23db7f0e76e14db7114c07fab6053b",
                "17bd5b1120df68babbcf9349e89eab21e74ea2d26be3da0d0b2a405878a97050",
                "a192e941b9c8b2d20381690ac614249c4b1eb8742b5fc6c0b8cae737665dd638",
            ),
            (
                "c8f34d58537f98380fe3b6e06e4774bb2195216838c87494347b11a2fdfa8451",
                "e515da188987bf3cda35ec5fdf6c6632a66040cb07567e1af79a9a356665b212",
                "ad092871dc065875e918a3404eb4daedc7f56133401ef3ae2b16acd763603764",
                "e3dd733fcaf7d8fb34adca808fda0d897b34e19c3072f6793de0766c9795d23e",
                "d78ee1c6050230d502bfc5b1c7071ff261c4371b09e44c09347698f2dffd246f",
                "35b0cca69b9a508f7a42d9ce77472d714cf1204af7654a9c1ca45eebe2869c33",
                "8e4d78525937bf45c6d07d1681d41f22a67c78216eabc785c796df53c749f858",
            ),
            (
                "ad9af299141301f9ae34be655f52686528b626740e981ce60499fe9e85509879",
                "15c05a7559228ba8cc5624ecef9d45f0c6d1b5a3c20d6d6f7454dbed5ae26c6b",
                "d55a4d0f6e358ca17b8be2514ff0ad55ef87dc17d1a5895579edd98ce0320565",
                "98da9724bbf07550e2dd99796fb4227561e470d04b8aaf76904423b12a6e2b0e",
                "852e13c8c74257c0d8dac23562858040b55c4257a3626b827d35f2e3e1d9ef75",
                "a68eae26e3673f7d94fb59fb8b8a48925de00ef7f6207ccf860a64f984482140",
                "7f127b38664a53ca4d5ca079bcf4e157e820b8f056d2f475f65e6caf77455c18",
            ),
            (
                "4d573d5540163839c1aad3d03b786c0e8a0500581877289930bb88cbd1225a71",
                "e41528e49adef41cfd411a1d108b143df754414f4c33870b44f2a3a2adb7a713",
                "446d6539dbf42c56beeceded4b03814b815a41a764aaafa474ad2c6e7fda0105",
                "69411571a537431cc468b9b32bed57d192b0be08cc43a18decc8e428246bb25d",
                "80d825fe61a0672d24652653e1cff13145caa86f44a30cd1f8635863f6d45339",
                "48f286c424566319cbc99a79a1dddcbccfe93ffa1154cb9c3e13e7a4c6c60707",
                "fada34c20912913fd7f1a6938f7b1bc4043b94b55d08e6d293b6aeb0bd3de546",
            ),
            (
                "af619dbf381838420fb412c1f92a5b472f7479241a76739dbafd27ccb84bc352",
                "98350778dd2d1e39a416b0ebe3aafe9f2258c49c48712a551dc64462f05f9a78",
                "5a97a4371646567bb3cac2acddd559e751cc3dc162e79df2d7c36c2ea9ab5d4b",
                "042c96475bea19096b9d62d515805ca70c1cb587d10449489d37e369c8eb285a",
                "d064b1271de87c00f8c6a64b0d9fce8b4ce57afba1c9d3976c90b7061d074631",
                "c7b7e62caa6b137579a3cc6262f774b466008d307f34fd42f8d3dfc0c8685232",
                "ff7b66bb82567db31d44091a90898d9655c31985666f8e403b73fb7481c3a714",
            ),
            (
                "3a6d063ebafce90cda2d955ffc4d2540668cb8a06f9790bee9ca0f9a2258b263",
                "e49aba44e5418d4c95321c104a88f177cbe147209273b8395659d54ad476f157",
                "3108c1829f3e77596f60b16f46d616b8316e00c1010b49f83f24e5e4f6cea33b",
                "56d24bf9d4ba5cc044fb784fb2c533c89aaa7080dd23d88493713a4f4ee1c00b",
                "3d0ef6ed354c4caea5d87e245416ec59c05e8c03f805f7fd7bec62c9e2fa4b49",
                "fd5e787c1d45c0521074b1474874ecdf7e6862c4b657b0fafaa61e20ac82590b",
                "d2f2bbf754adbd1dd9ff4f1401f8b59d10a270f195b177076463787675070860",
            ),
            (
                "269237aa66e0500d4b17d2318887891c4e3754635a7292516350015a33f36c66",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "279237aa66e0500d4b17d2318887891c4e3754635a7292516350015a33f36c66",
                "259237aa66e0500d4b17d2318887891c4e3754635a7292516350015a33f36c66",
                "269237aa66e0500d4b17d2318887891c4e3754635a7292516350015a33f36c66",
                "8f412cb4b387a80294a008362b53ce41ab5d908a6c3b2984eee8a89137c9d643",
                "189afa7f743bc80bde7310e30bb3361a78eec21242ea74593211ec14373e5e1d",
            ),
            (
                "f70c5047eeace6c38bec9bad51cdcb3c42d0c0ab3248a5ea9ac8c164743da20d",
                "0000000000000000000000000000000000000000000000000010000000000000",
                "f70c5047eeace6c38bec9bad51cdcb3c42d0c0ab3248a5ea9ad8c164743da20d",
                "f70c5047eeace6c38bec9bad51cdcb3c42d0c0ab3248a5ea9ab8c164743da20d",
                "34f1cb5152fca10764509deee957788b48ed6f3c4c6ff4516190cf0075e4ce6a",
                "cfba20d86348ea016c055a3aa2cf38151f68a0e4e41fa22b8f2ae62801088809",
                "9c6ce4149d51252f4893f17e5eb2744ff2149c88a07ce032782682e456ffcb3d",
            ),
            (
                "b6c0c3c55a59c10a748d736f827ce53bff4044d3ac5a28b2923ef7d39bddbc69",
                "4d573d5540163839c1aad3d03b786c0e8a0500581877289930bb88cbd1225a71",
                "1618011b9b6ff94335384740bef4514a8946442bc5d1504bc3f97f9f6d00175b",
                "566986701a4389d1b2e29f9e4604792d753b447b94e3ff1862836e08caba6278",
                "272bb66efc91aac133ffcf80dd09261205931c1ade3dbd0563f7dbbb07e7215f",
                "3ebfb3461fe24bead3571b471e26196cdcbcbab49c37aa45eaafcaa751371622",
                "6d7dc840935225ae9a8feb2670bc74eb034134456f8c3fc577312e47178d2905",
            ),
            (
                "3045ec38c3a2bc21bc9f0bfaf689c18118190c35171e93dcbf860f72a2859f6b",
                "6bdd23d9665826024968590c98b6044318d8e3d283540c93a8e98ad3895d843a",
                "ae2210122afbe223050865068f40c6c430f1ef079b729f6f68709a452ce32326",
                "c567c85f5c4a961f7337b2ed5ed3bc3e0041286293c98649179d849e18281b31",
                "07ef82ac413a1ed906dd54933689bf23dfad71566317c182a7bb98df17b13237",
                "0ae56360c3abc9a9f68b1857a8132691a3804937db608e9f9c8365a21a999020",
                "87f133dd614d939f7c202a29003983bb7451abe0c4128bf2b4520d7e7fba2e40",
            ),
            (
                "6bdd23d9665826024968590c98b6044318d8e3d283540c93a8e98ad3895d843a",
                "6db36a86458237702c16b3ee980857d897748b1ba77c8ba3ace45b3468257c54",
                "eb908e5facda5d72757e0cfb30bf5b1bb04c6fee2ad1973655cee607f282000f",
                "eb29b95221d6ee911c52a61dffadad6a806358b7dcd780effb042f9f21380866",
                "cc2f3aebf8ab320498660ed850fdcb810b563a88dde4cec2f2664ddb2d65496e",
                "9626f0665f9c58e593c5f1dbd55ad09f13924987c2432081af2644abac45ae09",
                "1e120584d3ab88f0b71a4222d5b03caaeb82ab3747c7d9977d70073d03b57e1f",
            ),
            (
                "17d753354a9e3b48a6f6431aa52d0491bf88f2567c8e38cd44f5b13fd1d9be32",
                "5f1cba56fa35a993347141543fa3b979a68ea9cc4e66d9898d005a67c1453675",
                "89f30d8c44d4e4dbda67856ee4d0bd0a66179c23cbf41157d2f50ba7921ff527",
                "a5ba99de4f6892b4718502c6658a4a1719fa488a2d285f43b7f457d80f94883d",
                "0f411657f5c52ea653ae4108b9abc5b255fb8751d6c94c153b3fd42d5cf7fa28",
                "afc37238619a9cacbc4cf4410485ee3ec30d52ffbda2f07ef922a883d779024c",
                "2f858b6bfddf29e890370995aeab7565412fe641acfbc6340892a5dc22842d26",
            ),
            (
                "ff58b61bba8c7fc3cd5d98942ee8803f2fbb7efe65420250d58b1ddca7cf0a2c",
                "e67d64b77b45c0ff4c9318d8863775b2d5c81f1d01ddadb4d17a1bcf34180760",
                "f8d61ad335d23fc31af1b06cb51ff6f104849e1b671fb004a70639abdce7110c",
                "06db51643e47bfc380ca7fbca7b00b8d59f25ee16465549b0311020d73b7034c",
                "a4a38389536732b5bfac91ecbf34370ec9e3fef2a3cf4f87baa831b7fe6a8f48",
                "2645a667e931ea5722e7f9f7779b8551fa53758b4989bad5d7536a033b458d71",
                "7e5c387a6936c91d69b8f98fdd800418b531f2c92fdc6c2057b70c399ddcc30f",
            ),
            (
                "36eeb5471012eea8c5d298210f8dad5a4d4bf673cd8fec0ff78f9b333790975e",
                "3b3a3a1901da50bb2a351d6ae5c1e3f522ae4d3abe084c9b4b7b51ea2c8f177b",
                "8428f06011ec3e64f007b68bf44e915070f943ae8b9838ab420bed1d641faf59",
                "e8b37b2e0f389ded9a9d7bb729cbc9642a9da8390f87a074ab144a490a018063",
                "b7d0beeb6db37fa9e999a97e37cac45ca73cf64204962cd1ce75423f42a63b58",
                "889fecd61313a02aab788cc09bb6c7b3a7bf771588bf9bfeb19f56cb5731cc06",
                "c8c1e94bf587ddf9c67a2f0784abfe1cabc1df1c8f18b7ac8f3fab849a387b00",
            ),
            (
                "5c7d0ee355f4bc4fd8b1e0ef0911fc7ad2c11baa18928434aa516a3278152d70",
                "0409c83197dd60b85e89f80694856db4ed569f527d7a25ecc4d129b77ad6c338",
                "7386d614edd11d08373bd9f69d96692fc018bbfc950caa206f2394e9f2ebf028",
                "587446b1be165c977928e8e8758b8ec6e46a7c579b175f48e57f407bfd3e6937",
                "b4ca0742483cc2f7923fa7e92cc6c2be037c0246bd3a2a29c2b85a7e59a0e54f",
                "6528fd9ffd7d2067aee0b88e344c68db361f55bbe351cea44a55d79f31a23363",
                "17c8ee9272150a0be1190e4ba4fdc90b8b239fe3dfbbc2f3f6749305b6189311",
            ),
            (
                "12d51aa9571a03b843530af5a85df5f73fb121848c6e7af6ecffd0f353f94132",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "12d51aa9571a03b843530af5a85df5f73fb121848c6e7af6ecffd0f353f94132",
                "12d51aa9571a03b843530af5a85df5f73fb121848c6e7af6ecffd0f353f94132",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "92ff5ddc2832dd2ae3cc9ed07a315ce9998fe93d889fa0b7af3e6f408f836347",
                "41526f04ddf3df9a038ee073cb96a7698ad3d71c930e2f90ca6585b1ec7a8477",
            ),
            (
                "56aabda9c1e1fb0697b5b2a99538c8e6d6ddb5f1924a7d29fde0a292748dd652",
                "0000000000000000000000000000000000000000000000000000000000000008",
                "56aabda9c1e1fb0697b5b2a99538c8e6d6ddb5f1924a7d29fde0a292748dd65a",
                "56aabda9c1e1fb0697b5b2a99538c8e6d6ddb5f1924a7d29fde0a292748dd64a",
                "523a91f9151c4b58a33784b931c30d326ff7077f8ec844a12c6b216efac75e12",
                "5bd42fc22aad2d8e65103e1ffd3acb0aad062fcc98b61bdc12564c3956dfba0f",
                "a8599255387fa97f085e278ec6c3e399880dfe8909a2c251b8efe3f14c6a4b64",
            ),
            (
                "6db36a86458237702c16b3ee980857d897748b1ba77c8ba3ace45b3468257c54",
                "ad9af299141301f9ae34be655f52686528b626740e981ce60499fe9e85509879",
                "2d4e5d205a953869db4a7154f85abf3dc02ab28fb514a889b17d5ad3ed75144e",
                "ad1878ec306f36777de1f48839b6ee726fbe64a798e46ebda74b5d95e2d4e35a",
                "9c05fe6f494771df60c31f31dd553fff7c7af407d251a223010ca136b6073f02",
                "6707a5d16b89590ef825ad1d0f0df6449cf9e6344b7ba29a63c1886d9b29550e",
                "9ca78ce3c186a720f399f62eddd0dd1a4d84af20522b052bfa9140e83b015977",
            ),
            (
                "e515da188987bf3cda35ec5fdf6c6632a66040cb07567e1af79a9a356665b212",
                "3045ec38c3a2bc21bc9f0bfaf689c18118190c35171e93dcbf860f72a2859f6b",
                "155bc6514c2a7c5e96d5f759d6f627b4be794c001f7411f7b621aaa708eb517e",
                "a2d0eddfc5e4021b1e96e065e8e2a4b08d473496f037eb3d37148bc3c3df1227",
                "c812cb1a4be6a37c8a0c06e252b5131d10cc61c0a357367f3865f61e06bf9d47",
                "adf2a19fc2a964a8f112fb7e3a27ca034a51702bd3aebf4e9f2ff905c255ca6f",
                "d7822520e89dd497ddbd99b81d1010a6b883460497d22d5fecf9ec99fd851508",
            ),
            (
                "70f0a0f0d80b8344169c005780be105ebf78c4e808333dd4c58869cbf8f5dc44",
                "56aabda9c1e1fb0697b5b2a99538c8e6d6ddb5f1924a7d29fde0a292748dd652",
                "d99a5e9a9aed7e4bad51b30016f7d84496567ada9b7dbafdc2690c5e6d83b317",
                "0746e346172a873d7fe64dadea854877e89a0ef775e8bfaac8a7c63884680672",
                "11e36a3ad039ae5a55dd5ad3d68c921c52f8285c75f93e3a360309c6beb69c37",
                "2b4f36e5fbefec29343a187a39bacd9f019f22842df956667a65a7af6213f82e",
                "636bf7e38d7b666da692e49bd1d525bd891567d6bfcc2da4d7b663bd49b0eb78",
            ),
            (
                "1ef910de4be162b1f8a85e2240226d067906a421a581c9343ffa3e841475312f",
                "aaed5e4b822280922e6f4946942c73f6497384cd22e4bb81d67fbc8676714448",
                "c8e66f29ce03e3432718a868d44ee0fcc27928efc76585b6157afb0a8be67577",
                "610bb292c9bee21eca3915dcabf5f90f2f931f54829d0db3687a82fd9d03ed66",
                "34b94b4d03f4079a1fd282e08c46753e3777ff1b7c54e0ade0bb5c5656a83713",
                "588dc9f57c137765c6821175bf574a5adc91868c3857953ff2075612f546c45d",
                "05d3c927042082bd4ccde5a939be55569a467f1e61181d04f46961bc3254c973",
            ),
            (
                "02069bd9f321b84a023f1a4bd87658187e730c9e5870f83f3278d1422a195b72",
                "8d52a6f870a99191303817a0a959a05072a03309670c13406315102cabc8826a",
                "a25841d264cb49dc327731eb81d0f868f01340a7bf7c0b80958de16ed5e1dd5c",
                "75b3f4e0827826b9d10603ab2e1db8c70bd3d894f163e5ffce62c1167f50d807",
                "6c0c9cdf32d3f48900717c4caba20b687596ff8036fb8cf80129a175c91a651a",
                "c1cd68d2becd8780b952d354d38295a4ce00bc24a08d18046af240ad96934930",
                "12a172e73e61abf6d401d334af8bffa3398fc9b2c64ea40383d653a1f69cd250",
            ),
            (
                "0c3f7cc0dddaf5839e6112e6ae13b421cd1ce4039aeaf1522b982b822aa4ec47",
                "427bec2cf5ddb017a6f365636e608571e552f2da369541e3718d7f860a197f6b",
                "61ba68edd2b8a69b445578491d743993b26fd6ded07f33369d25ab0835bd6b33",
                "b7c38f93e8fc446cf86dac8240b32eb0e7c9f1286355b06fb90aacfb1f8b6d5c",
                "9d847e433928329e0eb71f42e979835c2c5395bae0198db90d26264940e6ea0d",
                "5f0a0f93aae229291568210f5f4ca4281f9592392392d7a82751db50bc55af13",
                "db22c530e4033646673b4aa547e5011fa275bbd4491656ac8064e95efe13632d",
            ),
            (
                "aaed5e4b822280922e6f4946942c73f6497384cd22e4bb81d67fbc8676714448",
                "9849a6bbaf29de09cb40add526b2836f9f7d55a1524a7967f8adcaf104ab5b76",
                "55370507324c5e9cf9aff61bbbdef665e9f0d96e752e35e9ce2d87787b1ca03e",
                "ffa3b88fd2f8a188632e9c706d7aef86aaf52e2cd099421aded1f19471c6e851",
                "749f43226476529124ec1ced6d74417fd4578e66b7cd3ef9da8a80a5209a2218",
                "89324a230153c37906d8e9239372e8907b2aafa12101f673bead35f87cda4d17",
                "bcbc6291ae6fefc09f13992d90f6827f28ab6b42a2575e3a25994edad4e10e3e",
            ),
            (
                "5f1cba56fa35a993347141543fa3b979a68ea9cc4e66d9898d005a67c1453675",
                "0b296a3a79cedb5b2e1db0c23b5f3cf60a3ab4f7d34a95e1a657a986f7896d5d",
                "7d452491730485ef628ef1167b02f66fb1c85dc422b16e6b345803eeb8cfa352",
                "54f34f1c8167cd370654919103447d839b54f5d47a1b44a8e6a8b0e0c9bbc817",
                "2e44dd8122d7a873037fdc4a49709143c3b20bdcc53bd5b46fd27a4bc9e08a3c",
                "e109b6342dce7d76e29f7cd4b2d931574b4acd5cc9d3ad4ba273476489dc6b1a",
                "869852cfd60fde4a1b0b36f679a0044c621d0020cd55dedbbf22b10daf7a4f0c",
            ),
            (
                "15c05a7559228ba8cc5624ecef9d45f0c6d1b5a3c20d6d6f7454dbed5ae26c6b",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "14c05a7559228ba8cc5624ecef9d45f0c6d1b5a3c20d6d6f7454dbed5ae26c6b",
                "16c05a7559228ba8cc5624ecef9d45f0c6d1b5a3c20d6d6f7454dbed5ae26c6b",
                "d83fa58aa6dd745733a9db131062ba0f392e4a5c3df292908bab2412a51d9314",
                "86270ec15154652bf495447f4bd512420af15ae6b8fdfa4b832c92d42fd10916",
                "1b4aa766ee18fd32dc9e0b49144977bd5482a185cb5c4c74062588dc6add212c",
            ),
            (
                "130325451463d43862989eb33731edc64742fdc9b3d40c86f36f4135c85b074d",
                "c8f34d58537f98380fe3b6e06e4774bb2195216838c87494347b11a2fdfa8451",
                "eef6729d67e26c71717b5594a678618269d71e32ec9c811a28eb52d7c5568c1e",
                "380fd7ecc0e33b0053b5e7d2c8e9780b26addb617b0c98f1bef42f93ca60827b",
                "df2feab81334c884c790c3ad1e4fe7d1bcff3e7bf9f12d4fe21bc2cf6408d03b",
                "09594ef7e5f74be6995b48037971eb02c65aaeb4f0ff9751c17839f69bf96522",
                "351394938e85283b29680c348f2becdc0664d031956d5d984586f220b42c8376",
            ),
            (
                "7e4c8042a9088038f25ae2403a13e9297400e2d32f74f1c5e1f92cb1ec14b451",
                "b6c0c3c55a59c10a748d736f827ce53bff4044d3ac5a28b2923ef7d39bddbc69",
                "470d44080462414366e855b0bc8fce65734126a7dcce19787438248588f2703b",
                "b58bbc7c4eafbe2d7ecd6ed1b79603ee74bf9d008319c9134fbb35dd5037f767",
                "e21fb76ea0a8865659574d3319a57153f247f6a3b87282699db738b2acab4422",
                "d0754aca08d084ae65f29b95da537973ec5a5942cc38d02a4d8f7d0944a11237",
                "c57ca2bd393892b01699e74c46d531405d6dc77fd901503c4f7df8706c06ee0b",
            ),
            (
                "db3498dde8fef5f8608f7859f97a11b0dabba961df51ebd1c97b07dc8c818861",
                "12d51aa9571a03b843530af5a85df5f73fb121848c6e7af6ecffd0f353f94132",
                "000ab3864019f9b0a4e2824ea2d806a81a6dcbe56bc065c8b67bd8cfe07aca13",
                "c95f7d3491e4f2401d3c6e64501d1cb89a0a88dd52e370dbdc7b36e83888462f",
                "4a6ecac1599e0d6e22ba6b5954fe0612ad59fb136fe18221b6d2cc8abc533c16",
                "fe1b3c08d854c238a61351fe90f65a9f9fc9bd10cf6d9f4237ae5684c3352d5a",
                "08a5d2e0a301d7d29a8455d9fff0c630b43b07bee6d50f7ce3642b753989b809",
            ),
            (
                "ca015361e6b438580312c60d9ac000b6b894dcfd208504a078315f838362af03",
                "0c3f7cc0dddaf5839e6112e6ae13b421cd1ce4039aeaf1522b982b822aa4ec47",
                "d640cf21c48f2edca173d8f348d4b4d785b1c001bb6ff6f2a3c98a05ae069c4b",
                "abc2d6a008da42d464b0b327ebac4c94eb77f8f9869a124d4d99330159bec23b",
                "88d503759c45111b2cfd3394eb9b9d5f98705863462fcffa41bb3127946fb25e",
                "5e70fb5abcd3e473bb197bd2be7a8f9353b08895395c0d86d228b189bc584e55",
                "fac99a70eee58e252f36195349690f26104e93510a3c49c78c9acd73a16bb036",
            ),
            (
                "8d52a6f870a99191303817a0a959a05072a03309670c13406315102cabc8826a",
                "ca015361e6b438580312c60d9ac000b6b894dcfd208504a078315f838362af03",
                "5754f959575ecae9334addad431aa1062b351007889117e0db466faf2e2b326e",
                "c35053978af458392d2651920f999f9ab90b570b46870ea0eae3b0a82766d366",
                "66a686efba006cd9be6e4961331ec9a6ce0bef2e0d339a3d1e9b4b31d1b38148",
                "d3aee786c9fe4d647d719b00fc5184beb41a1911c3d06dc974010aec5e15785d",
                "ea1f43acccc17b627d2176754daeae79cd06926947b0e167c0f1e04cc1393c28",
            ),
            (
                "e67d64b77b45c0ff4c9318d8863775b2d5c81f1d01ddadb4d17a1bcf34180760",
                "1b133526963b8b5efc38a787c9b76574f7db47528ab6ce6f2f8ec764090c9728",
                "149199dd11814b5e49ccbf5f50efda26cda4676f8b937c240109e3333e249e08",
                "cb6a2f91e50935a1505a7150bd7f0f3edeecd7ca7626df44a2ec536a2b0c7037",
                "4ff14eb306471d2e6d27856f8d9c21ffc51cacc869dc126846429af313ce762b",
                "6f53b11707c2fe3067b3c144241309e679a307ea3309f8594e6ae7b9636ab73e",
                "5ff49d6219087d09d5006df7e492062da430cb9780a0c824678c4bcc7ea5c91d",
            ),
            (
                "e41528e49adef41cfd411a1d108b143df754414f4c33870b44f2a3a2adb7a713",
                "04cb61b3fbc71a27db8f1a247366c9aa6763fe4fe7aa44adf9128b206e46d926",
                "e8e0899796a60f44d8d1344183f1dde75eb83f9f33decbb83d052fc31bfe803a",
                "cd4ac6309f16daf521b2fff89c244b928ff142ff6488425e4adf18823f71ce6c",
                "ac9292f3b3562b96e67437e2f4520b183ff18e14a5fe1898cd115e51bdfd343b",
                "5c78224a899f1ee4b3531661eb205a60463134488edbb8ad666d3c806c973036",
                "993e369f4a1d5695aa46b898a3cb09c1a994cfa8d27c7884fc87ed90f6392528",
            ),
            (
                "fb8eeff9a5a364f95bbcd0d1462e4480a0be21c9445440b5b4c2478c9cf3544a",
                "2ed4312348807345e6f64c9947d5ae36ce9811d33320e949e2c5c14f36f8540d",
                "2963211dee23d83e42b31d6b8e03f3b66e57339c787429ff968809dcd2eba957",
                "cdbabdd65d23f1b375c58338ff589549d22510f61034576bd2fc853c66fbff3c",
                "8eaf235db01130f5cf31c655eab4f16cdd603d8bd5c951c29a050f830fe7b33e",
                "bc112c347dfb6fe01128275b991a548801489485d955903b2382b1a0b8185234",
                "b1be186c29049edb85f11f510db156abe10b8aed784533b49cecf3ccfd758573",
            ),
            (
                "7ab68a89d5dd37915a356b8b2c9a8bd8f7bf19314b3402cf617b5e41477d327a",
                "1300000000000000000000000000000000000000000000000000000000000000",
                "8db68a89d5dd37915a356b8b2c9a8bd8f7bf19314b3402cf617b5e41477d327a",
                "67b68a89d5dd37915a356b8b2c9a8bd8f7bf19314b3402cf617b5e41477d327a",
                "648c4b35d97625c7b8f5f4584e715c12653fe9a494e1295d422803da494cbf11",
                "63390616fe3b67220469e74f5c48609f66f6b735b54fbd30a208e899590be626",
                "2b8678e1c7c693f5f8a48b82ec615288006de79f5108848f844700c45f637e49",
            ),
            (
                "fc947cd76024969ee9b25f1f5743c43070c3e961a5ef2361eba4a7cc758a512b",
                "ddbd826ba4cb02a49ea3177bcd80754f86b26f9db945b0c8a7e051c350066567",
                "ec52ff4205f098428856779a24c43980f67559ff5e35d4299385f98fc690b612",
                "0cd7f96bbc5893fa4a0f48a489c24ee1e9107ac4eba9739843c455092584ec43",
                "3614fc7ddd004db535daf43ae384505032f162a5ed874b1cc7717ab9bb58d20e",
                "546f02f5b5558141ba20968559085fc46ad4ca6a8f72a7c84c8a3e991ba80208",
                "09ec54019b30c9ec079864478bd15159efd9dc31e5dda026e7a9ee90b480f518",
            ),
            (
                "1b133526963b8b5efc38a787c9b76574f7db47528ab6ce6f2f8ec764090c9728",
                "f70c5047eeace6c38bec9bad51cdcb3c42d0c0ab3248a5ea9ac8c164743da20d",
                "1220856d84e87122882543351b8531b139ac08febcfe735aca5689c97d493936",
                "2406e5dea78ea49a704c0bda77ea9937b50b87a6576e298594c5050095cef41a",
                "b035acbaa1288e6297c18f32bb5eee6229a1b2fe1c4d62100cc903534167a00a",
                "8dbb85b77cfd1c97524fb4150314a0e143abba4f1b0e880eb7ee4642e9713f32",
                "2084d0821d4d2798bb43fcd2cb8dd848a4ca6f7e6b721a9056d42b5257efc51d",
            ),
            (
                "427bec2cf5ddb017a6f365636e608571e552f2da369541e3718d7f860a197f6b",
                "5c7d0ee355f4bc4fd8b1e0ef0911fc7ad2c11baa18928434aa516a3278152d70",
                "b1f8fa0f4bd26d677ea54653787181ecb7140e854f27c6171cdfe9b8822eac5b",
                "d3fddd499fe9f3c7cd418573644f89f61291d6301e03bdaec73b15549203527b",
                "8d5f72096dd08f5eafc06b1fc9b83c314b88219754834a46923690e3a4e3c333",
                "068fa5330ad3160e5238d93df32e3fed22c581e4c4c261ae794f283da308f373",
                "a066e17fecb2447f29bc986c2c141ef9070f2e41af445a14912c0ef8baa21c2b",
            ),
            (
                "3b3a3a1901da50bb2a351d6ae5c1e3f522ae4d3abe084c9b4b7b51ea2c8f177b",
                "02069bd9f321b84a023f1a4bd87658187e730c9e5870f83f3278d1422a195b72",
                "5040d5f2f4fb08062d7437b5bd383c0ea1215ad8167944db7df3222d57a8726d",
                "39349f3f0db8987028f6021f0d4b8bdda43a419c6598535b190380a70276bc08",
                "c063e5d1336c112cbb1da80b5c71c0ddc0b1aefc8030ce78a93d3f1f2ffa225a",
                "61026e62d43d6f98a4fb84b2a83838391dd0b4420e2a5b03fe9480b7bc9ea42b",
                "cd7fd09db9686bb619c4483162f0df31b87b4c14cea3268b8fb3da2aca48b51b",
            ),
            (
                "98350778dd2d1e39a416b0ebe3aafe9f2258c49c48712a551dc64462f05f9a78",
                "db3498dde8fef5f8608f7859f97a11b0dabba961df51ebd1c97b07dc8c818861",
                "866a9f55c62c143205a62845dd251050fd136efe27c31527e7414c3e7de1225a",
                "bd006f9af42e284043873792ea2fedef479c1a3b691f3f83534a3d8663de1117",
                "ac8616e6b968c8417e3f56a0f94caf82a1d4c6f3862f7f7579ab480505faa96e",
                "1a36c49d7e156c6f5ac385b3b1aa9e89330cc6f6e077777e5eb6cd769e67c54e",
                "4c21a55ece9344adb29d61bc2075d3e706873bbe5bc79c4da1d53ff82effb06b",
            ),
            (
                "8b8de348f5b9e76f4d9b55844a652f6eaca901b0c249f6dbd0f74f77ec95ea60",
                "fc947cd76024969ee9b25f1f5743c43070c3e961a5ef2361eba4a7cc758a512b",
                "9a22602056de7d0e374eb5a3a1a8f39e1c6deb1168391a3dbc9cf74362203c0c",
                "8ff86671949551d163e8f564f3216b3d3ce6174e1d5ad27ae552a8aa760b9935",
                "1a84d2bdd5ad9be24b4bf20c1e594139156252694de1e9b810faa585d0a4603a",
                "0e9e11f51434c60ad6cf19495eb7735f898b93fe5962c2e4d1c4a5358b803579",
                "6201739bf2e513f2eab7c45984a923a8db07ceba9e64907b6220b0536e71ca1c",
            ),
            (
                "6e4f9338962272cc6fdbda6836bf98b824b9fbccbf8713fe2114083d68e4ba44",
                "ce501eca2a30b402e2d099c80dcda21cf4d3bbede1c49e3b20de120c02dc671e",
                "3ca0b102c15226cf51ac7431448c3bd5188db7baa14cb23942f21a496ac02263",
                "a0fe746e6bf2bdc98d0a41a028f2f59b30e53fdfddc274c20136f53066085326",
                "015b09a02580bfa4e5fcf2c52fb7f3fe3360729f524cbf611c1404b46044bd64",
                "61396c68a59ba61cabac6143ec7df6b5d761b4d6f6be60175d0181b67ab1ee57",
                "7209ec57e2137c362afdc94f5951bc4c783c02fda5cb5985167edc242e120b6a",
            ),
            (
                "ce501eca2a30b402e2d099c80dcda21cf4d3bbede1c49e3b20de120c02dc671e",
                "35fd12a1730baafb6c4c0be61f346dc1a2e85dc0670d36bcd3762b01dfc4b856",
                "034e316b9e3b5efe4e1da5ae2d0110de96bc19ae49d2d4f7f3543e0de1a02075",
                "86530b29b7240a0775848ee2ed98355b51eb5d2d7ab7687f4c67e70a2317af47",
                "01a932ed3bc196453d9b13cb6085cfc9715e13c4759b0ea5ccf6085e1b41802a",
                "06262e9a149467a0d01b1074268ad5a4ff9c0e4e0699f92369038120c63b7d4d",
                "6082944cc9e9e115a5865eb0f872df8b5de5f1a4c5b4be9e1c10eadc6a73ba25",
            ),
            (
                "04cb61b3fbc71a27db8f1a247366c9aa6763fe4fe7aa44adf9128b206e46d926",
                "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "02cb61b3fbc71a27db8f1a247366c9aa6763fe4fe7aa44adf9128b206e46d926",
                "06cb61b3fbc71a27db8f1a247366c9aa6763fe4fe7aa44adf9128b206e46d926",
                "e5693c990870cab149e0cab719336daa3039036031aa76a50cdae9be23734d32",
                "252ba0b45f945858a685e19ffebfd32fb33a8229038cd1661d83ac82d61d8c5e",
                "0a81919e7334952eaca7ffbd467bbafb274dd988ede6a0c14cc738deb3091a2d",
            ),
            (
                "9849a6bbaf29de09cb40add526b2836f9f7d55a1524a7967f8adcaf104ab5b76",
                "0c334a24bd8eebdadb23009d51d85b68cac2313271f89e954cf49addd217f568",
                "b77cf0df6cb8c9e4a664ad72788adfd7694087d3c34218fd44a265cfd7c2505f",
                "8c165c97f29af22eef1cad38d5d92707d5ba236fe151dad1abb92f143293660d",
                "766ddc50ed0942d333e7cf4a105cf4ebb8df18c3bd5a6853517aa3d9fa7c3401",
                "d10358ed46c7537cf2a2e66676d6d20104417fa0728b8c9e93881a1b377b6c47",
                "85c727f3817849c79f9cdfd189bfddf409a73c219e8a8a4bf00b3362adcdf06e",
            ),
            (
                "0409c83197dd60b85e89f80694856db4ed569f527d7a25ecc4d129b77ad6c338",
                "269237aa66e0500d4b17d2318887891c4e3754635a7292516350015a33f36c66",
                "3d9bffdbfdbdb1c5a9a0ca381c0df7d03b8ef3b5d7ecb73d28222b11aec9301f",
                "cb76908730fd0fab137226d50bfee3979f1f4bef2208939a6181285d47e35652",
                "f4d8de78175ad420cb65aa6c6ed30f13b7e727a9e328ac0f0ae7599806615871",
                "e7bd3dcb30af4b582bb8be408c8a5471267a401074959e122a65e7363a9fe252",
                "21a7f8b4ade7293975abf27ebdb400e9e1df58507b9ae221e20dc2f3434b5606",
            ),
            (
                "e49aba44e5418d4c95321c104a88f177cbe147209273b8395659d54ad476f157",
                "36eeb5471012eea8c5d298210f8dad5a4d4bf673cd8fec0ff78f9b333790975e",
                "2d89708cf5537bf55a05b53159159fd2182d3e945f03a5494de9707e0b078936",
                "9bac04fdd42f9fa3cf5f83ee3afb431d7e9651acc4e3cb295fc939179de65979",
                "d05e1f704b5ee0bae1c2848cb19c0d0791bdd6f9238b982436eb06d70e9fe31c",
                "2df6a7d1d6b9f8f709bd3310c238b8615d986b8dea0ec3e5a4e534f16c936053",
                "22a158fa2f75d9f1578dc9f4a8b12352c20ab750759395eb57da8e1fa386d40e",
            ),
            (
                "f23eaeada33b93cfde61408e30a67c50a3d9efd4f07f63ee92ce0ac1033e4a50",
                "1ef910de4be162b1f8a85e2240226d067906a421a581c9343ffa3e841475312f",
                "1038bf8bef1cf680d70a9fb070c8e9561ce093f695012d23d2c8494518b37b7f",
                "d4459dcf575a301ee6b8e16bf0830f4a2ad34bb34bfe99b953d4cb3cefc81821",
                "ff3db1bfd6937567178f5f0dd23cc544975721811ef760718ff7bc662c16cd42",
                "4e5f46da68c677296e7875000399ebb1721f28ee36a2fa08715461b3c91b2040",
                "f0f89e3683762f487ea7509ff3617da65c632291ac0998bba9b6e891e31b8e74",
            ),
            (
                "313531b66acf6787785ba8c7a90e00b1672331be9f6424716dcd5a4e4ec7031a",
                "7e4c8042a9088038f25ae2403a13e9297400e2d32f74f1c5e1f92cb1ec14b451",
                "af81b1f813d8e7bf6ab68a08e421e9dadb231392cfd815374fc787ff3adcb76b",
                "a0e8b073c1c6e74e8600c6866ffb1687f3224fea6ff032ab8bd32d9d61b24f48",
                "4aaeba3f731e9a507d3a52cea7b278c59d74dd4f8f9a4814090d7b369358504f",
                "7096435a4d86b27c3537cbc0b43099f8f01ded897290478abc2dd86c938bc246",
                "a17721807115ab34bbc8b80d82302a2738a86dafb691cd395dae19183b909714",
            ),
            (
                "35fd12a1730baafb6c4c0be61f346dc1a2e85dc0670d36bcd3762b01dfc4b856",
                "7ab68a89d5dd37915a356b8b2c9a8bd8f7bf19314b3402cf617b5e41477d327a",
                "c2b39d2a49e9e18cc78176714ccef8999aa877f1b241388b35f289422642eb50",
                "a84688179e2d726a1217a05af399e1e8aa28448f1cd933ed71fbccbf9747865c",
                "e74df51e111982aa99c0e74ae63257cae53222708391dfbea369e9ec9f44163b",
                "6286c1b28b9b4261c262cafcaeeb559fbb5002d1b3a2f084d1a5b13eeb68d91d",
                "99541f7e00906d7c9988426171640c010867cd9a17c6a442226b7adcf4b31c27",
            ),
            (
                "2ed4312348807345e6f64c9947d5ae36ce9811d33320e949e2c5c14f36f8540d",
                "6e4f9338962272cc6fdbda6836bf98b824b9fbccbf8713fe2114083d68e4ba44",
                "9c23c55bdea2e51156d227027e9447eff2510da0f3a7fc4704dac98c9edc0f52",
                "ad849eeab15d0179761b72301116167ea9df15067498d54bc0b1b912ce139a48",
                "4116599341e160df4894318609880fb24e31f7d77ac0a6072841d5666e47190c",
                "6fd41987f9f05be6e751967b9e6c151ae88156f907634ff621be85ca0e0f4058",
                "d9827ffb6ae254e71a37bc63dee686008549f77c4b431e14558ea33c4c161065",
            ),
            (
                "0b296a3a79cedb5b2e1db0c23b5f3cf60a3ab4f7d34a95e1a657a986f7896d5d",
                "313531b66acf6787785ba8c7a90e00b1672331be9f6424716dcd5a4e4ec7031a",
                "3c5e9bf0e39d43e3a678588ae56d3ca7725de5b573afb952142504d545517177",
                "daf338840eff73d4b5c107fb91503c45a316833934e67070398a4e38a9c26943",
                "f0af0b8fb620ca1dae58800e4a1beaf77e674c5eb862b8ed96229420f4fef837",
                "0b2bc517dbd3fdd620e3159df4cc7572bcae4262e56d42f3da62d54bfc197f5d",
                "447b5b074bc6dd9551db4300f284f14d55426d139d82ed3ee2a85f5d75925d31",
            ),
        ];

        let fe = |h: &str| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&hex::decode(h).unwrap());
            Fe::from_bytes(&b)
        };

        for (i, (a, b, sum, diff, prod, sq, inv)) in VECTORS.iter().enumerate() {
            let (x, y) = (fe(a), fe(b));
            assert_eq!(hex::encode(x.to_bytes()), *a, "vector {i}: a round-trip");
            assert_eq!(hex::encode(y.to_bytes()), *b, "vector {i}: b round-trip");
            assert_eq!(hex::encode((x + y).to_bytes()), *sum, "vector {i}: a + b");
            assert_eq!(hex::encode((x - y).to_bytes()), *diff, "vector {i}: a - b");
            assert_eq!(hex::encode((x * y).to_bytes()), *prod, "vector {i}: a * b");
            assert_eq!(hex::encode(x.square().to_bytes()), *sq, "vector {i}: a^2");
            assert_eq!(hex::encode(x.invert().to_bytes()), *inv, "vector {i}: a^-1");
        }
    }

    /// The carry chain must survive repeated unreduced operations, which is
    /// where a lazy 5-limb implementation is most likely to drift.
    #[test]
    fn repeated_operations_do_not_drift() {
        let mut acc = Fe::ONE;
        let mut mul = Fe::ZERO - Fe::ONE; // p - 1, the largest canonical value
        for _ in 0..200 {
            // Each step mixes an add, a subtract and a multiply so limbs never
            // settle into a reduced shape.
            acc = (acc + mul) * (acc - mul) + Fe::ONE;
            mul = mul.square();
            // The canonical encoding must always be a fixed point.
            let bytes = acc.to_bytes();
            assert_eq!(Fe::from_bytes(&bytes).to_bytes(), bytes);
        }
        // ...and the result must still invert correctly.
        if acc.is_nonzero() {
            assert!(!(acc * acc.invert() - Fe::ONE).is_nonzero());
        }
    }

    #[test]
    fn divpowm1_lands_on_one_of_the_four_roots() {
        let i = sqrtm1();
        for k in 1u64..64 {
            for j in 1u64..4 {
                let u = small(k);
                let v = small(j);
                let s = divpowm1(u, v).square() * v;
                let hits = [
                    !(s - u).is_nonzero(),
                    !(s + u).is_nonzero(),
                    !(s - i * u).is_nonzero(),
                    !(s + i * u).is_nonzero(),
                ];
                assert!(
                    hits.iter().any(|h| *h),
                    "divpowm1({k}, {j}) landed outside {{+/-u, +/-i*u}}"
                );
            }
        }
    }

    /// The two loaders must agree exactly when bit 255 is clear, and differ by
    /// `19` when it is set -- `2^255 === 19 (mod p)`.
    #[test]
    fn masked_and_unmasked_loaders() {
        let mut b = [0x5au8; 32];
        b[31] = 0x5a; // bit 255 clear
        assert_eq!(
            Fe::from_bytes(&b).to_bytes(),
            Fe::from_bytes_unmasked(&b).to_bytes()
        );

        b[31] = 0xda; // same low 255 bits, bit 255 set
        let masked = Fe::from_bytes(&b);
        let unmasked = Fe::from_bytes_unmasked(&b);
        assert_ne!(masked.to_bytes(), unmasked.to_bytes());
        assert!(!(unmasked - masked - small(19)).is_nonzero());
    }
}
