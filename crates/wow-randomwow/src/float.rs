//! IEEE 754 arithmetic in all four rounding modes, without touching the FPU.
//!
//! RandomX's `CFROUND` switches the rounding mode, and every later `FADD`,
//! `FSUB`, `FMUL`, `FDIV` and `FSQRT` rounds that way (spec §4.3, §5.3). The
//! C++ sets the CPU's rounding mode. Rust cannot: the compiler assumes
//! round-to-nearest everywhere, so changing the mode under it is undefined.
//!
//! So each operation is done in round-to-nearest, which gives either the
//! floor or the ceiling of the exact result, and then moved one step when the
//! requested direction wants the other. Which way the exact result lies is
//! found exactly: TwoSum for addition, and a 128-bit integer comparison of
//! mantissas for multiplication, division and square root. The spec rules out
//! NaN and denormal results; overflow is handled anyway.

use std::cmp::Ordering;

/// The `fprc` register.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    #[default]
    Nearest,
    Down,
    Up,
    Zero,
}

impl Mode {
    pub(crate) fn from_bits(bits: u64) -> Mode {
        match bits & 3 {
            0 => Mode::Nearest,
            1 => Mode::Down,
            2 => Mode::Up,
            _ => Mode::Zero,
        }
    }
}

/// Move the nearest-rounded `r` to the directed result, given which side of
/// `r` the exact result lies on.
#[inline(always)]
fn direct(r: f64, exact_vs_r: Ordering, mode: Mode) -> f64 {
    match (mode, exact_vs_r) {
        (Mode::Up, Ordering::Greater) => r.next_up(),
        (Mode::Down, Ordering::Less) => r.next_down(),
        (Mode::Zero, Ordering::Less) if r > 0.0 => r.next_down(),
        (Mode::Zero, Ordering::Greater) if r < 0.0 => r.next_up(),
        _ => r,
    }
}

/// A finite result too large for a double: infinity only where the
/// direction allows it, the largest double otherwise.
fn overflow(r: f64, mode: Mode) -> f64 {
    match mode {
        Mode::Nearest => r,
        Mode::Up if r < 0.0 => -f64::MAX,
        Mode::Down if r > 0.0 => f64::MAX,
        Mode::Zero => f64::MAX.copysign(r),
        _ => r,
    }
}

/// `x = mantissa * 2^exponent` for a finite nonzero double's magnitude.
#[inline(always)]
fn parts(x: f64) -> (u64, i32) {
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32;
    let m = bits & ((1u64 << 52) - 1);
    if e == 0 {
        (m, -1074)
    } else {
        (m | (1u64 << 52), e - 1075)
    }
}

/// `|x * y|` against `|z|`, exactly, for finite nonzero operands.
#[inline(always)]
fn compare_product(x: f64, y: f64, z: f64) -> Ordering {
    let (mx, ex) = parts(x);
    let (my, ey) = parts(y);
    let (mz, ez) = parts(z);
    let p = u128::from(mx) * u128::from(my);
    let pe = ex + ey;
    let p_top = pe + (128 - p.leading_zeros() as i32);
    let z_top = ez + (64 - mz.leading_zeros() as i32);
    if p_top != z_top {
        return p_top.cmp(&z_top);
    }
    // The leading bits are at the same place, so aligning shifts neither
    // value past 106 bits.
    if pe >= ez {
        (p << (pe - ez)).cmp(&u128::from(mz))
    } else {
        p.cmp(&(u128::from(mz) << (ez - pe)))
    }
}

/// Which side of `r` a value lies on, from how its magnitude compares.
#[inline(always)]
fn side(r: f64, magnitude: Ordering) -> Ordering {
    if r > 0.0 {
        magnitude
    } else {
        magnitude.reverse()
    }
}

pub(crate) fn add(a: f64, b: f64, mode: Mode) -> f64 {
    let r = a + b;
    if mode == Mode::Nearest {
        return r;
    }
    if !r.is_finite() {
        return if a.is_finite() && b.is_finite() {
            overflow(r, mode)
        } else {
            r
        };
    }
    if r == 0.0 {
        // An exact zero from operands of opposite sign is -0 only when
        // rounding toward negative infinity.
        return if mode == Mode::Down && a.is_sign_negative() != b.is_sign_negative() {
            -0.0
        } else {
            r
        };
    }
    // TwoSum: `err` is exactly `(a + b) - r`.
    let bb = r - a;
    let err = (a - (r - bb)) + (b - bb);
    direct(r, err.partial_cmp(&0.0).unwrap_or(Ordering::Equal), mode)
}

pub(crate) fn sub(a: f64, b: f64, mode: Mode) -> f64 {
    add(a, -b, mode)
}

pub(crate) fn mul(a: f64, b: f64, mode: Mode) -> f64 {
    let r = a * b;
    if mode == Mode::Nearest {
        return r;
    }
    if !r.is_finite() {
        return if a.is_finite() && b.is_finite() {
            overflow(r, mode)
        } else {
            r
        };
    }
    if r == 0.0 {
        return r;
    }
    direct(r, side(r, compare_product(a, b, r)), mode)
}

pub(crate) fn div(a: f64, b: f64, mode: Mode) -> f64 {
    let r = a / b;
    if mode == Mode::Nearest {
        return r;
    }
    if !r.is_finite() {
        return if a.is_finite() && b.is_finite() && b != 0.0 {
            overflow(r, mode)
        } else {
            r
        };
    }
    if r == 0.0 {
        return r;
    }
    // |a/b| > |r| exactly when |r * b| < |a|.
    direct(r, side(r, compare_product(r, b, a).reverse()), mode)
}

pub(crate) fn sqrt(a: f64, mode: Mode) -> f64 {
    let r = a.sqrt();
    // Zero, a negative operand's NaN, and infinity are exact.
    if mode == Mode::Nearest || r.partial_cmp(&0.0) != Some(Ordering::Greater) || !r.is_finite() {
        return r;
    }
    // sqrt(a) > r exactly when r * r < a.
    direct(r, compare_product(r, r, a).reverse(), mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(lo: u64, hi: u64) -> (f64, f64) {
        (f64::from_bits(lo), f64::from_bits(hi))
    }

    /// The register the C++'s tests store, as its 16 little-endian bytes.
    fn hex(lo: f64, hi: f64) -> String {
        let mut s = String::new();
        for b in lo
            .to_bits()
            .to_le_bytes()
            .iter()
            .chain(&hi.to_bits().to_le_bytes())
        {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// `tests.cpp`, "FADD_R" in each mode.
    #[test]
    fn addition_rounds_as_the_reference() {
        let (f_lo, f_hi) = bits(0xc1ce30b3c4223576, 0x3ffd2c97cc4ef015);
        let (a_lo, a_hi) = bits(0x40b8f684057a59e1, 0x402a26a86a60c8fb);
        for (mode, want) in [
            (Mode::Nearest, "b932e048a730cec1fea6ea633bcc2d40"),
            (Mode::Down, "b932e048a730cec1fda6ea633bcc2d40"),
            (Mode::Up, "b832e048a730cec1fea6ea633bcc2d40"),
            (Mode::Zero, "b832e048a730cec1fda6ea633bcc2d40"),
        ] {
            assert_eq!(
                hex(add(f_lo, a_lo, mode), add(f_hi, a_hi, mode)),
                want,
                "{mode:?}"
            );
        }
    }

    /// `tests.cpp`, "FMUL_R".
    #[test]
    fn multiplication_rounds_as_the_reference() {
        let (e_lo, e_hi) = bits(0x40fdfdabb6173d07, 0x41dbc35cef248783);
        let (a_lo, a_hi) = bits(0x41c4561212ae2d50, 0x40eba861aa31c7c0);
        for (mode, want) in [
            (Mode::Nearest, "69697aff350fd3422f1589cdecfed742"),
            (Mode::Down, "69697aff350fd3422e1589cdecfed742"),
            (Mode::Zero, "69697aff350fd3422e1589cdecfed742"),
            (Mode::Up, "6a697aff350fd3422f1589cdecfed742"),
        ] {
            assert_eq!(
                hex(mul(e_lo, a_lo, mode), mul(e_hi, a_hi, mode)),
                want,
                "{mode:?}"
            );
        }
    }

    /// `tests.cpp`, "FSQRT_R".
    #[test]
    fn square_roots_round_as_the_reference() {
        let (lo, hi) = bits(0x40526a7e778d9824, 0x41b6b21c11affea7);
        for (mode, want) in [
            (Mode::Nearest, "e81f300b612a21408dbaa33f570ed340"),
            (Mode::Down, "e81f300b612a21408cbaa33f570ed340"),
            (Mode::Zero, "e81f300b612a21408cbaa33f570ed340"),
            (Mode::Up, "e91f300b612a21408dbaa33f570ed340"),
        ] {
            assert_eq!(hex(sqrt(lo, mode), sqrt(hi, mode)), want, "{mode:?}");
        }
    }

    /// The directed results bracket the exact one, a step apart at most.
    #[test]
    fn directed_results_bracket_the_exact_result() {
        let mut x = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Positive and negative values between about 2^-40 and 2^40.
            let m = x & ((1 << 52) - 1);
            let e = 1023 - 40 + (x >> 56) % 80;
            let s = (x >> 63) << 63;
            f64::from_bits(s | (e << 52) | m)
        };
        for _ in 0..20_000 {
            let (a, b) = (next(), next());
            for op in [add, mul, div] {
                let down = op(a, b, Mode::Down);
                let up = op(a, b, Mode::Up);
                let near = op(a, b, Mode::Nearest);
                let zero = op(a, b, Mode::Zero);
                assert!(down <= near && near <= up, "{a:e} {b:e}");
                assert!(up == down || up == down.next_up(), "{a:e} {b:e}");
                assert!(zero == if near > 0.0 { down } else { up }, "{a:e} {b:e}");
            }
            let a = a.abs();
            let (down, up) = (sqrt(a, Mode::Down), sqrt(a, Mode::Up));
            assert!(up == down || up == down.next_up());
        }
    }

    #[test]
    fn exact_zero_and_overflow_follow_ieee() {
        assert!(add(1.5, -1.5, Mode::Down).is_sign_negative());
        assert!(add(1.5, -1.5, Mode::Up).is_sign_positive());
        assert_eq!(mul(f64::MAX, 2.0, Mode::Zero), f64::MAX);
        assert_eq!(mul(f64::MAX, 2.0, Mode::Up), f64::INFINITY);
        assert_eq!(mul(-f64::MAX, 2.0, Mode::Up), -f64::MAX);
        assert_eq!(mul(-f64::MAX, 2.0, Mode::Down), f64::NEG_INFINITY);
    }
}
