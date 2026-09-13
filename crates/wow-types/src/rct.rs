//! RingCT signatures: `rctSigBase` and `rctSigPrunable`.
//!
//! `specs/05-blocks-and-transactions.md` §2.3 and §2.4.
//!
//! This is the part of the format that cannot be parsed context-free: array
//! lengths come from `(type, inputs, outputs, mixin)`, all derived from the
//! already-parsed prefix (`specs/04` §1.4). `message` and `mixRing` are never
//! serialized — the first is the tx prefix hash, the second comes from the
//! chain.

use wow_crypto::types::{EcPoint, EcScalar};
use wow_serialize::binary::{Reader, Writer};
use wow_serialize::error::{Error, Result};

/// `specs/02-crypto.md` §4.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RctType {
    #[default]
    Null = 0,
    Full = 1,
    Simple = 2,
    FullBulletproof = 3,
    SimpleBulletproof = 4,
    Bulletproof = 5,
    Bulletproof2 = 6,
    Clsag = 7,
    BulletproofPlus = 8,
    /// Wownero-only, HF 21 (testnet). The one difference from
    /// `BulletproofPlus` is the commitment convention (`specs/02` §4.4).
    BulletproofPlusFullCommit = 9,
}

impl RctType {
    pub fn from_u8(v: u8) -> Result<RctType> {
        Ok(match v {
            0 => RctType::Null,
            1 => RctType::Full,
            2 => RctType::Simple,
            3 => RctType::FullBulletproof,
            4 => RctType::SimpleBulletproof,
            5 => RctType::Bulletproof,
            6 => RctType::Bulletproof2,
            7 => RctType::Clsag,
            8 => RctType::BulletproofPlus,
            9 => RctType::BulletproofPlusFullCommit,
            _ => return Err(Error::InvalidValue("unknown RCT type")),
        })
    }

    pub fn is_null(self) -> bool {
        self == RctType::Null
    }

    /// `is_rct_bulletproof`: types 3, 4, 5, 6, 7.
    pub fn is_bulletproof(self) -> bool {
        matches!(
            self,
            RctType::FullBulletproof
                | RctType::SimpleBulletproof
                | RctType::Bulletproof
                | RctType::Bulletproof2
                | RctType::Clsag
        )
    }

    /// `is_rct_bulletproof_plus`: types 8, 9.
    pub fn is_bulletproof_plus(self) -> bool {
        matches!(
            self,
            RctType::BulletproofPlus | RctType::BulletproofPlusFullCommit
        )
    }

    /// `is_rct_old_bulletproof`: types 3, 4 — excluded from the weight clawback.
    pub fn is_old_bulletproof(self) -> bool {
        matches!(self, RctType::FullBulletproof | RctType::SimpleBulletproof)
    }

    /// Types 7, 8, 9 use CLSAG rather than MLSAG.
    pub fn is_clsag(self) -> bool {
        matches!(
            self,
            RctType::Clsag | RctType::BulletproofPlus | RctType::BulletproofPlusFullCommit
        )
    }

    /// `is_rct_bp_plus_legacy`: type 8, where `outPk.mask` holds `C / 8` rather
    /// than the full commitment (`specs/02` §4.4, `specs/06` §9.7).
    pub fn is_bp_plus_legacy(self) -> bool {
        self == RctType::BulletproofPlus
    }

    /// Types >= `Bulletproof2` use the **short** `ecdhInfo` form: 8 bytes of
    /// amount, no mask (`specs/02` §4.5).
    pub fn has_short_ecdh(self) -> bool {
        matches!(
            self,
            RctType::Bulletproof2
                | RctType::Clsag
                | RctType::BulletproofPlus
                | RctType::BulletproofPlusFullCommit
        )
    }

    /// Types whose `rctSigPrunable` carries a trailing `pseudoOuts` array.
    fn has_prunable_pseudo_outs(self) -> bool {
        matches!(
            self,
            RctType::SimpleBulletproof
                | RctType::Bulletproof
                | RctType::Bulletproof2
                | RctType::Clsag
                | RctType::BulletproofPlus
                | RctType::BulletproofPlusFullCommit
        )
    }

    /// For MLSAG types, how many `mg` elements `rctSigPrunable` holds.
    fn mg_elements(self, inputs: usize) -> usize {
        if matches!(
            self,
            RctType::Simple
                | RctType::Bulletproof
                | RctType::Bulletproof2
                | RctType::SimpleBulletproof
        ) {
            inputs
        } else {
            1
        }
    }

    /// For MLSAG types, the inner `ss` row width minus one.
    fn mg_ss2(self, inputs: usize) -> usize {
        if matches!(
            self,
            RctType::Simple
                | RctType::Bulletproof
                | RctType::Bulletproof2
                | RctType::SimpleBulletproof
        ) {
            2
        } else {
            inputs + 1
        }
    }
}

/// `ecdhTuple`. For types >= `Bulletproof2` only `amount` is serialized, and
/// only its first 8 bytes; `mask` is recomputed (`specs/02` §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EcdhInfo {
    pub mask: EcScalar,
    pub amount: EcScalar,
}

/// A Bulletproof, as it appears on the wire. `V` is **not** serialized — it is
/// reconstructed from `outPk.mask`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Bulletproof {
    pub a: EcPoint,
    pub s: EcPoint,
    pub t1: EcPoint,
    pub t2: EcPoint,
    pub taux: EcScalar,
    pub mu: EcScalar,
    pub l: Vec<EcPoint>,
    pub r: Vec<EcPoint>,
    pub a_scalar: EcScalar,
    pub b: EcScalar,
    pub t: EcScalar,
}

impl Bulletproof {
    /// `n_bulletproof_max_amounts(p) = 1 << (p.L.len() - 6)`.
    pub fn max_amounts(&self) -> Option<usize> {
        let n = self.l.len().checked_sub(6)?;
        if n >= usize::BITS as usize {
            return None;
        }
        Some(1usize << n)
    }
}

/// A Bulletproof+, as it appears on the wire. `V` is not serialized.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BulletproofPlus {
    pub a: EcPoint,
    pub a1: EcPoint,
    pub b: EcPoint,
    pub r1: EcScalar,
    pub s1: EcScalar,
    pub d1: EcScalar,
    pub l: Vec<EcPoint>,
    pub r: Vec<EcPoint>,
}

impl BulletproofPlus {
    /// `n_bulletproof_plus_max_amounts(p) = 1 << (p.L.len() - 6)`.
    ///
    /// `L.len() >= 6` is required (`specs/02` §4.4).
    pub fn max_amounts(&self) -> Option<usize> {
        let n = self.l.len().checked_sub(6)?;
        if n >= usize::BITS as usize {
            return None;
        }
        Some(1usize << n)
    }
}

/// A Borromean range signature (types 1 and 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeSig {
    pub asig_s0: Vec<EcScalar>,
    pub asig_s1: Vec<EcScalar>,
    pub asig_ee: EcScalar,
    pub ci: Vec<EcPoint>,
}

impl Default for RangeSig {
    fn default() -> Self {
        RangeSig {
            asig_s0: vec![EcScalar::ZERO; 64],
            asig_s1: vec![EcScalar::ZERO; 64],
            asig_ee: EcScalar::ZERO,
            ci: vec![EcPoint::ZERO; 64],
        }
    }
}

/// A CLSAG signature. `I` is **not** serialized (it is the input's `k_image`);
/// `D` is.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Clsag {
    /// `ring_size` entries.
    pub s: Vec<EcScalar>,
    pub c1: EcScalar,
    pub d: EcPoint,
}

/// An MLSAG signature. `II` is not serialized.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MgSig {
    /// `(mixin + 1)` rows of `ss2` scalars each.
    pub ss: Vec<Vec<EcScalar>>,
    pub cc: EcScalar,
}

/// The whole RingCT signature set: `rctSigBase` plus `rctSigPrunable`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RctSignatures {
    // --- rctSigBase ---
    pub ty: RctType,
    pub txn_fee: u64,
    /// Only type `Simple` (2) keeps `pseudoOuts` in the base.
    pub pseudo_outs_base: Vec<EcPoint>,
    pub ecdh_info: Vec<EcdhInfo>,
    /// `outPk`, of which only `mask` is serialized; `dest` is derived.
    pub out_pk: Vec<EcPoint>,

    // --- rctSigPrunable ---
    pub range_sigs: Vec<RangeSig>,
    pub bulletproofs: Vec<Bulletproof>,
    pub bulletproofs_plus: Vec<BulletproofPlus>,
    pub mgs: Vec<MgSig>,
    pub clsags: Vec<Clsag>,
    pub pseudo_outs: Vec<EcPoint>,
}

impl RctSignatures {
    pub fn null() -> RctSignatures {
        RctSignatures::default()
    }

    /// `serialize_rctsig_base` (`specs/05` §2.3).
    pub fn read_base(r: &mut Reader<'_>, inputs: usize, outputs: usize) -> Result<RctSignatures> {
        let ty = RctType::from_u8(r.read_u8()?)?;
        let mut rv = RctSignatures {
            ty,
            ..Default::default()
        };
        if ty.is_null() {
            return Ok(rv);
        }
        rv.txn_fee = r.read_varint()?;

        if ty == RctType::Simple {
            rv.pseudo_outs_base.reserve(inputs.min(4096));
            for _ in 0..inputs {
                rv.pseudo_outs_base.push(EcPoint(r.read_array::<32>()?));
            }
        }

        rv.ecdh_info.reserve(outputs.min(4096));
        for _ in 0..outputs {
            if ty.has_short_ecdh() {
                // Truncated to 8 bytes; the mask is recomputed, not sent.
                let mut amount = EcScalar::ZERO;
                amount.0[..8].copy_from_slice(&r.read_array::<8>()?);
                rv.ecdh_info.push(EcdhInfo {
                    mask: EcScalar::ZERO,
                    amount,
                });
            } else {
                rv.ecdh_info.push(EcdhInfo {
                    mask: EcScalar(r.read_array::<32>()?),
                    amount: EcScalar(r.read_array::<32>()?),
                });
            }
        }

        rv.out_pk.reserve(outputs.min(4096));
        for _ in 0..outputs {
            rv.out_pk.push(EcPoint(r.read_array::<32>()?));
        }
        Ok(rv)
    }

    pub fn write_base(&self, w: &mut Writer, _outputs: usize) {
        w.write_u8(self.ty as u8);
        if self.ty.is_null() {
            return;
        }
        w.write_varint(self.txn_fee);
        if self.ty == RctType::Simple {
            for p in &self.pseudo_outs_base {
                w.write_bytes(&p.0);
            }
        }
        for e in &self.ecdh_info {
            if self.ty.has_short_ecdh() {
                w.write_bytes(&e.amount.0[..8]);
            } else {
                w.write_bytes(&e.mask.0);
                w.write_bytes(&e.amount.0);
            }
        }
        for p in &self.out_pk {
            w.write_bytes(&p.0);
        }
    }

    /// `serialize_rctsig_prunable` (`specs/05` §2.4).
    ///
    /// Parameterised by `(type, inputs, outputs, mixin)`; none of those lengths
    /// appear on the wire.
    pub fn read_prunable(
        &mut self,
        r: &mut Reader<'_>,
        inputs: usize,
        outputs: usize,
        mixin: usize,
    ) -> Result<()> {
        self.read_range_proofs(r, outputs)?;
        self.read_ring_sigs(r, inputs, mixin)?;

        if self.ty.has_prunable_pseudo_outs() {
            self.pseudo_outs.reserve(inputs.min(4096));
            for _ in 0..inputs {
                self.pseudo_outs.push(EcPoint(r.read_array::<32>()?));
            }
        }
        Ok(())
    }

    fn read_range_proofs(&mut self, r: &mut Reader<'_>, outputs: usize) -> Result<()> {
        match self.ty {
            RctType::SimpleBulletproof | RctType::FullBulletproof => {
                // One proof per output, with no count prefix.
                for _ in 0..outputs {
                    self.bulletproofs.push(read_bulletproof(r)?);
                }
            }
            RctType::BulletproofPlus | RctType::BulletproofPlusFullCommit => {
                // `nbp` is a `uint32_t`, so `VARINT_FIELD(nbp)` reads with
                // bits = 32. Using 64 here would accept varints the reference
                // rejects as overflow.
                let nbp = r.read_varint_bits(32)?;
                let nbp = usize::try_from(nbp).map_err(|_| Error::LimitExceeded("nbp"))?;
                if nbp > outputs {
                    return Err(Error::LimitExceeded("nbp > outputs"));
                }
                for _ in 0..nbp {
                    self.bulletproofs_plus.push(read_bulletproof_plus(r)?);
                }
                let total: usize = self
                    .bulletproofs_plus
                    .iter()
                    .map(|b| b.max_amounts().unwrap_or(0))
                    .sum();
                if total < outputs {
                    return Err(Error::LimitExceeded(
                        "n_bulletproof_plus_max_amounts < outputs",
                    ));
                }
                // Note: `bulletproofs_plus.len() == 1` is *not* checked here.
                // The reference enforces it in `expand_transaction_1`, a
                // separate step -- see `Transaction::expand`.
            }
            RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag => {
                let nbp = if self.ty == RctType::Bulletproof {
                    // Note: `FIELD(nbp)` on a `uint32_t` -- a **raw u32 LE**,
                    // not a varint, for RCT type 5 only.
                    r.read_u32_le()? as u64
                } else {
                    r.read_varint_bits(32)?
                };
                let nbp = usize::try_from(nbp).map_err(|_| Error::LimitExceeded("nbp"))?;
                if nbp > outputs {
                    return Err(Error::LimitExceeded("nbp > outputs"));
                }
                for _ in 0..nbp {
                    self.bulletproofs.push(read_bulletproof(r)?);
                }
                let total: usize = self
                    .bulletproofs
                    .iter()
                    .map(|b| b.max_amounts().unwrap_or(0))
                    .sum();
                if total < outputs {
                    return Err(Error::LimitExceeded("n_bulletproof_max_amounts < outputs"));
                }
            }
            RctType::Full | RctType::Simple => {
                for _ in 0..outputs {
                    self.range_sigs.push(read_range_sig(r)?);
                }
            }
            RctType::Null => {}
        }
        Ok(())
    }

    fn read_ring_sigs(&mut self, r: &mut Reader<'_>, inputs: usize, mixin: usize) -> Result<()> {
        if self.ty.is_clsag() {
            self.clsags.reserve(inputs.min(4096));
            for _ in 0..inputs {
                let mut s = Vec::with_capacity((mixin + 1).min(4096));
                for _ in 0..=mixin {
                    s.push(EcScalar(r.read_array::<32>()?));
                }
                self.clsags.push(Clsag {
                    s,
                    c1: EcScalar(r.read_array::<32>()?),
                    d: EcPoint(r.read_array::<32>()?),
                });
            }
        } else if !self.ty.is_null() {
            let n = self.ty.mg_elements(inputs);
            let ss2 = self.ty.mg_ss2(inputs);
            self.mgs.reserve(n.min(4096));
            for _ in 0..n {
                let mut ss = Vec::with_capacity((mixin + 1).min(4096));
                for _ in 0..=mixin {
                    let mut row = Vec::with_capacity(ss2.min(4096));
                    for _ in 0..ss2 {
                        row.push(EcScalar(r.read_array::<32>()?));
                    }
                    ss.push(row);
                }
                self.mgs.push(MgSig {
                    ss,
                    cc: EcScalar(r.read_array::<32>()?),
                });
            }
        }
        Ok(())
    }

    pub fn write_prunable(&self, w: &mut Writer) {
        match self.ty {
            RctType::SimpleBulletproof | RctType::FullBulletproof => {
                for b in &self.bulletproofs {
                    write_bulletproof(w, b);
                }
            }
            RctType::BulletproofPlus | RctType::BulletproofPlusFullCommit => {
                w.write_varint(self.bulletproofs_plus.len() as u64);
                for b in &self.bulletproofs_plus {
                    write_bulletproof_plus(w, b);
                }
            }
            RctType::Bulletproof => {
                w.write_u32_le(self.bulletproofs.len() as u32);
                for b in &self.bulletproofs {
                    write_bulletproof(w, b);
                }
            }
            RctType::Bulletproof2 | RctType::Clsag => {
                w.write_varint(self.bulletproofs.len() as u64);
                for b in &self.bulletproofs {
                    write_bulletproof(w, b);
                }
            }
            RctType::Full | RctType::Simple => {
                for rs in &self.range_sigs {
                    write_range_sig(w, rs);
                }
            }
            RctType::Null => return,
        }

        if self.ty.is_clsag() {
            for c in &self.clsags {
                for s in &c.s {
                    w.write_bytes(&s.0);
                }
                w.write_bytes(&c.c1.0);
                w.write_bytes(&c.d.0);
            }
        } else {
            for m in &self.mgs {
                for row in &m.ss {
                    for s in row {
                        w.write_bytes(&s.0);
                    }
                }
                w.write_bytes(&m.cc.0);
            }
        }

        if self.ty.has_prunable_pseudo_outs() {
            for p in &self.pseudo_outs {
                w.write_bytes(&p.0);
            }
        }
    }

    /// The `pseudoOuts` actually in force: type `Simple` keeps them in the
    /// base, every other type that has them keeps them in the prunable part.
    pub fn effective_pseudo_outs(&self) -> &[EcPoint] {
        if self.ty == RctType::Simple {
            &self.pseudo_outs_base
        } else {
            &self.pseudo_outs
        }
    }

    /// `n_bulletproof_plus_max_amounts` / `n_bulletproof_max_amounts` summed
    /// over the proofs — the padded output count the weight clawback uses.
    pub fn n_padded_outputs(&self) -> Option<usize> {
        if self.ty.is_bulletproof_plus() {
            self.bulletproofs_plus
                .iter()
                .try_fold(0usize, |a, b| a.checked_add(b.max_amounts()?))
        } else if self.ty.is_bulletproof() {
            self.bulletproofs
                .iter()
                .try_fold(0usize, |a, b| a.checked_add(b.max_amounts()?))
        } else {
            None
        }
    }
}

/// Inside `rctSigPrunable`, the `L` and `R` vectors **do** carry their own
/// varint length prefixes — they are ordinary `FIELD(vector)`s
/// (`specs/05` §2.4).
fn read_point_vec(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<EcPoint>> {
    let n = r.read_len(r.remaining() / 32, what)?;
    let mut v = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        v.push(EcPoint(r.read_array::<32>()?));
    }
    Ok(v)
}

fn write_point_vec(w: &mut Writer, v: &[EcPoint]) {
    w.write_varint(v.len() as u64);
    for p in v {
        w.write_bytes(&p.0);
    }
}

fn read_bulletproof(r: &mut Reader<'_>) -> Result<Bulletproof> {
    Ok(Bulletproof {
        a: EcPoint(r.read_array::<32>()?),
        s: EcPoint(r.read_array::<32>()?),
        t1: EcPoint(r.read_array::<32>()?),
        t2: EcPoint(r.read_array::<32>()?),
        taux: EcScalar(r.read_array::<32>()?),
        mu: EcScalar(r.read_array::<32>()?),
        l: read_point_vec(r, "bp.L")?,
        r: read_point_vec(r, "bp.R")?,
        a_scalar: EcScalar(r.read_array::<32>()?),
        b: EcScalar(r.read_array::<32>()?),
        t: EcScalar(r.read_array::<32>()?),
    })
}

fn write_bulletproof(w: &mut Writer, b: &Bulletproof) {
    w.write_bytes(&b.a.0);
    w.write_bytes(&b.s.0);
    w.write_bytes(&b.t1.0);
    w.write_bytes(&b.t2.0);
    w.write_bytes(&b.taux.0);
    w.write_bytes(&b.mu.0);
    write_point_vec(w, &b.l);
    write_point_vec(w, &b.r);
    w.write_bytes(&b.a_scalar.0);
    w.write_bytes(&b.b.0);
    w.write_bytes(&b.t.0);
}

fn read_bulletproof_plus(r: &mut Reader<'_>) -> Result<BulletproofPlus> {
    Ok(BulletproofPlus {
        a: EcPoint(r.read_array::<32>()?),
        a1: EcPoint(r.read_array::<32>()?),
        b: EcPoint(r.read_array::<32>()?),
        r1: EcScalar(r.read_array::<32>()?),
        s1: EcScalar(r.read_array::<32>()?),
        d1: EcScalar(r.read_array::<32>()?),
        l: read_point_vec(r, "bpp.L")?,
        r: read_point_vec(r, "bpp.R")?,
    })
}

fn write_bulletproof_plus(w: &mut Writer, b: &BulletproofPlus) {
    w.write_bytes(&b.a.0);
    w.write_bytes(&b.a1.0);
    w.write_bytes(&b.b.0);
    w.write_bytes(&b.r1.0);
    w.write_bytes(&b.s1.0);
    w.write_bytes(&b.d1.0);
    write_point_vec(w, &b.l);
    write_point_vec(w, &b.r);
}

fn read_range_sig(r: &mut Reader<'_>) -> Result<RangeSig> {
    // Fixed 64-element arrays with no length prefix (Borromean).
    let mut asig_s0 = Vec::with_capacity(64);
    for _ in 0..64 {
        asig_s0.push(EcScalar(r.read_array::<32>()?));
    }
    let mut asig_s1 = Vec::with_capacity(64);
    for _ in 0..64 {
        asig_s1.push(EcScalar(r.read_array::<32>()?));
    }
    let asig_ee = EcScalar(r.read_array::<32>()?);
    let mut ci = Vec::with_capacity(64);
    for _ in 0..64 {
        ci.push(EcPoint(r.read_array::<32>()?));
    }
    Ok(RangeSig {
        asig_s0,
        asig_s1,
        asig_ee,
        ci,
    })
}

fn write_range_sig(w: &mut Writer, rs: &RangeSig) {
    for s in &rs.asig_s0 {
        w.write_bytes(&s.0);
    }
    for s in &rs.asig_s1 {
        w.write_bytes(&s.0);
    }
    w.write_bytes(&rs.asig_ee.0);
    for c in &rs.ci {
        w.write_bytes(&c.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rct_type_numbering_matches_the_reference() {
        assert_eq!(RctType::Null as u8, 0);
        assert_eq!(RctType::Full as u8, 1);
        assert_eq!(RctType::Simple as u8, 2);
        assert_eq!(RctType::FullBulletproof as u8, 3);
        assert_eq!(RctType::SimpleBulletproof as u8, 4);
        assert_eq!(RctType::Bulletproof as u8, 5);
        assert_eq!(RctType::Bulletproof2 as u8, 6);
        assert_eq!(RctType::Clsag as u8, 7);
        assert_eq!(RctType::BulletproofPlus as u8, 8);
        assert_eq!(RctType::BulletproofPlusFullCommit as u8, 9);
        for v in 0u8..=9 {
            assert_eq!(RctType::from_u8(v).unwrap() as u8, v);
        }
        for v in 10u8..=255 {
            assert!(RctType::from_u8(v).is_err(), "type {v} should be unknown");
        }
    }

    /// `specs/02` §4.5: the short `ecdhInfo` form starts at `Bulletproof2` (6).
    #[test]
    fn short_ecdh_starts_at_bulletproof2() {
        for t in [
            RctType::Full,
            RctType::Simple,
            RctType::FullBulletproof,
            RctType::SimpleBulletproof,
            RctType::Bulletproof,
        ] {
            assert!(!t.has_short_ecdh(), "{t:?} should use the legacy form");
        }
        for t in [
            RctType::Bulletproof2,
            RctType::Clsag,
            RctType::BulletproofPlus,
            RctType::BulletproofPlusFullCommit,
        ] {
            assert!(t.has_short_ecdh(), "{t:?} should use the short form");
        }
    }

    /// `specs/06` §9.7: only type 8 stores `C / 8`.
    #[test]
    fn only_type_8_is_bp_plus_legacy() {
        assert!(RctType::BulletproofPlus.is_bp_plus_legacy());
        assert!(!RctType::BulletproofPlusFullCommit.is_bp_plus_legacy());
        assert!(!RctType::Clsag.is_bp_plus_legacy());
    }

    #[test]
    fn max_amounts_is_one_shl_len_minus_six() {
        let mk = |n: usize| BulletproofPlus {
            l: vec![EcPoint::ZERO; n],
            ..Default::default()
        };
        assert_eq!(mk(6).max_amounts(), Some(1));
        assert_eq!(mk(7).max_amounts(), Some(2));
        assert_eq!(mk(10).max_amounts(), Some(16));
        // L.len() < 6 is required.
        assert_eq!(mk(5).max_amounts(), None);
        assert_eq!(mk(0).max_amounts(), None);
    }

    #[test]
    fn mlsag_shape_depends_on_the_type() {
        // Simple-family types get one mg per input, each row 2 scalars wide.
        assert_eq!(RctType::Simple.mg_elements(5), 5);
        assert_eq!(RctType::Simple.mg_ss2(5), 2);
        assert_eq!(RctType::Bulletproof2.mg_elements(5), 5);
        // Full-family types get one mg, with a row per input plus one.
        assert_eq!(RctType::Full.mg_elements(5), 1);
        assert_eq!(RctType::Full.mg_ss2(5), 6);
        assert_eq!(RctType::FullBulletproof.mg_elements(5), 1);
    }

    #[test]
    fn pseudo_outs_location_by_type() {
        // Type 2 keeps them in the base; 4,5,6,7,8,9 in the prunable part.
        assert!(!RctType::Simple.has_prunable_pseudo_outs());
        for t in [
            RctType::SimpleBulletproof,
            RctType::Bulletproof,
            RctType::Bulletproof2,
            RctType::Clsag,
            RctType::BulletproofPlus,
            RctType::BulletproofPlusFullCommit,
        ] {
            assert!(t.has_prunable_pseudo_outs(), "{t:?}");
        }
        // Types 1 and 3 have none at all.
        assert!(!RctType::Full.has_prunable_pseudo_outs());
        assert!(!RctType::FullBulletproof.has_prunable_pseudo_outs());
    }
}
