//! The RandomX virtual machine: program generation, the bytecode it compiles
//! to, and the hash (`virtual_machine.cpp`, `bytecode_machine.cpp`,
//! `vm_interpreted.cpp`, `randomx_calculate_hash`; RandomX spec §2, §4, §5).
//!
//! An interpreter, as the C++ runs without its JIT. Programs are decoded once
//! each into a compact instruction list, the way `BytecodeMachine` does, and
//! the list is run for every iteration.

#![allow(
    clippy::needless_range_loop,
    reason = "register loops follow the reference implementation's indices"
)]

use crate::aes;
use crate::blake2b::blake2b;
use crate::cache::CacheData;
use crate::float::{self, Mode};
use crate::params::{Config, INSTRUCTION_COUNT};
use crate::superscalar::reciprocal;

/// Where Dataset items come from.
pub(crate) enum Memory<'a> {
    /// Computed from the Cache per read: light mode.
    Light(&'a CacheData),
    /// Read from the full Dataset, eight words an item.
    Full(&'a [u64]),
}

/// A 128-bit floating point register: a pair of doubles.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct F128 {
    lo: f64,
    hi: f64,
}

/// The index of the always-zero register that memory operands with
/// `src == dst` read their address from.
const ZERO_REGISTER: u8 = 8;
/// `dynamicMantissaMask`: the mantissa and the low four exponent bits.
const DYNAMIC_MANTISSA_MASK: u64 = (1 << 56) - 1;
/// `RegisterNeedsDisplacement`.
const REGISTER_NEEDS_DISPLACEMENT: usize = 5;
/// `StoreL3Condition`.
const STORE_L3_CONDITION: u8 = 14;

// Instruction types, in frequency-table order.
const IADD_RS: u8 = 0;
const IADD_M: u8 = 1;
const ISUB_R: u8 = 2;
const ISUB_M: u8 = 3;
const IMUL_R: u8 = 4;
const IMUL_M: u8 = 5;
const IMULH_R: u8 = 6;
const IMULH_M: u8 = 7;
const ISMULH_R: u8 = 8;
const ISMULH_M: u8 = 9;
const IMUL_RCP: u8 = 10;
const INEG_R: u8 = 11;
const IXOR_R: u8 = 12;
const IXOR_M: u8 = 13;
const IROR_R: u8 = 14;
const IROL_R: u8 = 15;
const ISWAP_R: u8 = 16;
const FSWAP_R: u8 = 17;
const FADD_R: u8 = 18;
const FADD_M: u8 = 19;
const FSUB_R: u8 = 20;
const FSUB_M: u8 = 21;
const FSCAL_R: u8 = 22;
const FMUL_R: u8 = 23;
const FDIV_M: u8 = 24;
const FSQRT_R: u8 = 25;
const CBRANCH: u8 = 26;
const CFROUND: u8 = 27;
const ISTORE: u8 = 28;

/// A decoded instruction's operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    IaddRs,
    IaddM,
    IsubR,
    IsubI,
    IsubM,
    ImulR,
    ImulI,
    ImulM,
    ImulhR,
    ImulhM,
    IsmulhR,
    IsmulhM,
    InegR,
    IxorR,
    IxorI,
    IxorM,
    IrorR,
    IrorI,
    IrolR,
    IrolI,
    IswapR,
    FswapF,
    FswapE,
    FaddR,
    FaddM,
    FsubR,
    FsubM,
    FscalR,
    FmulR,
    FdivM,
    FsqrtR,
    Cbranch,
    Cfround,
    Istore,
    Nop,
}

/// `InstructionByteCode`.
#[derive(Clone, Copy, Debug)]
struct Instr {
    op: Op,
    dst: u8,
    src: u8,
    shift: u8,
    /// The instruction a taken `CBRANCH` continues after; -1 for the start.
    target: i16,
    imm: u64,
    mask: u32,
}

const NOP: Instr = Instr {
    op: Op::Nop,
    dst: 0,
    src: 0,
    shift: 0,
    target: 0,
    imm: 0,
    mask: 0,
};

/// What decoding needs from the parameters.
struct Decoder {
    /// Instruction type by opcode byte.
    kind: [u8; 256],
    l1: u32,
    l2: u32,
    l3: u32,
    condition_mask: u32,
    condition_offset: u32,
}

impl Decoder {
    fn new(cfg: &Config) -> Decoder {
        let mut kind = [0u8; 256];
        let mut ceiling = 0u32;
        let mut t = 0usize;
        for (opcode, k) in kind.iter_mut().enumerate() {
            while t < INSTRUCTION_COUNT && opcode as u32 >= ceiling + cfg.frequencies[t] {
                ceiling += cfg.frequencies[t];
                t += 1;
            }
            *k = t as u8;
        }
        Decoder {
            kind,
            l1: (cfg.scratchpad_l1 / 8 - 1) * 8,
            l2: (cfg.scratchpad_l2 / 8 - 1) * 8,
            l3: (cfg.scratchpad_l3 / 8 - 1) * 8,
            condition_mask: (1 << cfg.jump_bits) - 1,
            condition_offset: cfg.jump_offset,
        }
    }

    /// `BytecodeMachine::compileInstruction` for the instruction at `pc`.
    fn decode(&self, pc: usize, bytes: &[u8], usage: &mut [i32; 8]) -> Instr {
        let (opcode, dst8, src8, modifier) = (bytes[0], bytes[1], bytes[2], bytes[3]);
        let imm32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let imm64 = imm32 as i32 as i64 as u64;
        let dst = dst8 % 8;
        let src = src8 % 8;
        let (fdst, fsrc) = (dst8 % 4, src8 % 4);
        let mem = if modifier % 4 != 0 { self.l1 } else { self.l2 };
        let pc16 = pc as i32;
        let base = Instr {
            dst,
            src,
            imm: imm64,
            ..NOP
        };

        // A register instruction whose source is its destination uses the
        // immediate instead.
        let reg_or_imm = |usage: &mut [i32; 8], reg: Op, imm: Op, imm_value: u64| {
            usage[usize::from(dst)] = pc16;
            if src != dst {
                Instr { op: reg, ..base }
            } else {
                Instr {
                    op: imm,
                    imm: imm_value,
                    ..base
                }
            }
        };
        // A memory operand from `src + imm`, or from `imm` alone in L3 when
        // the source is the destination.
        let memory = |usage: &mut [i32; 8], op: Op| {
            usage[usize::from(dst)] = pc16;
            if src != dst {
                Instr {
                    op,
                    mask: mem,
                    ..base
                }
            } else {
                Instr {
                    op,
                    src: ZERO_REGISTER,
                    mask: self.l3,
                    ..base
                }
            }
        };

        match self.kind[usize::from(opcode)] {
            IADD_RS => {
                usage[usize::from(dst)] = pc16;
                Instr {
                    op: Op::IaddRs,
                    shift: (modifier >> 2) % 4,
                    imm: if usize::from(dst) == REGISTER_NEEDS_DISPLACEMENT {
                        imm64
                    } else {
                        0
                    },
                    ..base
                }
            }
            IADD_M => memory(usage, Op::IaddM),
            ISUB_R => reg_or_imm(usage, Op::IsubR, Op::IsubI, imm64),
            ISUB_M => memory(usage, Op::IsubM),
            IMUL_R => reg_or_imm(usage, Op::ImulR, Op::ImulI, imm64),
            IMUL_M => memory(usage, Op::ImulM),
            IMULH_R => {
                usage[usize::from(dst)] = pc16;
                Instr {
                    op: Op::ImulhR,
                    ..base
                }
            }
            IMULH_M => memory(usage, Op::ImulhM),
            ISMULH_R => {
                usage[usize::from(dst)] = pc16;
                Instr {
                    op: Op::IsmulhR,
                    ..base
                }
            }
            ISMULH_M => memory(usage, Op::IsmulhM),
            IMUL_RCP => {
                if imm32 & imm32.wrapping_sub(1) != 0 {
                    usage[usize::from(dst)] = pc16;
                    Instr {
                        op: Op::ImulI,
                        imm: reciprocal(imm32),
                        ..base
                    }
                } else {
                    NOP
                }
            }
            INEG_R => {
                usage[usize::from(dst)] = pc16;
                Instr {
                    op: Op::InegR,
                    ..base
                }
            }
            IXOR_R => reg_or_imm(usage, Op::IxorR, Op::IxorI, imm64),
            IXOR_M => memory(usage, Op::IxorM),
            IROR_R => reg_or_imm(usage, Op::IrorR, Op::IrorI, u64::from(imm32)),
            IROL_R => reg_or_imm(usage, Op::IrolR, Op::IrolI, u64::from(imm32)),
            ISWAP_R => {
                if src != dst {
                    usage[usize::from(dst)] = pc16;
                    usage[usize::from(src)] = pc16;
                    Instr {
                        op: Op::IswapR,
                        ..base
                    }
                } else {
                    NOP
                }
            }
            FSWAP_R => {
                if dst < 4 {
                    Instr {
                        op: Op::FswapF,
                        ..base
                    }
                } else {
                    Instr {
                        op: Op::FswapE,
                        dst: dst - 4,
                        ..base
                    }
                }
            }
            FADD_R | FSUB_R | FMUL_R => Instr {
                op: match self.kind[usize::from(opcode)] {
                    FADD_R => Op::FaddR,
                    FSUB_R => Op::FsubR,
                    _ => Op::FmulR,
                },
                dst: fdst,
                src: fsrc,
                ..base
            },
            FADD_M | FSUB_M | FDIV_M => Instr {
                op: match self.kind[usize::from(opcode)] {
                    FADD_M => Op::FaddM,
                    FSUB_M => Op::FsubM,
                    _ => Op::FdivM,
                },
                dst: fdst,
                mask: mem,
                ..base
            },
            FSCAL_R => Instr {
                op: Op::FscalR,
                dst: fdst,
                ..base
            },
            FSQRT_R => Instr {
                op: Op::FsqrtR,
                dst: fdst,
                ..base
            },
            CBRANCH => {
                let target = usage[usize::from(dst)] as i16;
                let shift = u32::from(modifier >> 4) + self.condition_offset;
                let mut imm = imm64 | (1u64 << shift);
                if self.condition_offset > 0 || shift > 0 {
                    imm &= !(1u64 << (shift - 1));
                }
                // CBRANCH counts as modifying every register.
                usage.fill(pc16);
                Instr {
                    op: Op::Cbranch,
                    target,
                    imm,
                    mask: self.condition_mask << shift,
                    ..base
                }
            }
            CFROUND => Instr {
                op: Op::Cfround,
                imm: u64::from(imm32 & 63),
                ..base
            },
            ISTORE => Instr {
                op: Op::Istore,
                mask: if (modifier >> 4) < STORE_L3_CONDITION {
                    mem
                } else {
                    self.l3
                },
                ..base
            },
            _ => NOP,
        }
    }
}

#[inline(always)]
fn read(sp: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(sp[at..at + 8].try_into().expect("8 bytes"))
}

#[inline(always)]
fn write(sp: &mut [u8], at: usize, v: u64) {
    sp[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A memory operand's address.
#[inline(always)]
fn address(base: u64, ins: &Instr) -> usize {
    (base.wrapping_add(ins.imm) & u64::from(ins.mask)) as usize
}

/// Eight bytes as a pair of signed 32-bit integers, as doubles (§4.3.1).
#[inline(always)]
fn convert(v: u64) -> F128 {
    F128 {
        lo: f64::from(v as u32 as i32),
        hi: f64::from((v >> 32) as u32 as i32),
    }
}

/// The group E post-processing (§4.3.2).
#[inline(always)]
fn mask_e(x: F128, e_mask: [u64; 2]) -> F128 {
    F128 {
        lo: f64::from_bits((x.lo.to_bits() & DYNAMIC_MANTISSA_MASK) | e_mask[0]),
        hi: f64::from_bits((x.hi.to_bits() & DYNAMIC_MANTISSA_MASK) | e_mask[1]),
    }
}

#[inline(always)]
fn both(x: F128, y: F128, mode: Mode, f: fn(f64, f64, Mode) -> f64) -> F128 {
    F128 {
        lo: f(x.lo, y.lo, mode),
        hi: f(x.hi, y.hi, mode),
    }
}

/// The registers one program leaves, for the next program's seed.
#[derive(Clone, Copy, Default)]
struct RegisterFile {
    r: [u64; 8],
    f: [F128; 4],
    e: [F128; 4],
    a: [F128; 4],
}

impl RegisterFile {
    fn bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mut at = 0;
        let mut put = |v: u64| {
            out[at..at + 8].copy_from_slice(&v.to_le_bytes());
            at += 8;
        };
        for v in self.r {
            put(v);
        }
        for group in [self.f, self.e, self.a] {
            for reg in group {
                put(reg.lo.to_bits());
                put(reg.hi.to_bits());
            }
        }
        out
    }
}

/// `getSmallPositiveFloatBits`: a group A value in [1, 2^32).
fn small_positive_float(entropy: u64) -> f64 {
    let exponent = ((entropy >> 59) + 1023) & 2047;
    f64::from_bits((exponent << 52) | (entropy & ((1 << 52) - 1)))
}

/// `getFloatMask`: the fraction and exponent bits a group E value is forced
/// to.
fn float_mask(entropy: u64) -> u64 {
    let exponent = (0x300 | ((entropy >> 60) << 4)) << 52;
    (entropy & ((1 << 22) - 1)) | exponent
}

/// One VM, reused across hashes. Not shareable between threads.
pub(crate) struct Machine {
    pub(crate) config: &'static Config,
    hard_aes: bool,
    decoder: Decoder,
    scratchpad: Vec<u8>,
    program: Vec<u8>,
    code: Vec<Instr>,
    reg: RegisterFile,
    mode: Mode,
    l3_mask64: u32,
    align_mask: u32,
    extra_items: u64,
}

impl Machine {
    /// `None` when the scratchpad cannot be allocated.
    pub(crate) fn new(config: &'static Config, hard_aes: bool) -> Option<Machine> {
        let mut scratchpad = Vec::new();
        scratchpad
            .try_reserve_exact(config.scratchpad_l3 as usize)
            .ok()?;
        scratchpad.resize(config.scratchpad_l3 as usize, 0);
        Some(Machine {
            config,
            hard_aes,
            decoder: Decoder::new(config),
            scratchpad,
            program: vec![0; 128 + 8 * config.program_size as usize],
            code: vec![NOP; config.program_size as usize],
            reg: RegisterFile::default(),
            mode: Mode::Nearest,
            l3_mask64: (config.scratchpad_l3 / 64 - 1) * 64,
            align_mask: ((config.dataset_base_size - 1) & !63) as u32,
            extra_items: config.dataset_extra_size / 64,
        })
    }

    /// `randomx_calculate_hash`.
    pub(crate) fn hash(&mut self, input: &[u8], memory: &Memory<'_>) -> [u8; 32] {
        let mut seed = [0u8; 64];
        blake2b(&mut seed, input);
        aes::fill_aes_1r_x4(&mut seed, &mut self.scratchpad, self.hard_aes);
        self.mode = Mode::Nearest;
        for _ in 0..self.config.program_count - 1 {
            self.run(&seed, memory);
            blake2b(&mut seed, &self.reg.bytes());
        }
        self.run(&seed, memory);
        let mut file = self.reg.bytes();
        file[192..].copy_from_slice(&aes::hash_aes_1r_x4(&self.scratchpad, self.hard_aes));
        let mut out = [0u8; 32];
        blake2b(&mut out, &file);
        out
    }

    fn entropy(&self, i: usize) -> u64 {
        read(&self.program, 8 * i)
    }

    /// Generate, initialise and execute one program.
    fn run(&mut self, seed: &[u8; 64], memory: &Memory<'_>) {
        aes::fill_aes_4r_x4(
            seed,
            &mut self.program,
            &self.config.aes_4r_keys,
            self.hard_aes,
        );

        for i in 0..4 {
            self.reg.a[i] = F128 {
                lo: small_positive_float(self.entropy(2 * i)),
                hi: small_positive_float(self.entropy(2 * i + 1)),
            };
        }
        let mut ma = (self.entropy(8) & u64::from(self.align_mask)) as u32;
        let mut mx = self.entropy(10) as u32;
        let address_registers = self.entropy(12);
        let read_reg = [
            (address_registers & 1) as usize,
            2 + ((address_registers >> 1) & 1) as usize,
            4 + ((address_registers >> 2) & 1) as usize,
            6 + ((address_registers >> 3) & 1) as usize,
        ];
        let dataset_offset = (self.entropy(13) % (self.extra_items + 1)) * 64;
        let e_mask = [float_mask(self.entropy(14)), float_mask(self.entropy(15))];

        let mut usage = [-1i32; 8];
        for pc in 0..self.code.len() {
            let at = 128 + 8 * pc;
            self.code[pc] = self
                .decoder
                .decode(pc, &self.program[at..at + 8], &mut usage);
        }

        let mut r = [0u64; 9];
        let mut f = [F128::default(); 4];
        let mut e = [F128::default(); 4];
        let a = self.reg.a;
        let sp = &mut self.scratchpad;
        let mut mode = self.mode;
        let mut sp_addr0 = mx;
        let mut sp_addr1 = ma;

        for _ in 0..self.config.program_iterations {
            let sp_mix = r[read_reg[0]] ^ r[read_reg[1]];
            sp_addr0 = (sp_addr0 ^ sp_mix as u32) & self.l3_mask64;
            sp_addr1 = (sp_addr1 ^ (sp_mix >> 32) as u32) & self.l3_mask64;
            let (p0, p1) = (sp_addr0 as usize, sp_addr1 as usize);
            for i in 0..8 {
                r[i] ^= read(sp, p0 + 8 * i);
            }
            for i in 0..4 {
                f[i] = convert(read(sp, p1 + 8 * i));
                e[i] = mask_e(convert(read(sp, p1 + 8 * (4 + i))), e_mask);
            }

            execute(
                &self.code, &mut r, &mut f, &mut e, &a, &mut mode, sp, e_mask,
            );

            mx ^= (r[read_reg[2]] ^ r[read_reg[3]]) as u32;
            mx &= self.align_mask;
            let item_address = dataset_offset + u64::from(ma);
            let item = match memory {
                Memory::Light(cache) => cache.item(u64::from((item_address / 64) as u32)),
                Memory::Full(words) => {
                    let at = (item_address / 64) as usize * 8;
                    words[at..at + 8].try_into().expect("8 words")
                }
            };
            for i in 0..8 {
                r[i] ^= item[i];
            }
            std::mem::swap(&mut mx, &mut ma);

            for i in 0..8 {
                write(sp, p1 + 8 * i, r[i]);
            }
            for i in 0..4 {
                f[i] = F128 {
                    lo: f64::from_bits(f[i].lo.to_bits() ^ e[i].lo.to_bits()),
                    hi: f64::from_bits(f[i].hi.to_bits() ^ e[i].hi.to_bits()),
                };
                write(sp, p0 + 16 * i, f[i].lo.to_bits());
                write(sp, p0 + 16 * i + 8, f[i].hi.to_bits());
            }
            sp_addr0 = 0;
            sp_addr1 = 0;
        }

        self.reg.r.copy_from_slice(&r[..8]);
        self.reg.f = f;
        self.reg.e = e;
        self.mode = mode;
    }
}

/// One pass over a program's instructions.
#[allow(
    clippy::too_many_arguments,
    reason = "the VM's register groups and scratchpad, each distinct"
)]
#[inline]
fn execute(
    code: &[Instr],
    r: &mut [u64; 9],
    f: &mut [F128; 4],
    e: &mut [F128; 4],
    a: &[F128; 4],
    mode: &mut Mode,
    sp: &mut [u8],
    e_mask: [u64; 2],
) {
    let mut pc = 0usize;
    while pc < code.len() {
        let ins = &code[pc];
        let d = usize::from(ins.dst);
        let s = usize::from(ins.src);
        match ins.op {
            Op::IaddRs => r[d] = r[d].wrapping_add((r[s] << ins.shift).wrapping_add(ins.imm)),
            Op::IaddM => r[d] = r[d].wrapping_add(read(sp, address(r[s], ins))),
            Op::IsubR => r[d] = r[d].wrapping_sub(r[s]),
            Op::IsubI => r[d] = r[d].wrapping_sub(ins.imm),
            Op::IsubM => r[d] = r[d].wrapping_sub(read(sp, address(r[s], ins))),
            Op::ImulR => r[d] = r[d].wrapping_mul(r[s]),
            Op::ImulI => r[d] = r[d].wrapping_mul(ins.imm),
            Op::ImulM => r[d] = r[d].wrapping_mul(read(sp, address(r[s], ins))),
            Op::ImulhR => r[d] = mulh(r[d], r[s]),
            Op::ImulhM => r[d] = mulh(r[d], read(sp, address(r[s], ins))),
            Op::IsmulhR => r[d] = smulh(r[d], r[s]),
            Op::IsmulhM => r[d] = smulh(r[d], read(sp, address(r[s], ins))),
            Op::InegR => r[d] = r[d].wrapping_neg(),
            Op::IxorR => r[d] ^= r[s],
            Op::IxorI => r[d] ^= ins.imm,
            Op::IxorM => r[d] ^= read(sp, address(r[s], ins)),
            Op::IrorR => r[d] = r[d].rotate_right((r[s] & 63) as u32),
            Op::IrorI => r[d] = r[d].rotate_right((ins.imm & 63) as u32),
            Op::IrolR => r[d] = r[d].rotate_left((r[s] & 63) as u32),
            Op::IrolI => r[d] = r[d].rotate_left((ins.imm & 63) as u32),
            Op::IswapR => r.swap(d, s),
            Op::FswapF => {
                f[d] = F128 {
                    lo: f[d].hi,
                    hi: f[d].lo,
                }
            }
            Op::FswapE => {
                e[d] = F128 {
                    lo: e[d].hi,
                    hi: e[d].lo,
                }
            }
            Op::FaddR => f[d] = both(f[d], a[s], *mode, float::add),
            Op::FaddM => {
                let m = convert(read(sp, address(r[s], ins)));
                f[d] = both(f[d], m, *mode, float::add);
            }
            Op::FsubR => f[d] = both(f[d], a[s], *mode, float::sub),
            Op::FsubM => {
                let m = convert(read(sp, address(r[s], ins)));
                f[d] = both(f[d], m, *mode, float::sub);
            }
            Op::FscalR => {
                const SCALE: u64 = 0x80F0_0000_0000_0000;
                f[d] = F128 {
                    lo: f64::from_bits(f[d].lo.to_bits() ^ SCALE),
                    hi: f64::from_bits(f[d].hi.to_bits() ^ SCALE),
                };
            }
            Op::FmulR => e[d] = both(e[d], a[s], *mode, float::mul),
            Op::FdivM => {
                let m = mask_e(convert(read(sp, address(r[s], ins))), e_mask);
                e[d] = both(e[d], m, *mode, float::div);
            }
            Op::FsqrtR => {
                e[d] = F128 {
                    lo: float::sqrt(e[d].lo, *mode),
                    hi: float::sqrt(e[d].hi, *mode),
                };
            }
            Op::Cbranch => {
                r[d] = r[d].wrapping_add(ins.imm);
                if r[d] & u64::from(ins.mask) == 0 {
                    pc = (i32::from(ins.target) + 1) as usize;
                    continue;
                }
            }
            Op::Cfround => *mode = Mode::from_bits(r[s].rotate_right(ins.imm as u32)),
            Op::Istore => {
                let at = (r[d].wrapping_add(ins.imm) & u64::from(ins.mask)) as usize;
                write(sp, at, r[s]);
            }
            Op::Nop => {}
        }
        pc += 1;
    }
}

#[inline(always)]
fn mulh(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}

#[inline(always)]
fn smulh(a: u64, b: u64) -> u64 {
    ((i128::from(a as i64) * i128::from(b as i64)) >> 64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::RANDOMX;

    const IMM32: u32 = 3234567890;
    const IMM64: u64 = IMM32 as i32 as i64 as u64;

    /// An instruction of type `t` (upstream's opcode table, as `tests.cpp`
    /// uses: the top opcode of the type's range).
    fn instr(d: &Decoder, t: u8, dst: u8, src: u8, modifier: u8, imm: u32) -> [u8; 8] {
        let opcode = (0..=255u8)
            .rev()
            .find(|o| d.kind[usize::from(*o)] == t)
            .unwrap();
        let i = imm.to_le_bytes();
        [
            opcode,
            192 | dst,
            192 | src,
            modifier,
            i[0],
            i[1],
            i[2],
            i[3],
        ]
    }

    fn run_one(ins: Instr, r: &mut [u64; 9]) {
        let mut f = [F128::default(); 4];
        let mut e = [F128::default(); 4];
        let mut mode = Mode::Nearest;
        let mut sp = [0u8; 64];
        execute(
            &[ins],
            r,
            &mut f,
            &mut e,
            &[F128::default(); 4],
            &mut mode,
            &mut sp,
            [0; 2],
        );
    }

    /// `tests.cpp`: decoding and executing integer instructions.
    #[test]
    fn integer_instructions_match_the_reference() {
        let d = Decoder::new(&RANDOMX);
        let mut usage = [-1; 8];

        let ins = d.decode(0, &instr(&d, IADD_RS, 0, 1, u8::MAX, IMM32), &mut usage);
        assert_eq!((ins.op, ins.shift, ins.imm), (Op::IaddRs, 3, 0));
        let mut r = [0; 9];
        r[0] = 0x8000000000000000;
        r[1] = 0x1000000000000000;
        run_one(ins, &mut r);
        assert_eq!(r[0], 0);

        let ins = d.decode(0, &instr(&d, IADD_RS, 5, 1, 8, IMM32), &mut usage);
        assert_eq!((ins.shift, ins.imm), (2, IMM64));
        r[5] = 0x8000000000000000;
        r[1] = 0x2000000000000000;
        run_one(ins, &mut r);
        assert_eq!(r[5], IMM64);

        let ins = d.decode(0, &instr(&d, IADD_M, 0, 1, 1, IMM32), &mut usage);
        assert_eq!((ins.op, ins.mask), (Op::IaddM, d.l1));
        let ins = d.decode(0, &instr(&d, IMUL_M, 0, 0, 0, IMM32), &mut usage);
        assert_eq!((ins.src, ins.mask), (ZERO_REGISTER, d.l3));

        let cases: [(u8, u8, u64, u64, u64); 6] = [
            (ISUB_R, 1, 1, 0xFFFFFFFF, 0xFFFFFFFF00000002),
            (
                IMUL_R,
                1,
                0xBC550E96BA88A72B,
                0xF5391FA9F18D6273,
                0x28723424A9108E51,
            ),
            (
                IMULH_R,
                1,
                0xBC550E96BA88A72B,
                0xF5391FA9F18D6273,
                0xB4676D31D2B34883,
            ),
            (
                ISMULH_R,
                1,
                0xBC550E96BA88A72B,
                0xF5391FA9F18D6273,
                0x02D93EF1269D3EE5,
            ),
            (
                IROR_R,
                1,
                953360005391419562,
                4569451684712230561,
                0xD835C455069D81EF,
            ),
            (
                IXOR_R,
                1,
                0x8888888888888888,
                0xAAAAAAAAAAAAAAAA,
                0x2222222222222222,
            ),
        ];
        for (t, src, dst_value, src_value, want) in cases {
            let ins = d.decode(0, &instr(&d, t, 0, src, 0, IMM32), &mut usage);
            let mut r = [0; 9];
            r[0] = dst_value;
            r[1] = src_value;
            run_one(ins, &mut r);
            assert_eq!(r[0], want, "type {t}");
        }

        let ins = d.decode(0, &instr(&d, IMUL_RCP, 0, 0, 0, IMM32), &mut usage);
        assert_eq!((ins.op, ins.imm), (Op::ImulI, reciprocal(IMM32)));
        assert_eq!(
            d.decode(0, &instr(&d, IMUL_RCP, 0, 0, 0, 0), &mut usage).op,
            Op::Nop
        );
    }

    /// `tests.cpp`: CBRANCH at 100 and 200, and CFROUND.
    #[test]
    fn control_instructions_match_the_reference() {
        let d = Decoder::new(&RANDOMX);
        let mut usage = [-1; 8];
        let bytes = instr(&d, CBRANCH, 0, 0, 48, IMM32);
        let first = d.decode(100, &bytes, &mut usage);
        assert_eq!((first.imm, first.mask), (0xFFFFFFFFC0CB9AD2, 0x7F800));
        let second = d.decode(200, &bytes, &mut usage);
        assert_eq!(second.target, 100);

        let mut r = [0; 9];
        run_one(second, &mut r);
        r[0] = 0xFFFFFFFFFFFC6800;
        let mut f = [F128::default(); 4];
        let mut e = [F128::default(); 4];
        let mut mode = Mode::Nearest;
        let mut sp = [0u8; 64];
        let code = [
            second,
            Instr {
                op: Op::IxorI,
                imm: 1,
                ..NOP
            },
        ];
        execute(
            &code,
            &mut r,
            &mut f,
            &mut e,
            &[F128::default(); 4],
            &mut mode,
            &mut sp,
            [0; 2],
        );
        // Taken: back to instruction 101, which is past this two-instruction
        // program, so the XOR never runs.
        assert_eq!(r[0], 0xFFFFFFFFFFFC6800u64.wrapping_add(second.imm));

        let cfround = d.decode(100, &instr(&d, CFROUND, 0, 1, 0, IMM32), &mut usage);
        assert_eq!(cfround.imm, 18);
        let store = d.decode(0, &instr(&d, ISTORE, 0, 1, 224, IMM32), &mut usage);
        assert_eq!(store.mask, d.l3);
    }

    /// `tests.cpp`: FSWAP_R, FSCAL_R, the F conversion and FDIV_M.
    #[test]
    fn float_instructions_match_the_reference() {
        let x = F128 {
            lo: f64::from_bits(4569451684712230561),
            hi: f64::from_bits(953360005391419562),
        };
        let mut f = [x, F128::default(), F128::default(), F128::default()];
        let mut e = [F128::default(); 4];
        let mut r = [0; 9];
        let mut mode = Mode::Nearest;
        let mut sp = [0u8; 64];
        let swap = Instr {
            op: Op::FswapF,
            ..NOP
        };
        execute(
            &[swap],
            &mut r,
            &mut f,
            &mut e,
            &[F128::default(); 4],
            &mut mode,
            &mut sp,
            [0; 2],
        );
        assert_eq!(f[0].lo.to_bits(), 953360005391419562);

        let converted = convert(0x1234567890abcdef);
        assert_eq!(converted.lo.to_bits(), 0xc1dbd50c84400000);
        assert_eq!(converted.hi.to_bits(), 0x41b2345678000000);

        let e_mask = [0x3a0000000005d11a, 0x39000000001ba31e];
        let divisor = mask_e(convert(0x8b2460d9_d350a1b6), e_mask);
        let dividend = F128 {
            lo: f64::from_bits(0x411b414296ce93b6),
            hi: f64::from_bits(0x41937f76fede16ee),
        };
        for (mode, lo, hi) in [
            (Mode::Nearest, 0x464384946369b2e7u64, 0x47a55b63664a4732u64),
            (Mode::Down, 0x464384946369b2e6, 0x47a55b63664a4732),
            (Mode::Up, 0x464384946369b2e7, 0x47a55b63664a4733),
        ] {
            let q = both(dividend, divisor, mode, float::div);
            assert_eq!((q.lo.to_bits(), q.hi.to_bits()), (lo, hi), "{mode:?}");
        }
    }
}
