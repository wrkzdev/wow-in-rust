//! SuperscalarHash: the generated programs that turn Cache blocks into
//! Dataset items (`superscalar.cpp`; RandomX spec §6).
//!
//! Generation simulates an Intel Ivy Bridge core -- decode buffers, execution
//! ports, instruction latencies -- so the programs are fast on CPUs and hard
//! to shortcut. None of that simulation is visible in the output except
//! through which instructions it picks, and every pick consumes generator
//! bytes, so it is ported branch for branch: one difference and every program
//! after it changes.

use crate::blake2b::Blake2Generator;

pub(crate) const ISUB_R: i32 = 0;
pub(crate) const IXOR_R: i32 = 1;
pub(crate) const IADD_RS: i32 = 2;
pub(crate) const IMUL_R: i32 = 3;
pub(crate) const IROR_C: i32 = 4;
pub(crate) const IADD_C7: i32 = 5;
pub(crate) const IXOR_C7: i32 = 6;
pub(crate) const IADD_C8: i32 = 7;
pub(crate) const IXOR_C8: i32 = 8;
pub(crate) const IADD_C9: i32 = 9;
pub(crate) const IXOR_C9: i32 = 10;
pub(crate) const IMULH_R: i32 = 11;
pub(crate) const ISMULH_R: i32 = 12;
pub(crate) const IMUL_RCP: i32 = 13;
const INVALID: i32 = -1;

/// x86 `r13`: `lea` cannot use it as a base without a displacement.
const REGISTER_NEEDS_DISPLACEMENT: i32 = 5;
const LOOK_FORWARD_CYCLES: i32 = 4;
const MAX_THROWAWAY_COUNT: i32 = 256;

/// Execution ports a micro-op may go to.
const P0: i32 = 1;
const P1: i32 = 2;
const P5: i32 = 4;
const P01: i32 = P0 | P1;
const P05: i32 = P0 | P5;
const P015: i32 = P0 | P1 | P5;

#[derive(Clone, Copy)]
struct MacroOp {
    /// x86 code size, which the reference tracks for statistics only.
    #[allow(dead_code, reason = "kept to match the reference table")]
    size: i32,
    latency: i32,
    uop1: i32,
    uop2: i32,
    dependent: bool,
}

const fn op(size: i32, latency: i32, uop1: i32, uop2: i32) -> MacroOp {
    MacroOp {
        size,
        latency,
        uop1,
        uop2,
        dependent: false,
    }
}

const SUB_RR: MacroOp = op(3, 1, P015, 0);
const XOR_RR: MacroOp = op(3, 1, P015, 0);
const IMUL_R_1: MacroOp = op(3, 4, P1, P5);
const MUL_R: MacroOp = op(3, 4, P1, P5);
const MOV_RR: MacroOp = op(3, 0, 0, 0);
const LEA_SIB: MacroOp = op(4, 1, P01, 0);
const IMUL_RR: MacroOp = op(4, 3, P1, 0);
const ROR_RI: MacroOp = op(4, 1, P05, 0);
const ADD_RI: MacroOp = op(7, 1, P015, 0);
const XOR_RI: MacroOp = op(7, 1, P015, 0);
const MOV_RI64: MacroOp = op(10, 1, P015, 0);
const IMUL_RR_DEPENDENT: MacroOp = MacroOp {
    dependent: true,
    ..IMUL_RR
};

/// `SuperscalarInstructionInfo`.
struct Info {
    kind: i32,
    ops: &'static [MacroOp],
    result_op: i32,
    dst_op: i32,
    src_op: i32,
}

const fn single(kind: i32, op: &'static [MacroOp], src_op: i32) -> Info {
    Info {
        kind,
        ops: op,
        result_op: 0,
        dst_op: 0,
        src_op,
    }
}

const I_ISUB_R: Info = single(ISUB_R, &[SUB_RR], 0);
const I_IXOR_R: Info = single(IXOR_R, &[XOR_RR], 0);
const I_IADD_RS: Info = single(IADD_RS, &[LEA_SIB], 0);
const I_IMUL_R: Info = single(IMUL_R, &[IMUL_RR], 0);
const I_IROR_C: Info = single(IROR_C, &[ROR_RI], -1);
const I_IADD_C7: Info = single(IADD_C7, &[ADD_RI], -1);
const I_IXOR_C7: Info = single(IXOR_C7, &[XOR_RI], -1);
const I_IADD_C8: Info = single(IADD_C8, &[ADD_RI], -1);
const I_IXOR_C8: Info = single(IXOR_C8, &[XOR_RI], -1);
const I_IADD_C9: Info = single(IADD_C9, &[ADD_RI], -1);
const I_IXOR_C9: Info = single(IXOR_C9, &[XOR_RI], -1);
const I_IMULH_R: Info = Info {
    kind: IMULH_R,
    ops: &[MOV_RR, MUL_R, MOV_RR],
    result_op: 1,
    dst_op: 0,
    src_op: 1,
};
const I_ISMULH_R: Info = Info {
    kind: ISMULH_R,
    ops: &[MOV_RR, IMUL_R_1, MOV_RR],
    result_op: 1,
    dst_op: 0,
    src_op: 1,
};
const I_IMUL_RCP: Info = Info {
    kind: IMUL_RCP,
    ops: &[MOV_RI64, IMUL_RR_DEPENDENT],
    result_op: 1,
    dst_op: 1,
    src_op: -1,
};
const I_NOP: Info = Info {
    kind: INVALID,
    ops: &[],
    result_op: 0,
    dst_op: 0,
    src_op: -1,
};

const SLOT_3: [&Info; 2] = [&I_ISUB_R, &I_IXOR_R];
const SLOT_3L: [&Info; 4] = [&I_ISUB_R, &I_IXOR_R, &I_IMULH_R, &I_ISMULH_R];
const SLOT_4: [&Info; 2] = [&I_IROR_C, &I_IADD_RS];
const SLOT_7: [&Info; 2] = [&I_IXOR_C7, &I_IADD_C7];
const SLOT_8: [&Info; 2] = [&I_IXOR_C8, &I_IADD_C8];
const SLOT_9: [&Info; 2] = [&I_IXOR_C9, &I_IADD_C9];

/// One way to split a 16-byte decode window into instruction slots.
struct DecoderBuffer {
    index: i32,
    counts: &'static [i32],
}

const BUFFER_484: DecoderBuffer = DecoderBuffer {
    index: 0,
    counts: &[4, 8, 4],
};
const BUFFER_7333: DecoderBuffer = DecoderBuffer {
    index: 1,
    counts: &[7, 3, 3, 3],
};
const BUFFER_3733: DecoderBuffer = DecoderBuffer {
    index: 2,
    counts: &[3, 7, 3, 3],
};
const BUFFER_493: DecoderBuffer = DecoderBuffer {
    index: 3,
    counts: &[4, 9, 3],
};
const BUFFER_4444: DecoderBuffer = DecoderBuffer {
    index: 4,
    counts: &[4, 4, 4, 4],
};
const BUFFER_3310: DecoderBuffer = DecoderBuffer {
    index: 5,
    counts: &[3, 3, 10],
};
const DEFAULT_BUFFERS: [&DecoderBuffer; 4] = [&BUFFER_484, &BUFFER_7333, &BUFFER_3733, &BUFFER_493];

/// `DecoderBuffer::fetchNext`.
fn fetch_next(
    kind: i32,
    cycle: i32,
    mul_count: i32,
    gen: &mut Blake2Generator,
) -> &'static DecoderBuffer {
    // A 128-bit multiplication decodes to two uOPs, so the next window is
    // 3-3-10.
    if kind == IMULH_R || kind == ISMULH_R {
        return &BUFFER_3310;
    }
    // Keep the multiplication port saturated.
    if mul_count < cycle + 1 {
        return &BUFFER_4444;
    }
    // IMUL_RCP ends in a 4-byte multiplication slot.
    if kind == IMUL_RCP {
        return if gen.get_byte() & 1 != 0 {
            &BUFFER_484
        } else {
            &BUFFER_493
        };
    }
    DEFAULT_BUFFERS[usize::from(gen.get_byte() & 3)]
}

#[derive(Clone, Copy)]
struct RegisterInfo {
    latency: i32,
    last_op_group: i32,
    last_op_par: i32,
}

/// The instruction being assembled (`SuperscalarInstruction`).
struct Current {
    info: &'static Info,
    src: i32,
    dst: i32,
    mod_: u8,
    imm32: u32,
    op_group: i32,
    op_group_par: i32,
    can_reuse: bool,
    group_par_is_source: bool,
}

fn select_register(available: &[i32], gen: &mut Blake2Generator) -> Option<i32> {
    match available.len() {
        0 => None,
        1 => Some(available[0]),
        n => Some(available[(gen.get_u32() % n as u32) as usize]),
    }
}

fn is_zero_or_power_of_2(x: u32) -> bool {
    x & x.wrapping_sub(1) == 0
}

impl Current {
    fn null() -> Current {
        Current {
            info: &I_NOP,
            src: -1,
            dst: -1,
            mod_: 0,
            imm32: 0,
            op_group: INVALID,
            op_group_par: 0,
            can_reuse: false,
            group_par_is_source: false,
        }
    }

    fn create(&mut self, info: &'static Info, gen: &mut Blake2Generator) {
        self.info = info;
        self.src = -1;
        self.dst = -1;
        self.can_reuse = false;
        self.group_par_is_source = false;
        match info.kind {
            ISUB_R => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = IADD_RS;
                self.group_par_is_source = true;
            }
            IXOR_R => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = IXOR_R;
                self.group_par_is_source = true;
            }
            IADD_RS => {
                self.mod_ = gen.get_byte();
                self.imm32 = 0;
                self.op_group = IADD_RS;
                self.group_par_is_source = true;
            }
            IMUL_R => {
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = IMUL_R;
                self.group_par_is_source = true;
            }
            IROR_C => {
                self.mod_ = 0;
                loop {
                    self.imm32 = u32::from(gen.get_byte() & 63);
                    if self.imm32 != 0 {
                        break;
                    }
                }
                self.op_group = IROR_C;
                self.op_group_par = -1;
            }
            IADD_C7 | IADD_C8 | IADD_C9 => {
                self.mod_ = 0;
                self.imm32 = gen.get_u32();
                self.op_group = IADD_C7;
                self.op_group_par = -1;
            }
            IXOR_C7 | IXOR_C8 | IXOR_C9 => {
                self.mod_ = 0;
                self.imm32 = gen.get_u32();
                self.op_group = IXOR_C7;
                self.op_group_par = -1;
            }
            IMULH_R | ISMULH_R => {
                self.can_reuse = true;
                self.mod_ = 0;
                self.imm32 = 0;
                self.op_group = info.kind;
                self.op_group_par = gen.get_u32() as i32;
            }
            IMUL_RCP => {
                self.mod_ = 0;
                loop {
                    self.imm32 = gen.get_u32();
                    if !is_zero_or_power_of_2(self.imm32) {
                        break;
                    }
                }
                self.op_group = IMUL_RCP;
                self.op_group_par = -1;
            }
            _ => {}
        }
    }

    fn create_for_slot(
        &mut self,
        gen: &mut Blake2Generator,
        slot_size: i32,
        fetch_type: i32,
        is_last: bool,
    ) {
        let info = match slot_size {
            3 if is_last => SLOT_3L[usize::from(gen.get_byte() & 3)],
            3 => SLOT_3[usize::from(gen.get_byte() & 1)],
            // The 4-4-4-4 window issues multiplications in its first three slots.
            4 if fetch_type == 4 && !is_last => &I_IMUL_R,
            4 => SLOT_4[usize::from(gen.get_byte() & 1)],
            7 => SLOT_7[usize::from(gen.get_byte() & 1)],
            8 => SLOT_8[usize::from(gen.get_byte() & 1)],
            9 => SLOT_9[usize::from(gen.get_byte() & 1)],
            _ => &I_IMUL_RCP,
        };
        self.create(info, gen);
    }

    fn select_destination(
        &mut self,
        cycle: i32,
        allow_chained_mul: bool,
        registers: &[RegisterInfo; 8],
        gen: &mut Blake2Generator,
    ) -> bool {
        let mut available = [0i32; 8];
        let mut n = 0;
        for (i, reg) in registers.iter().enumerate() {
            let i = i as i32;
            if reg.latency <= cycle
                && (self.can_reuse || i != self.src)
                && (allow_chained_mul || self.op_group != IMUL_R || reg.last_op_group != IMUL_R)
                && (reg.last_op_group != self.op_group || reg.last_op_par != self.op_group_par)
                && (self.info.kind != IADD_RS || i != REGISTER_NEEDS_DISPLACEMENT)
            {
                available[n] = i;
                n += 1;
            }
        }
        match select_register(&available[..n], gen) {
            Some(r) => {
                self.dst = r;
                true
            }
            None => false,
        }
    }

    fn select_source(
        &mut self,
        cycle: i32,
        registers: &[RegisterInfo; 8],
        gen: &mut Blake2Generator,
    ) -> bool {
        let mut available = [0i32; 8];
        let mut n = 0;
        for (i, reg) in registers.iter().enumerate() {
            if reg.latency <= cycle {
                available[n] = i as i32;
                n += 1;
            }
        }
        // With two registers left for IADD_RS and one of them r5, r5 must be
        // the source, since it cannot be the destination.
        if n == 2
            && self.info.kind == IADD_RS
            && (available[0] == REGISTER_NEEDS_DISPLACEMENT
                || available[1] == REGISTER_NEEDS_DISPLACEMENT)
        {
            self.op_group_par = REGISTER_NEEDS_DISPLACEMENT;
            self.src = REGISTER_NEEDS_DISPLACEMENT;
            return true;
        }
        match select_register(&available[..n], gen) {
            Some(r) => {
                self.src = r;
                if self.group_par_is_source {
                    self.op_group_par = r;
                }
                true
            }
            None => false,
        }
    }

    fn to_instruction(&self) -> Instruction {
        let dst = self.dst as u8;
        let src = if self.src >= 0 { self.src as u8 } else { dst };
        Instruction {
            opcode: self.info.kind as u8,
            dst,
            src,
            mod_: self.mod_,
            imm32: self.imm32,
            reciprocal: if self.info.kind == IMUL_RCP {
                reciprocal(self.imm32)
            } else {
                0
            },
        }
    }
}

fn is_multiplication(kind: i32) -> bool {
    matches!(kind, IMUL_R | IMULH_R | ISMULH_R | IMUL_RCP)
}

/// `scheduleUop`: the first cycle from `cycle` with a free port for `uop`,
/// trying P5, then P0, then P1.
fn schedule_uop(uop: i32, ports: &mut [[i32; 3]], mut cycle: i32, commit: bool) -> i32 {
    while cycle >= 0 && (cycle as usize) < ports.len() {
        let c = cycle as usize;
        for (mask, port) in [(P5, 2), (P0, 0), (P1, 1)] {
            if uop & mask != 0 && ports[c][port] == 0 {
                if commit {
                    ports[c][port] = uop;
                }
                return cycle;
            }
        }
        cycle += 1;
    }
    -1
}

/// `scheduleMop`.
fn schedule_mop(
    mop: &MacroOp,
    ports: &mut [[i32; 3]],
    mut cycle: i32,
    dep_cycle: i32,
    commit: bool,
) -> i32 {
    if mop.dependent {
        cycle = cycle.max(dep_cycle);
    }
    if mop.uop1 == 0 {
        // Eliminated (a register move): no execution port.
        return cycle;
    }
    if mop.uop2 == 0 {
        return schedule_uop(mop.uop1, ports, cycle, commit);
    }
    // Both uOPs must execute in the same cycle.
    while cycle >= 0 && (cycle as usize) < ports.len() {
        let c1 = schedule_uop(mop.uop1, ports, cycle, false);
        let c2 = schedule_uop(mop.uop2, ports, cycle, false);
        if c1 >= 0 && c1 == c2 {
            if commit {
                schedule_uop(mop.uop1, ports, c1, true);
                schedule_uop(mop.uop2, ports, c2, true);
            }
            return c1;
        }
        cycle += 1;
    }
    -1
}

/// One SuperscalarHash instruction, in RandomX's 8-byte form plus the
/// reciprocal an `IMUL_RCP` multiplies by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Instruction {
    pub(crate) opcode: u8,
    pub(crate) dst: u8,
    pub(crate) src: u8,
    pub(crate) mod_: u8,
    pub(crate) imm32: u32,
    pub(crate) reciprocal: u64,
}

impl Instruction {
    /// The 8 bytes `randomx::Instruction` holds.
    #[cfg(test)]
    pub(crate) fn to_bytes(self) -> [u8; 8] {
        let i = self.imm32.to_le_bytes();
        [
            self.opcode,
            self.dst,
            self.src,
            self.mod_,
            i[0],
            i[1],
            i[2],
            i[3],
        ]
    }
}

pub(crate) struct Program {
    pub(crate) instructions: Vec<Instruction>,
    /// The register whose value picks the next Cache block.
    pub(crate) address_register: usize,
}

/// `generateSuperscalar`.
pub(crate) fn generate(gen: &mut Blake2Generator, latency: u32) -> Program {
    let latency = latency as i32;
    let max_size = (3 * latency + 2) as usize;
    let mut ports = vec![[0i32; 3]; (latency + 4) as usize];
    let mut registers = [RegisterInfo {
        latency: 0,
        last_op_group: INVALID,
        last_op_par: -1,
    }; 8];
    let mut current = Current::null();
    let mut program: Vec<Instruction> = Vec::with_capacity(max_size);
    let mut macro_op_index = 0i32;
    let mut cycle = 0i32;
    let mut dep_cycle = 0i32;
    let mut ports_saturated = false;
    let mut mul_count = 0i32;
    let mut throw_away_count = 0i32;

    let mut decode_cycle = 0i32;
    while decode_cycle < latency && !ports_saturated && program.len() < max_size {
        let buffer = fetch_next(current.info.kind, decode_cycle, mul_count, gen);
        let mut buffer_index = 0usize;
        while buffer_index < buffer.counts.len() {
            let top_cycle = cycle;
            if macro_op_index >= current.info.ops.len() as i32 {
                if ports_saturated || program.len() >= max_size {
                    break;
                }
                current.create_for_slot(
                    gen,
                    buffer.counts[buffer_index],
                    buffer.index,
                    buffer.counts.len() == buffer_index + 1,
                );
                macro_op_index = 0;
            }
            let mop = current.info.ops[macro_op_index as usize];
            let mut schedule_cycle = schedule_mop(&mop, &mut ports, cycle, dep_cycle, false);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }

            if macro_op_index == current.info.src_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_source(schedule_cycle, &registers, gen)
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len() as i32;
                        continue;
                    }
                    current = Current::null();
                    break;
                }
            }

            if macro_op_index == current.info.dst_op {
                let mut forward = 0;
                while forward < LOOK_FORWARD_CYCLES
                    && !current.select_destination(
                        schedule_cycle,
                        throw_away_count > 0,
                        &registers,
                        gen,
                    )
                {
                    schedule_cycle += 1;
                    cycle += 1;
                    forward += 1;
                }
                if forward == LOOK_FORWARD_CYCLES {
                    if throw_away_count < MAX_THROWAWAY_COUNT {
                        throw_away_count += 1;
                        macro_op_index = current.info.ops.len() as i32;
                        continue;
                    }
                    current = Current::null();
                    break;
                }
            }
            throw_away_count = 0;

            schedule_cycle = schedule_mop(&mop, &mut ports, schedule_cycle, schedule_cycle, true);
            if schedule_cycle < 0 {
                ports_saturated = true;
                break;
            }
            dep_cycle = schedule_cycle + mop.latency;

            if macro_op_index == current.info.result_op {
                let reg = &mut registers[current.dst as usize];
                reg.latency = dep_cycle;
                reg.last_op_group = current.op_group;
                reg.last_op_par = current.op_group_par;
            }
            buffer_index += 1;
            macro_op_index += 1;
            if schedule_cycle >= latency {
                ports_saturated = true;
            }
            cycle = top_cycle;

            if macro_op_index >= current.info.ops.len() as i32 {
                program.push(current.to_instruction());
                mul_count += i32::from(is_multiplication(current.info.kind));
            }
        }
        cycle += 1;
        decode_cycle += 1;
    }

    // The address register is the one with the longest dependency chain,
    // assuming one cycle per operation and unlimited parallelism.
    let mut asic = [0i32; 8];
    for ins in &program {
        let (d, s) = (usize::from(ins.dst), usize::from(ins.src));
        let lat_dst = asic[d] + 1;
        let lat_src = if d != s { asic[s] + 1 } else { 0 };
        asic[d] = lat_dst.max(lat_src);
    }
    let mut highest = 0;
    let mut address_register = 0;
    for (i, lat) in asic.iter().enumerate() {
        if *lat > highest {
            highest = *lat;
            address_register = i;
        }
    }
    Program {
        instructions: program,
        address_register,
    }
}

/// `executeSuperscalar`.
#[inline]
pub(crate) fn execute(r: &mut [u64; 8], program: &Program) {
    for ins in &program.instructions {
        let d = usize::from(ins.dst);
        let s = usize::from(ins.src);
        let imm = ins.imm32 as i32 as i64 as u64;
        match i32::from(ins.opcode) {
            ISUB_R => r[d] = r[d].wrapping_sub(r[s]),
            IXOR_R => r[d] ^= r[s],
            IADD_RS => r[d] = r[d].wrapping_add(r[s] << ((ins.mod_ >> 2) % 4)),
            IMUL_R => r[d] = r[d].wrapping_mul(r[s]),
            IROR_C => r[d] = r[d].rotate_right(ins.imm32),
            IADD_C7 | IADD_C8 | IADD_C9 => r[d] = r[d].wrapping_add(imm),
            IXOR_C7 | IXOR_C8 | IXOR_C9 => r[d] ^= imm,
            IMULH_R => r[d] = ((u128::from(r[d]) * u128::from(r[s])) >> 64) as u64,
            ISMULH_R => {
                r[d] = ((i128::from(r[d] as i64) * i128::from(r[s] as i64)) >> 64) as u64;
            }
            _ => r[d] = r[d].wrapping_mul(ins.reciprocal),
        }
    }
}

/// `randomx_reciprocal`: 2^x / divisor for the largest x keeping it under
/// 2^64. `divisor` is neither 0 nor a power of 2.
pub(crate) fn reciprocal(divisor: u32) -> u64 {
    let d = u64::from(divisor);
    let p2exp63 = 1u64 << 63;
    let q = p2exp63 / d;
    let r = p2exp63 % d;
    let shift = 64 - d.leading_zeros();
    (q << shift) + ((r << shift) / d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake2b::blake2b;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// `tests.cpp`, "randomx_reciprocal".
    #[test]
    fn reciprocals_match_the_reference() {
        assert_eq!(reciprocal(3), 12297829382473034410);
        assert_eq!(reciprocal(13), 11351842506898185609);
        assert_eq!(reciprocal(33), 17887751829051686415);
        assert_eq!(reciprocal(65537), 18446462603027742720);
        assert_eq!(reciprocal(15000001), 10316166306300415204);
        assert_eq!(reciprocal(3845182035), 10302264209224146340);
        assert_eq!(reciprocal(0xffffffff), 9223372039002259456);
    }

    /// `tests.cpp`, "SuperscalarHash generator": ten programs from one
    /// generator keyed "test key 000", each hashed over its 8-byte
    /// instructions. The latency is 170 in RandomWOW and upstream alike.
    #[test]
    fn generated_programs_match_the_reference() {
        let expected = [
            "d3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61",
            "f5e7e0bbc7e93c609003d6359208688070afb4a77165a552ff7be63b38dfbc86",
            "85ed8b11734de5b3e9836641413a8f36e99e89694f419c8cd25c3f3f16c40c5a",
            "5dd956292cf5d5704ad99e362d70098b2777b2a1730520be52f772ca48cd3bc0",
            "6f14018ca7d519e9b48d91af094c0f2d7e12e93af0228782671a8640092af9e5",
            "134be097c92e2c45a92f23208cacd89e4ce51f1009a0b900dbe83b38de11d791",
            "268f9392c20c6e31371a5131f82bd7713d3910075f2f0468baafaa1abd2f3187",
            "c668a05fd909714ed4a91e8d96d67b17e44329e88bc71e0672b529a3fc16be47",
            "99739351315840963011e4c5d8e90ad0bfed3facdcb713fe8f7138fbf01c4c94",
            "14ab53d61880471f66e80183968d97effd5492b406876060e595fcf9682f9295",
        ];
        let mut gen = Blake2Generator::new(b"test key 000", 0);
        for (i, want) in expected.iter().enumerate() {
            let program = generate(&mut gen, 170);
            let bytes: Vec<u8> = program
                .instructions
                .iter()
                .flat_map(|ins| ins.to_bytes())
                .collect();
            let mut hash = [0u8; 32];
            blake2b(&mut hash, &bytes);
            assert_eq!(hex(&hash), *want, "program {i}");
        }
    }
}
