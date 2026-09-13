//! SuperscalarHash compiled to x86-64 machine code.
//!
//! Light mode computes a Dataset item for every VM iteration, and an item runs
//! eight SuperscalarHash programs of about 450 instructions: some 59 million
//! instructions a hash, which interpreted is most of a light hash's time.
//! SuperscalarHash was designed so that each of its instructions is one or two
//! x86-64 instructions, and this emits exactly those, with the C++'s register
//! assignment (`jit_compiler_x86.cpp`, `generateSuperscalarCode`): RandomX
//! register `i` is `r8 + i`.
//!
//! Only SuperscalarHash. It is the easy part to compile -- fourteen instruction
//! types over eight integer registers, with no memory access, no branches and
//! no floating point -- and the part that matters for verifying. The code is
//! written into pages that become executable only once complete and are never
//! writable again.
//!
//! Elsewhere, or where the operating system refuses executable memory, the
//! interpreter in [`crate::superscalar`] runs instead. The tests hold the two
//! to the same registers, over generated programs and over every instruction
//! with every register pair.

use crate::superscalar::{
    Program, IADD_C7, IADD_C8, IADD_C9, IADD_RS, IMULH_R, IMUL_R, IMUL_RCP, IROR_C, ISMULH_R,
    ISUB_R, IXOR_C7, IXOR_C8, IXOR_C9, IXOR_R,
};

#[cfg(all(target_arch = "x86_64", any(unix, windows)))]
pub(crate) use native::Compiled;
#[cfg(not(all(target_arch = "x86_64", any(unix, windows))))]
pub(crate) use portable::Compiled;

/// Whether this build compiles SuperscalarHash at all. The OS may still refuse
/// executable memory, which [`Compiled::new`] reports.
pub(crate) fn available() -> bool {
    cfg!(all(target_arch = "x86_64", any(unix, windows)))
}

const REX_W: u8 = 0x48;
/// Extends ModRM's `reg` field to r8-r15.
const REX_R: u8 = 0x04;
/// Extends SIB's `index` field.
const REX_X: u8 = 0x02;
/// Extends ModRM's `rm` field, or SIB's `base`.
const REX_B: u8 = 0x01;
/// `RegisterNeedsDisplacement`: r13 as a base needs an explicit displacement.
const R13: u8 = 5;

/// Save r12-r15, which sysv64 has the callee preserve, and load the registers
/// from the eight words at `rdi`.
fn prologue(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
    for i in 0..8u8 {
        // mov r8+i, [rdi + 8i]
        code.extend_from_slice(&[REX_W | REX_R, 0x8b, 0x47 | (i << 3), 8 * i]);
    }
}

/// Store the registers back, restore r12-r15 and return.
fn epilogue(code: &mut Vec<u8>) {
    for i in 0..8u8 {
        // mov [rdi + 8i], r8+i
        code.extend_from_slice(&[REX_W | REX_R, 0x89, 0x47 | (i << 3), 8 * i]);
    }
    code.extend_from_slice(&[0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0xc3]);
}

/// Machine code for `programs`, one `extern "sysv64" fn(*mut u64)` each over
/// the eight words its argument points at, and where each function starts.
///
/// `None` for an instruction outside SuperscalarHash's fourteen or a register
/// past r7, neither of which a generated program holds.
#[cfg_attr(
    not(all(target_arch = "x86_64", any(unix, windows))),
    allow(dead_code, reason = "only compiled code runs it")
)]
pub(crate) fn emit(programs: &[Program]) -> Option<(Vec<u8>, Vec<usize>)> {
    let mut code = Vec::with_capacity(programs.len() * 4096);
    let mut entries = Vec::with_capacity(programs.len());
    for program in programs {
        entries.push(code.len());
        prologue(&mut code);
        for ins in &program.instructions {
            let (d, s) = (ins.dst, ins.src);
            if d > 7 || s > 7 {
                return None;
            }
            let reg_reg = 0xc0 | (d << 3) | s;
            let imm = ins.imm32.to_le_bytes();
            match i32::from(ins.opcode) {
                // sub rd, rs
                ISUB_R => code.extend_from_slice(&[REX_W | REX_R | REX_B, 0x2b, reg_reg]),
                // xor rd, rs
                IXOR_R => code.extend_from_slice(&[REX_W | REX_R | REX_B, 0x33, reg_reg]),
                // lea rd, [rd + rs * 2^shift]
                IADD_RS => {
                    let sib = (((ins.mod_ >> 2) % 4) << 6) | (s << 3) | d;
                    let rex = REX_W | REX_R | REX_X | REX_B;
                    if d == R13 {
                        code.extend_from_slice(&[rex, 0x8d, 0x44 | (d << 3), sib, 0]);
                    } else {
                        code.extend_from_slice(&[rex, 0x8d, 0x04 | (d << 3), sib]);
                    }
                }
                // imul rd, rs
                IMUL_R => code.extend_from_slice(&[REX_W | REX_R | REX_B, 0x0f, 0xaf, reg_reg]),
                // ror rd, imm8
                IROR_C => {
                    code.extend_from_slice(&[REX_W | REX_B, 0xc1, 0xc8 | d, (ins.imm32 & 63) as u8])
                }
                // add rd, imm32 (sign-extended)
                IADD_C7 | IADD_C8 | IADD_C9 => {
                    code.extend_from_slice(&[REX_W | REX_B, 0x81, 0xc0 | d]);
                    code.extend_from_slice(&imm);
                }
                // xor rd, imm32 (sign-extended)
                IXOR_C7 | IXOR_C8 | IXOR_C9 => {
                    code.extend_from_slice(&[REX_W | REX_B, 0x81, 0xf0 | d]);
                    code.extend_from_slice(&imm);
                }
                // mov rax, rd; mul rs (imul for the signed form); mov rd, rdx
                IMULH_R | ISMULH_R => {
                    let group = if i32::from(ins.opcode) == IMULH_R {
                        0xe0
                    } else {
                        0xe8
                    };
                    code.extend_from_slice(&[REX_W | REX_B, 0x8b, 0xc0 | d]);
                    code.extend_from_slice(&[REX_W | REX_B, 0xf7, group | s]);
                    code.extend_from_slice(&[REX_W | REX_R, 0x8b, 0xc2 | (d << 3)]);
                }
                // mov rax, imm64; imul rd, rax
                IMUL_RCP => {
                    code.extend_from_slice(&[REX_W, 0xb8]);
                    code.extend_from_slice(&ins.reciprocal.to_le_bytes());
                    code.extend_from_slice(&[REX_W | REX_R, 0x0f, 0xaf, 0xc0 | (d << 3)]);
                }
                _ => return None,
            }
        }
        epilogue(&mut code);
    }
    Some((code, entries))
}

#[cfg(all(target_arch = "x86_64", any(unix, windows)))]
mod native {
    use super::emit;
    use crate::superscalar::Program;

    /// Compiled SuperscalarHash programs.
    pub(crate) struct Compiled {
        pages: Pages,
        entries: Vec<usize>,
    }

    impl Compiled {
        /// `None` when the OS refuses executable memory.
        pub(crate) fn new(programs: &[Program]) -> Option<Compiled> {
            let (code, entries) = emit(programs)?;
            Some(Compiled {
                pages: Pages::new(&code)?,
                entries,
            })
        }

        /// Run program `index` over `r`.
        #[inline]
        pub(crate) fn execute(&self, index: usize, r: &mut [u64; 8]) {
            let entry = self.pages.ptr.wrapping_add(self.entries[index]);
            // SAFETY: `entry` is where `emit` began this program's function,
            // inside pages that hold exactly `emit`'s output and were made
            // executable. The function keeps to sysv64: it reads and writes the
            // eight words at its argument, which `r` is, touches no other
            // memory, restores the callee-saved registers it uses and returns.
            unsafe {
                let f = std::mem::transmute::<*mut u8, unsafe extern "sysv64" fn(*mut u64)>(entry);
                f(r.as_mut_ptr());
            }
        }
    }

    /// Memory for machine code: filled while writable, then switched to read
    /// and execute before anything runs from it.
    struct Pages {
        ptr: *mut u8,
        len: usize,
    }

    // SAFETY: once `Pages::new` returns the memory is never written again, so
    // it can be shared and sent between threads like an immutable slice.
    unsafe impl Send for Pages {}
    unsafe impl Sync for Pages {}

    impl Pages {
        fn new(code: &[u8]) -> Option<Pages> {
            let len = code.len().max(1);
            let ptr = os::map(len)?;
            // SAFETY: `ptr` is a fresh writable mapping of `len >= code.len()`
            // bytes, so it cannot overlap `code`.
            unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
            // Built before the protection change so a failure still unmaps.
            let pages = Pages { ptr, len };
            // SAFETY: `ptr..ptr + len` is the mapping `os::map` returned.
            unsafe { os::make_executable(ptr, len) }.then_some(pages)
        }
    }

    impl Drop for Pages {
        fn drop(&mut self) {
            // SAFETY: the mapping `os::map` returned; with `self` going, no
            // `Compiled` is left to run code from it.
            unsafe { os::unmap(self.ptr, self.len) };
        }
    }

    #[cfg(unix)]
    mod os {
        pub(super) fn map(len: usize) -> Option<*mut u8> {
            // SAFETY: an anonymous private mapping at an address the kernel
            // chooses affects no existing memory.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            (p != libc::MAP_FAILED).then_some(p.cast())
        }

        /// # Safety
        /// `ptr..ptr + len` must be a mapping [`map`] returned.
        pub(super) unsafe fn make_executable(ptr: *mut u8, len: usize) -> bool {
            // SAFETY: the caller's.
            unsafe { libc::mprotect(ptr.cast(), len, libc::PROT_READ | libc::PROT_EXEC) == 0 }
        }

        /// # Safety
        /// As [`make_executable`], and nothing may run code from it any more.
        pub(super) unsafe fn unmap(ptr: *mut u8, len: usize) {
            // SAFETY: the caller's.
            unsafe { libc::munmap(ptr.cast(), len) };
        }
    }

    #[cfg(windows)]
    mod os {
        use std::ffi::c_void;

        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const MEM_RELEASE: u32 = 0x8000;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE_READ: u32 = 0x20;

        // kernel32, which every Windows program links; three functions do not
        // need a bindings crate.
        #[allow(non_snake_case, reason = "the Win32 names")]
        #[link(name = "kernel32")]
        extern "system" {
            fn VirtualAlloc(
                address: *mut c_void,
                size: usize,
                allocation_type: u32,
                protect: u32,
            ) -> *mut c_void;
            fn VirtualProtect(
                address: *mut c_void,
                size: usize,
                new_protect: u32,
                old_protect: *mut u32,
            ) -> i32;
            fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        }

        pub(super) fn map(len: usize) -> Option<*mut u8> {
            // SAFETY: a fresh allocation at an address the system chooses
            // affects no existing memory.
            let p = unsafe {
                VirtualAlloc(
                    std::ptr::null_mut(),
                    len,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            (!p.is_null()).then_some(p.cast())
        }

        /// # Safety
        /// `ptr..ptr + len` must be an allocation [`map`] returned.
        pub(super) unsafe fn make_executable(ptr: *mut u8, len: usize) -> bool {
            let mut old = 0u32;
            // SAFETY: the caller's.
            unsafe { VirtualProtect(ptr.cast(), len, PAGE_EXECUTE_READ, &mut old) != 0 }
        }

        /// # Safety
        /// As [`make_executable`], and nothing may run code from it any more.
        pub(super) unsafe fn unmap(ptr: *mut u8, _len: usize) {
            // SAFETY: the caller's. `MEM_RELEASE` takes the base address and a
            // size of zero.
            unsafe { VirtualFree(ptr.cast(), 0, MEM_RELEASE) };
        }
    }
}

#[cfg(not(all(target_arch = "x86_64", any(unix, windows))))]
mod portable {
    use crate::superscalar::Program;

    /// No compiler for this target: never constructed.
    pub(crate) enum Compiled {}

    impl Compiled {
        pub(crate) fn new(_programs: &[Program]) -> Option<Compiled> {
            None
        }

        pub(crate) fn execute(&self, _index: usize, _r: &mut [u64; 8]) {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superscalar::Instruction;

    fn one(opcode: i32, dst: u8, src: u8, mod_: u8, imm32: u32, reciprocal: u64) -> Program {
        Program {
            instructions: vec![Instruction {
                opcode: opcode as u8,
                dst,
                src,
                mod_,
                imm32,
                reciprocal,
            }],
            address_register: 0,
        }
    }

    /// The bytes `jit_compiler_x86.cpp` emits for the same instructions.
    #[test]
    fn instructions_encode_as_the_cpp_emits_them() {
        let body = |p: Program| {
            let (code, _) = emit(&[p]).expect("known instruction");
            code[40..code.len() - 41].to_vec()
        };
        assert_eq!(body(one(ISUB_R, 0, 1, 0, 0, 0)), [0x4d, 0x2b, 0xc1]);
        assert_eq!(
            body(one(IMULH_R, 2, 3, 0, 0, 0)),
            [0x49, 0x8b, 0xc2, 0x49, 0xf7, 0xe3, 0x4c, 0x8b, 0xd2]
        );
        assert_eq!(body(one(IADD_RS, 1, 6, 12, 0, 0)), [0x4f, 0x8d, 0x0c, 0xf1]);
        assert_eq!(
            body(one(IXOR_C9, 7, 0, 0, 0x8000_0001, 0)),
            [0x49, 0x81, 0xf7, 0x01, 0x00, 0x00, 0x80]
        );
        assert!(emit(&[one(IMUL_R, 8, 0, 0, 0, 0)]).is_none());
        assert!(emit(&[one(14, 0, 1, 0, 0, 0)]).is_none());
    }

    #[cfg(all(target_arch = "x86_64", any(unix, windows)))]
    mod running {
        use super::*;
        use crate::blake2b::Blake2Generator;
        use crate::superscalar;

        fn xorshift(x: &mut u64) -> u64 {
            *x ^= *x << 13;
            *x ^= *x >> 7;
            *x ^= *x << 17;
            *x
        }

        fn same_as_interpreted(programs: &[Program], rng: &mut u64) {
            let compiled = Compiled::new(programs).expect("executable memory");
            for (i, p) in programs.iter().enumerate() {
                let mut interpreted = [0u64; 8];
                interpreted.iter_mut().for_each(|r| *r = xorshift(rng));
                let mut native = interpreted;
                superscalar::execute(&mut interpreted, p);
                compiled.execute(i, &mut native);
                assert_eq!(native, interpreted, "program {i}: {:?}", p.instructions);
            }
        }

        #[test]
        fn generated_programs_run_as_interpreted() {
            let mut rng = 0x9e37_79b9_7f4a_7c15;
            for key in 0..16u8 {
                let mut gen = Blake2Generator::new(&[key; 32], 0);
                let programs: Vec<Program> = (0..8)
                    .map(|_| superscalar::generate(&mut gen, 170))
                    .collect();
                same_as_interpreted(&programs, &mut rng);
            }
        }

        /// Including the forms a generated program avoids, such as r13 as the
        /// base of `IADD_RS`, which needs a displacement byte.
        #[test]
        fn every_instruction_and_register_pair_runs_as_interpreted() {
            let mut programs = Vec::new();
            for d in 0..8u8 {
                for s in 0..8u8 {
                    for op in [ISUB_R, IXOR_R, IMUL_R, IMULH_R, ISMULH_R] {
                        programs.push(one(op, d, s, 0, 0, 0));
                    }
                    for shift in 0..4u8 {
                        programs.push(one(IADD_RS, d, s, shift << 2, 0, 0));
                    }
                }
                for imm in [1u32, 17, 63] {
                    programs.push(one(IROR_C, d, 0, 0, imm, 0));
                }
                for imm in [0x7fff_ffffu32, 0x8000_0000, 0xdead_beef] {
                    for op in [IADD_C7, IADD_C8, IADD_C9, IXOR_C7, IXOR_C8, IXOR_C9] {
                        programs.push(one(op, d, 0, 0, imm, 0));
                    }
                }
                for divisor in [3u32, 0xffff_fff7] {
                    let rcp = superscalar::reciprocal(divisor);
                    programs.push(one(IMUL_RCP, d, 0, 0, divisor, rcp));
                }
            }
            let mut rng = 1;
            for _ in 0..4 {
                same_as_interpreted(&programs, &mut rng);
            }
        }
    }
}
