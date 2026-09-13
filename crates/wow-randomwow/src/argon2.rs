//! The Argon2d fill that builds the RandomX Cache (`argon2_core.c`,
//! `argon2_ref.c`; RandomX spec §7.1).
//!
//! RandomX uses Argon2d's memory, not its output: the Cache *is* the filled
//! block array. It hashes an output length of 0 into the initial block, which
//! a general Argon2 library does not allow, so this is RandomX's own fill.

#![allow(
    clippy::needless_range_loop,
    reason = "indices follow the reference implementation's block arithmetic"
)]

use crate::blake2b::{blake2b_long, Blake2b};
use crate::params::Config;

/// Words in one 1 KiB block.
pub(crate) const BLOCK_WORDS: usize = 128;
const SYNC_POINTS: u32 = 4;
const VERSION: u32 = 0x13;
/// `Argon2_d`.
const TYPE_D: u32 = 0;

/// Fill `memory` (`argon_memory` blocks of 128 words) from `key`.
pub(crate) fn fill(memory: &mut [u64], key: &[u8], cfg: &Config) {
    let lanes = cfg.argon_lanes;
    let blocks = cfg.argon_memory;
    debug_assert_eq!(memory.len(), blocks as usize * BLOCK_WORDS);
    let segment_length = blocks / (lanes * SYNC_POINTS);
    let lane_length = segment_length * SYNC_POINTS;

    // H0: the parameters and inputs, with an output length of 0.
    let mut h = Blake2b::new(64);
    for v in [
        lanes,
        0,
        blocks,
        cfg.argon_iterations,
        VERSION,
        TYPE_D,
        key.len() as u32,
    ] {
        h.update(&v.to_le_bytes());
    }
    h.update(key);
    h.update(&(cfg.argon_salt.len() as u32).to_le_bytes());
    h.update(cfg.argon_salt);
    h.update(&0u32.to_le_bytes()); // no secret
    h.update(&0u32.to_le_bytes()); // no associated data
    let mut seed = [0u8; 72];
    h.finalize(&mut seed[..64]);

    // The first two blocks of each lane: H'(H0 || i || lane).
    for lane in 0..lanes {
        for i in 0..2u32 {
            seed[64..68].copy_from_slice(&i.to_le_bytes());
            seed[68..72].copy_from_slice(&lane.to_le_bytes());
            let mut bytes = [0u8; 1024];
            blake2b_long(&mut bytes, &seed);
            let base = (lane * lane_length + i) as usize * BLOCK_WORDS;
            for (w, chunk) in memory[base..base + BLOCK_WORDS]
                .iter_mut()
                .zip(bytes.as_chunks::<8>().0)
            {
                *w = u64::from_le_bytes(*chunk);
            }
        }
    }

    let shape = Shape {
        lanes,
        segment_length,
        lane_length,
    };
    for pass in 0..cfg.argon_iterations {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                fill_segment(memory, &shape, pass, lane, slice);
            }
        }
    }
}

struct Shape {
    lanes: u32,
    segment_length: u32,
    lane_length: u32,
}

/// `randomx_argon2_index_alpha`: the reference block for position `index`.
fn index_alpha(
    s: &Shape,
    pass: u32,
    slice: u32,
    index: u32,
    pseudo_rand: u32,
    same_lane: bool,
) -> u32 {
    let area: u32 = if pass == 0 {
        if slice == 0 {
            index.wrapping_sub(1)
        } else if same_lane {
            (slice * s.segment_length + index).wrapping_sub(1)
        } else {
            (slice * s.segment_length).wrapping_add(if index == 0 { u32::MAX } else { 0 })
        }
    } else if same_lane {
        (s.lane_length - s.segment_length + index).wrapping_sub(1)
    } else {
        (s.lane_length - s.segment_length).wrapping_add(if index == 0 { u32::MAX } else { 0 })
    };
    let area = u64::from(area);
    let mut relative = u64::from(pseudo_rand);
    relative = (relative * relative) >> 32;
    relative = area - 1 - ((area * relative) >> 32);
    let start = if pass != 0 {
        if slice == SYNC_POINTS - 1 {
            0
        } else {
            (slice + 1) * s.segment_length
        }
    } else {
        0
    };
    ((u64::from(start) + relative) % u64::from(s.lane_length)) as u32
}

/// `randomx_argon2_fill_segment_ref`.
fn fill_segment(memory: &mut [u64], s: &Shape, pass: u32, lane: u32, slice: u32) {
    let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };
    let first = lane * s.lane_length + slice * s.segment_length + starting_index;
    let mut prev = if first.is_multiple_of(s.lane_length) {
        first + s.lane_length - 1
    } else {
        first - 1
    };
    for (index, curr) in (starting_index..s.segment_length).zip(first..) {
        if curr % s.lane_length == 1 {
            prev = curr - 1;
        }
        let pseudo_rand = memory[prev as usize * BLOCK_WORDS];
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            ((pseudo_rand >> 32) % u64::from(s.lanes)) as u32
        };
        let ref_index = index_alpha(s, pass, slice, index, pseudo_rand as u32, ref_lane == lane);
        let reference = s.lane_length * ref_lane + ref_index;
        fill_block(memory, prev, reference, curr, pass != 0);
        prev += 1;
    }
}

#[inline(always)]
fn blamka(x: u64, y: u64) -> u64 {
    let xy = (x & 0xffff_ffff) * (y & 0xffff_ffff);
    x.wrapping_add(y).wrapping_add(xy.wrapping_mul(2))
}

#[inline(always)]
fn g(v: &mut [u64; BLOCK_WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// `BLAKE2_ROUND_NOMSG` over the sixteen words at `i`.
#[inline(always)]
fn round(v: &mut [u64; BLOCK_WORDS], i: [usize; 16]) {
    g(v, i[0], i[4], i[8], i[12]);
    g(v, i[1], i[5], i[9], i[13]);
    g(v, i[2], i[6], i[10], i[14]);
    g(v, i[3], i[7], i[11], i[15]);
    g(v, i[0], i[5], i[10], i[15]);
    g(v, i[1], i[6], i[11], i[12]);
    g(v, i[2], i[7], i[8], i[13]);
    g(v, i[3], i[4], i[9], i[14]);
}

/// `fill_block`: the new block is `P(ref ^ prev) ^ ref ^ prev`, XORed over the
/// old one after the first pass.
fn fill_block(memory: &mut [u64], prev: u32, reference: u32, curr: u32, with_xor: bool) {
    let (p, r, c) = (
        prev as usize * BLOCK_WORDS,
        reference as usize * BLOCK_WORDS,
        curr as usize * BLOCK_WORDS,
    );
    let mut state = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        state[i] = memory[r + i] ^ memory[p + i];
    }
    let mut keep = state;
    if with_xor {
        for i in 0..BLOCK_WORDS {
            keep[i] ^= memory[c + i];
        }
    }
    for i in 0..8 {
        let b = 16 * i;
        round(
            &mut state,
            [
                b,
                b + 1,
                b + 2,
                b + 3,
                b + 4,
                b + 5,
                b + 6,
                b + 7,
                b + 8,
                b + 9,
                b + 10,
                b + 11,
                b + 12,
                b + 13,
                b + 14,
                b + 15,
            ],
        );
    }
    for i in 0..8 {
        let b = 2 * i;
        round(
            &mut state,
            [
                b,
                b + 1,
                b + 16,
                b + 17,
                b + 32,
                b + 33,
                b + 48,
                b + 49,
                b + 64,
                b + 65,
                b + 80,
                b + 81,
                b + 96,
                b + 97,
                b + 112,
                b + 113,
            ],
        );
    }
    for i in 0..BLOCK_WORDS {
        memory[c + i] = keep[i] ^ state[i];
    }
}
