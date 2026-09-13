# 07 — Difficulty

Source: `src/cryptonote_basic/difficulty.cpp`,
`src/cryptonote_core/blockchain.cpp` (`get_difficulty_for_next_block`,
`get_next_difficulty_for_alternative_chain`, `recalculate_difficulties`).

Wownero changed its difficulty algorithm **six times**. All six must be
implemented, because a from-genesis sync re-derives cumulative difficulty at every
height, and cumulative difficulty is what decides reorgs.

Difficulty is `u128` (`boost::multiprecision::uint128_t`). Intermediate products
need 256 bits.

---

## 1. Data collected

For the block about to be added at height `H` (so the chain currently has `H`
blocks, heights `0..H-1`):

```
version = get_current_hard_fork_version()        # the TIP's version (see §3 note)

difficulty_blocks_count =
      if version >= 20                     { DIFFICULTY_BLOCKS_COUNT_V4 = 147 }
 else if version <= 17 && version >= 11    { DIFFICULTY_BLOCKS_COUNT_V3 = 145 }
 else if version <= 10 && version >= 8     { DIFFICULTY_BLOCKS_COUNT_V2 = 61  }
 else                                      { DIFFICULTY_BLOCKS_COUNT    = 735 }

offset = H - min(H, difficulty_blocks_count)
if offset == 0 { offset = 1 }                    # skip genesis
timestamps    = [ block_timestamp(i)             for i in offset..H ]
difficulties  = [ block_cumulative_difficulty(i) for i in offset..H ]
target        = get_difficulty_target()          # 300
HEIGHT        = db_height()                      # == H
```

Note that **versions 18 and 19 fall through to the last branch**, so they use
`DIFFICULTY_BLOCKS_COUNT = 735` and algorithm v1.

`get_difficulty_target()` is
`if get_current_hard_fork_version() < 2 { DIFFICULTY_TARGET_V1 } else { DIFFICULTY_TARGET_V2 }`
— and since both are 300 on Wownero, it is **always 300**.

### 1.1 Incremental cache

The C++ keeps `m_timestamps` / `m_difficulties` and appends one entry when
`height - m_timestamps_and_difficulties_height == 1`, trimming from the front.
A Rust implementation MAY cache the same way but MUST invalidate the cache on
reorg and on `m_reset_timestamps_and_difficulties_height`. Simplest correct
approach: rebuild the window from the DB, and only add a cache once M2 passes.

---

## 2. Algorithm selection

```rust
let diff = if version >= 20 {
    next_difficulty_v6(timestamps, difficulties, target, HEIGHT, nettype)
} else if version <= 17 && version >= 11 {
    next_difficulty_v5(timestamps, difficulties, HEIGHT, nettype)
} else if version == 10 {
    next_difficulty_v4(timestamps, difficulties, HEIGHT, nettype)
} else if version == 9 {
    next_difficulty_v3(timestamps, difficulties, HEIGHT, nettype)
} else if version == 8 {
    next_difficulty_v2(timestamps, difficulties, target, HEIGHT, nettype)
} else {
    next_difficulty(timestamps, difficulties, target, HEIGHT, nettype)
};
```

| Hard-fork version | Mainnet heights | Algorithm | Window |
|---|---|---|---|
| 7 | 1 – 6,968 | `next_difficulty` (v1, CryptoNote/Monero classic) | 720, cut 60, lag 15 |
| 8 | 6,969 – 53,665 | `next_difficulty_v2` (LWMA, Zawy) | 60 |
| 9 | 53,666 – 63,468 | `next_difficulty_v3` (LWMA-2) | 60 |
| 10 | 63,469 – 81,768 | `next_difficulty_v4` (LWMA-4) | 60 |
| 11 – 17 | 81,769 – 331,169 | `next_difficulty_v5` (LWMA-1, N=144) | 144 |
| **18, 19** | 331,170 – 513,999 | **`next_difficulty` (v1 again)** | 720, cut 60, lag 15 |
| 20 | 514,000 – tip | `next_difficulty_v6` (v1 shape, N=144) | 144, cut 12 |

The HF 18 switch back to Monero's classic algorithm is the "Reset difficulty and
switch back to Monero's difficulty algorithm" item in the README.

---

## 3. The algorithms

> **Critical: `HEIGHT` is the current chain height, not the height of the block
> being validated, and `version` is `get_current_hard_fork_version()` — the
> version at that chain height, the next block's, not the tip block's.** Several
> algorithms
> branch on `HEIGHT`, so during initial sync the branch taken depends on how far
> the chain has progressed. `recalculate_difficulties` reproduces this by passing
> `m_db->height()` (the *final* height) rather than the loop height — meaning a
> recalculation run and a live sync can take different branches. Reproduce the
> call sites literally; do not normalise `HEIGHT`.

### 3.1 `next_difficulty` (v1) — used by HF 7, 18, 19

```rust
fn next_difficulty(mut ts: Vec<u64>, mut cd: Vec<u128>,
                   target: u64, height: u64, net: Network) -> u128 {
    if (net == Testnet || net == Stagenet) && height <= DIFFICULTY_WINDOW /*720*/ {
        return 100;
    }
    if ts.len() > DIFFICULTY_WINDOW {            // trim the LAG from the tail
        ts.truncate(DIFFICULTY_WINDOW);
        cd.truncate(DIFFICULTY_WINDOW);
    }
    let length = ts.len();
    if length <= 1 { return 1; }

    // ---- mainnet difficulty reset at HF 18 ----
    if net == Mainnet && height <= 331_170 + DIFFICULTY_WINDOW && height >= 331_170 {
        return 100_000_000;
    }

    ts.sort();
    let (cut_begin, cut_end) = if length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT {
        (0, length)                               // 720 - 120 = 600
    } else {
        let cb = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) / 2;
        (cb, cb + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT))
    };
    let mut time_span = ts[cut_end - 1] - ts[cut_begin];
    if time_span == 0 { time_span = 1; }
    let total_work = cd[cut_end - 1] - cd[cut_begin];
    let res: U256 = (U256::from(total_work) * target + time_span - 1) / time_span;
    if res > U256::from(u128::MAX) { 0 } else { res.as_u128() }
}
```

Note `ts.truncate(720)` keeps the **first** 720 of the up-to-735 collected
entries — i.e. it drops the 15 most recent (the "lag"), because the vectors are
ordered oldest-first.

Note also that the `cd` vector is **not** sorted, only `ts` is. This is the
classic CryptoNote algorithm's behaviour.

The `height <= 331170 + 720 && height >= 331170` clause pins mainnet difficulty
to **100,000,000** for 721 heights starting at the HF 18 activation — the
difficulty reset.

### 3.2 `next_difficulty_v2` (LWMA) — HF 8

**Uses floating point.** This is the only algorithm that does, and it is
consensus. Use `f64` and reproduce the operation order exactly.

```rust
fn next_difficulty_v2(mut ts: Vec<u64>, mut cd: Vec<u128>,
                      target: u64, height: u64, net: Network) -> u128 {
    let t = target as i64;                        // 300
    let mut n = DIFFICULTY_WINDOW_V2;             // 60
    if (net == Testnet || net == Stagenet) && height <= DIFFICULTY_WINDOW { return 100; }
    if ts.len() < 4 { return 1; }
    else if ts.len() < n + 1 { n = ts.len() - 1; }
    else { ts.truncate(n + 1); cd.truncate(n + 1); }

    const ADJUST: f64 = 0.998;
    let k = (n * (n + 1) / 2) as f64;             // integer then to f64
    let mut lwma = 0f64;
    let mut sum_inverse_d = 0f64;
    for i in 1..=n {
        let mut solve_time = ts[i] as i64 - ts[i - 1] as i64;
        solve_time = solve_time.clamp(-7 * t, 7 * t);
        let difficulty = (cd[i] - cd[i - 1]) as u64;        // truncated to u64
        lwma += ((solve_time * i as i64) as f64) / k;       // NOTE: integer mul, then /k
        sum_inverse_d += 1.0 / difficulty as f64;
    }
    let harmonic_mean_d = n as f64 / sum_inverse_d;
    if boost_round(lwma) as i64 < t / 20 { lwma = (t / 20) as f64; }   // t/20 = 15
    let next = harmonic_mean_d * t as f64 / lwma * ADJUST;
    next as u64 as u128                            // C-style truncating cast
}
```

`boost::math::round` rounds half away from zero. `(int64_t)(solveTime * i) / k` in
the C++ computes the product in `int64_t` then divides by the `double` `k`.

### 3.3 `next_difficulty_v3` (LWMA-2) — HF 9

Pure integer, `int64_t` throughout. `timestamps.len()` is asserted to be exactly
`N+1 = 61`.

```rust
fn next_difficulty_v3(ts: Vec<u64>, cd: Vec<u128>, height: u64, net: Network) -> u128 {
    let t: i64 = 300;                              // DIFFICULTY_TARGET_V2
    let n: i64 = 60;                               // DIFFICULTY_WINDOW_V2
    if (net == Testnet || net == Stagenet) && height <= 720 { return 100; }
    let mut l: i64 = 0;
    let mut sum_3_st: i64 = 0;
    for i in 1..=n {
        let mut st = ts[i as usize] as i64 - ts[(i - 1) as usize] as i64;
        st = st.clamp(-4 * t, 6 * t);
        l += st * i;
        if i > n - 3 { sum_3_st += st; }
    }
    let mut next_d = ((cd[n as usize] - cd[0]) as i64 * t * (n + 1) * 99) / (100 * 2 * l);
    let prev_d = (cd[n as usize] - cd[(n - 1) as usize]) as i64;
    next_d = next_d.clamp((prev_d * 67) / 100, (prev_d * 150) / 100);
    if sum_3_st < (8 * t) / 10 {
        next_d = next_d.max((prev_d * 108) / 100);
    }
    next_d as u64 as u128
}
```

`clamp` here is `std::max(lo, std::min(x, hi))` in the C++ — same result, but note
the C++ writes `max((prev_D*67)/100, min(next_D, (prev_D*150)/100))`, so if
`lo > hi` the low bound wins. Rust's `clamp` panics in that case; use the explicit
`max(lo, min(x, hi))` form.

Division by `l` can divide by zero or a negative number if timestamps are
pathological — the C++ has no guard. Reproduce with wrapping/checked semantics
that do not panic: `l == 0` would be UB in C++; in practice `l > 0` because of the
`-4*t` floor and the `i` weighting. Return 1 (or propagate an error that rejects
the block) rather than panicking, and log loudly if it ever fires.

### 3.4 `next_difficulty_v4` (LWMA-4) — HF 10

```rust
fn next_difficulty_v4(ts: Vec<u64>, cd: Vec<u128>, height: u64, net: Network) -> u128 {
    let t: u64 = 300; let n: u64 = 60;
    if (net == Testnet || net == Stagenet) && height <= 720 { return 100; }

    // ---- mainnet override at the HF 10 activation ----
    if net == Mainnet && height <= 63_469 + 1 { return 100_000_069; }

    // monotonise timestamps
    let mut tsm = vec![0u64; (n + 1) as usize];
    tsm[0] = ts[0];
    for i in 1..=n as usize { tsm[i] = ts[i].max(tsm[i - 1]); }

    let mut l: u64 = 0;
    for i in 1..=n as usize {
        let st;
        if i > 4 && tsm[i] - tsm[i-1] > 5*t && tsm[i-1] - tsm[i-4] < (14*t)/10 { st = 2*t; }
        else if i > 7 && tsm[i] - tsm[i-1] > 5*t && tsm[i-1] - tsm[i-7] < 4*t { st = 2*t; }
        else { st = (5*t).min(tsm[i] - tsm[i-1]); }
        l += st * i as u64;
    }
    if l < n*n*t/20 { l = n*n*t/20; }

    let avg_d = ((cd[n as usize] - cd[0]) / n as u128) as u64;
    let mut next_d = if avg_d > 2_000_000 * n * n * t {
        (avg_d / (200 * l)) * (n * (n+1) * t * 97)
    } else {
        (avg_d * n * (n+1) * t * 97) / (200 * l)
    };
    let prev_d = (cd[n as usize] - cd[(n-1) as usize]) as u64;
    if (tsm[n as usize] - tsm[(n-1) as usize]) < (2*t)/10
    || (tsm[n as usize] - tsm[(n-2) as usize]) < (5*t)/10
    || (tsm[n as usize] - tsm[(n-3) as usize]) < (8*t)/10 {
        next_d = next_d.max(((prev_d*110)/100).min((105*avg_d)/100));
    }
    // zero out insignificant digits
    let mut i = 1_000_000_000u64;
    while i > 1 {
        if next_d > i * 100 { next_d = ((next_d + i/2)/i)*i; break; }
        i /= 10;
    }
    if next_d > 100_000 {
        next_d = ((next_d + 500)/1000)*1000
               + 999u64.min((tsm[n as usize] - tsm[(n as usize) - 10]) / 10);
    }
    next_d as u128
}
```

Both the digit-zeroing loop and the trailing `+ min(999, ...)` are consensus.

### 3.5 `next_difficulty_v5` (LWMA-1, N=144) — HF 11–17

The longest-lived algorithm, and the one with the hard-coded overrides.

```rust
fn next_difficulty_v5(ts: Vec<u64>, cd: Vec<u128>, height: u64, net: Network) -> u128 {
    let t: u64 = 300;
    let n: u64 = 144;                          // DIFFICULTY_WINDOW_V3
    if (net == Testnet || net == Stagenet) && height <= 720 { return 100; }

    // ---- reset window at the HF 11 activation ----
    if net == Mainnet && height >= 81_769 && height < 81_769 + n { return 10_000_000; }
    // ts.len() is asserted == n + 1 here

    // ---- six hard-coded corrections for previously mis-computed entries ----
    if net == Mainnet {
        match height {
            307_686 => return 25_800_000,
            307_692 => return  1_890_000,
            307_735 => return 17_900_000,
            307_742 => return 21_300_000,
            307_750 => return 10_900_000,
            307_766 => return  2_960_000,
            _ => {}
        }
    }

    let mut l: u128 = 0;
    let mut previous_timestamp = ts[0] - t;     // NOTE: ts[0] minus one target
    for i in 1..=n as usize {
        let this_timestamp = if ts[i] > previous_timestamp { ts[i] }
                             else { previous_timestamp + 1 };
        l += i as u128 * ((6*t).min(this_timestamp - previous_timestamp)) as u128;
        previous_timestamp = this_timestamp;
    }
    if l < (n*n*t/20) as u128 { l = (n*n*t/20) as u128; }
    let avg_d: u128 = (cd[n as usize] - cd[0]) / n as u128;

    let mut next_d: u128 =
        if avg_d > 2_000_000u128 * (n*n*t) as u128 && height < 307_800 {
            (avg_d / (200 * l)) * (n*(n+1)*t*99) as u128
        } else if avg_d > (u64::MAX as u128) / (n*(n+1)*t*99) as u128 && height > 307_800 {
            (avg_d / (200 * l)) * (n*(n+1)*t*99) as u128
        } else {
            (avg_d * (n*(n+1)*t*99) as u128) / (200 * l)
        };

    // zero out insignificant digits
    let mut i: u128 = 1_000_000_000;
    while i > 1 {
        if next_d > i * 100 { next_d = ((next_d + i/2)/i)*i; break; }
        i /= 10;
    }
    next_d
}
```

Watch the overflow-avoidance branch: the condition changed at height 307,800 and
the two branches are **not** equivalent, so the exact comparison (`<` vs `>`, and
note that `height == 307_800` falls into the third branch) matters.

### 3.6 `next_difficulty_v6` — HF 20+ (current)

`next_difficulty` with the V3 window and V2 cut, and without the HF 18 reset
clause.

```rust
fn next_difficulty_v6(mut ts: Vec<u64>, mut cd: Vec<u128>,
                      target: u64, height: u64, net: Network) -> u128 {
    if (net == Testnet || net == Stagenet) && height <= DIFFICULTY_WINDOW /*720*/ {
        return 100;
    }
    if ts.len() > DIFFICULTY_WINDOW_V3 /*144*/ {
        ts.truncate(144);                     // drops the 3-block lag
        cd.truncate(144);
    }
    let length = ts.len();
    if length <= 1 { return 1; }
    ts.sort();
    let span = DIFFICULTY_WINDOW_V3 - 2 * DIFFICULTY_CUT_V2;   // 144 - 24 = 120
    let (cut_begin, cut_end) = if length <= span { (0, length) }
                               else { let cb = (length - span + 1)/2; (cb, cb + span) };
    let mut time_span = ts[cut_end - 1] - ts[cut_begin];
    if time_span == 0 { time_span = 1; }
    let total_work = cd[cut_end - 1] - cd[cut_begin];
    let res: U256 = (U256::from(total_work) * target + time_span - 1) / time_span;
    if res > U256::from(u128::MAX) { 0 } else { res.as_u128() }
}
```

Because `difficulty_blocks_count` is 147 at HF 20 and the window is 144, the
3-block lag is dropped from the *recent* end. This is the "12-hour difficulty
adjustment window" of the HF 20 release notes (144 × 300 s = 12 hours).

### 3.7 `next_difficulty_64`

A `u64`-only variant of v6 present in the header. It is not called from the
blockchain code (only tests). MAY be skipped.

---

## 4. Summary of hard-coded difficulty overrides

All mainnet-only unless noted.

| Condition | Returned difficulty | Algorithm |
|---|---|---|
| testnet/stagenet and `HEIGHT <= 720` | `100` | all six |
| `331170 <= HEIGHT <= 331890` | `100_000_000` | v1 |
| `HEIGHT <= 63470` | `100_000_069` | v4 |
| `81769 <= HEIGHT < 81913` | `10_000_000` | v5 |
| `HEIGHT == 307686` | `25_800_000` | v5 |
| `HEIGHT == 307692` | `1_890_000` | v5 |
| `HEIGHT == 307735` | `17_900_000` | v5 |
| `HEIGHT == 307742` | `21_300_000` | v5 |
| `HEIGHT == 307750` | `10_900_000` | v5 |
| `HEIGHT == 307766` | `2_960_000` | v5 |

Note the interaction: the v1 reset window `[331170, 331890]` matches the
checkpoint at 331,891 commented "restart DIFFICULTY_WINDOW"
([01 §14](01-constants.md)).

Also note the v4 override reads `HEIGHT <= 63469 + 1`, i.e. `<= 63470` — but v4 is
only selected at HF version 10, which starts at height 63,469. So it applies to
exactly two heights.

---

## 5. Fixed difficulty (regtest)

`--fixed-difficulty N` sets `m_fixed_difficulty`; then

```
get_difficulty_for_next_block() = if db_height() > 0 { N } else { 1 }
```

and `recalculate_difficulties` is a no-op. Only for `FAKECHAIN`; MUST be
unavailable on mainnet.

---

## 6. Cumulative difficulty and drift detection

```
cumulative_difficulty[h] = cumulative_difficulty[h-1] + difficulty[h]
cumulative_difficulty[0] = difficulty[0]       # genesis
```

Stored as two `u64`s (`bi_diff_lo`, `bi_diff_hi`) in the block-info record; see
[10 §4.2](10-storage-lmdb.md).

`check_difficulty_checkpoints()` walks the checkpoint table and compares
`get_block_cumulative_difficulty(height)` against the stored value, returning the
last matching height. `recalculate_difficulties(start)` then recomputes forward
from there and, on a mismatch, rewrites the stored cumulative difficulties via
`correct_block_cumulative_difficulties`.

A Rust node SHOULD implement the *check* (it is a cheap and very effective
integration test: if your difficulty implementation is wrong anywhere, this fires
at the first checkpoint past the error) and MAY skip the *correction* path.

Overflow: `recalculate_difficulties` throws if the running cumulative difficulty
would exceed `u128::MAX`. Treat as a fatal error.

---

## 7. Alternative chains

`get_next_difficulty_for_alternative_chain(alt_chain, block_height)` collects
timestamps and cumulative difficulties by walking the alt chain back from the tip
and then continuing into the main chain, and feeds them to the same six
algorithms with the same selection logic (`get_current_hard_fork_version()` — the
version of the *main chain's* next block). It uses the same
`difficulty_blocks_count` derivation.

---

## 8. Conformance checklist

- [ ] All six algorithms implemented, selected exactly as in §2 — including
      versions 18 and 19 falling through to v1 with a 735-block collection and a
      720-block window.
- [ ] `HEIGHT` is the current chain height and `version` is
      `get_current_hard_fork_version()` — the version at that height, not the
      tip block's; call sites are not "corrected".
- [ ] v1 and v6 truncate the window from the tail (dropping the lag) and sort
      only the timestamps, never the cumulative difficulties.
- [ ] v2 uses `f64` with the exact operation order and `boost::math::round`
      semantics.
- [ ] v3 uses `max(lo, min(x, hi))`, not a panicking `clamp`.
- [ ] v4's timestamp monotonisation, digit-zeroing loop and trailing
      `min(999, ...)` term are reproduced.
- [ ] v5's `previous_timestamp = ts[0] - target` initialisation, the 307,800
      branch condition, and all six per-height overrides are reproduced.
- [ ] Every override in §4 is present.
- [ ] Difficulty 0 (overflow) causes the block to be rejected.
- [ ] `check_difficulty_checkpoints` passes against all 39 checkpoints after a
      full sync.
