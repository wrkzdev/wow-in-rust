#!/usr/bin/env python3
"""Capture per-block weights and long-term weights for the weight replay.

`specs/15-testing-and-conformance.md` §3.2: "**Weights.** Replay a 100,000-block
window and compare `long_term_weight` per block against the C++ values from
`get_block_header_by_height`."

`long_term_weight` is a stored database column that **cannot be recomputed from
block weights alone** (`specs/06` §3.4) -- it is a median over previously
*stored* long-term weights, so it is self-referential. The only way to check an
implementation is to replay the chain's own recorded column, which is what this
fetches.

Two ranges are worth having, for different reasons:

  * `[0, 170_000)` needs **no seed at all**. Below HF 13 (height 114,969) the
    stored long-term weight is just the block weight, and while `height <
    100_000` the median window is the whole chain, so a replay from genesis is
    exact. This range covers the HF 13 switch and the HF 15 switch.

  * `[414_000, 544_000)` covers the HF 20 switch at 514,000, where the clamp
    changes from `[0, 1.4x]` to `[1/1.7x, 1.7x]`. Its first 100,000 rows are
    the seed for the window that follows.

Output: `tests/corpus/weights/mainnet-<start>-<end>.tsv`, one block per line:

    height \t major_version \t block_weight \t long_term_weight \t reward

Usage:
    python scripts/fetch-weights.py --daemon 127.0.0.1:34568 --start 0 --end 170000
    python scripts/fetch-weights.py --daemon 127.0.0.1:34568 --preset hf20
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# `RESTRICTED_BLOCK_HEADER_RANGE` on a public node. The default batch is well
# under it: a public node's response time is markedly super-linear in the range
# (measured on a seed node: 200 headers in 2.7s, 500 in 7.2s, 1000 in 30.5s),
# so 500 finishes a 170,000-block range about four times faster than 1000 does.
MAX_RANGE = 1000
DEFAULT_BATCH = 500

PRESETS = {
    # From genesis: exact, unseeded, covers HF 13 (114,969) and HF 15 (160,777).
    "genesis": (0, 170_000),
    # Around HF 20 (514,000): the first 100,000 rows seed the window after it.
    "hf20": (414_000, 544_000),
}


class Daemon:
    def __init__(self, addr: str, timeout: float = 60.0):
        self.url = f"http://{addr}/json_rpc"
        self.timeout = timeout

    def rpc(self, method: str, params: dict | None = None, retries: int = 6) -> dict:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}
        ).encode()
        last = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    self.url, body, {"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    out = json.load(r)
                if "error" in out:
                    raise RuntimeError(f"{method}: {out['error']}")
                return out["result"]
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                last = e
                # A public node throttles; back off rather than giving up.
                time.sleep(min(2 ** attempt, 30))
        raise RuntimeError(f"{method} failed after {retries} tries: {last}")

    def headers(self, start: int, end: int) -> list[dict]:
        """`get_block_headers_range` is inclusive at both ends."""
        return self.rpc(
            "get_block_headers_range", {"start_height": start, "end_height": end}
        )["headers"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", default="127.0.0.1:34568")
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int, help="exclusive")
    ap.add_argument(
        "--batch",
        type=int,
        default=DEFAULT_BATCH,
        help=f"headers per request (max {MAX_RANGE}; default {DEFAULT_BATCH})",
    )
    ap.add_argument(
        "--out-dir",
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tests",
            "corpus",
            "weights",
        ),
    )
    args = ap.parse_args()
    if not 1 <= args.batch <= MAX_RANGE:
        ap.error(f"--batch must be in 1..{MAX_RANGE}")

    if args.preset:
        start, end = PRESETS[args.preset]
    elif args.start is not None and args.end is not None:
        start, end = args.start, args.end
    else:
        ap.error("pass --preset or both --start and --end")

    d = Daemon(args.daemon)
    tip = d.rpc("get_last_block_header")["block_header"]["height"]
    if end > tip + 1:
        print(f"clamping end {end} to tip {tip}", file=sys.stderr)
        end = tip + 1

    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, f"mainnet-{start}-{end}.tsv")
    tmp = path + ".part"

    # Resume: a public-node fetch of 170,000 headers takes a while.
    done = 0
    if os.path.exists(tmp):
        with open(tmp, encoding="utf-8") as f:
            rows = [l for l in f if l.strip() and not l.startswith("#")]
        done = len(rows)
        print(f"resuming after {done} rows", file=sys.stderr)

    mode = "a" if done else "w"
    with open(tmp, mode, encoding="utf-8", newline="\n") as f:
        if not done:
            f.write("# height\tmajor_version\tblock_weight\tlong_term_weight\treward\n")
            f.write(
                f"# generated by scripts/fetch-weights.py from {args.daemon},"
                f" tip {tip}, range [{start}, {end})\n"
            )
        h = start + done
        t0 = time.time()
        while h < end:
            last = min(h + args.batch - 1, end - 1)
            for hdr in d.headers(h, last):
                f.write(
                    "\t".join(
                        str(hdr[k])
                        for k in (
                            "height",
                            "major_version",
                            "block_weight",
                            "long_term_weight",
                            "reward",
                        )
                    )
                    + "\n"
                )
            f.flush()
            h = last + 1
            pct = 100.0 * (h - start) / (end - start)
            print(
                f"{time.strftime('%H:%M:%S')}  {h - start}/{end - start}"
                f"  ({pct:.1f}%)  {time.time() - t0:.0f}s",
                file=sys.stderr,
                flush=True,
            )

    os.replace(tmp, path)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
