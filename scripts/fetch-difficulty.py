#!/usr/bin/env python3
"""Capture real difficulty windows, one per algorithm era.

`specs/15-testing-and-conformance.md` §3.2 asks for "the exact timestamp and
cumulative-difficulty windows from real heights (extracted via RPC)" for each of
the six algorithms, compared against
`get_block_header_by_height(h).difficulty`.

Each row is the input `get_difficulty_for_next_block` assembles at `height`:
`difficulty_blocks_count(tip_version)` headers ending at `height - 1`, per
`specs/07` §1 --

    offset = H - min(H, difficulty_blocks_count)
    if offset == 0 { offset = 1 }          # skip genesis
    timestamps   = [ timestamp(i)             for i in offset..H ]
    difficulties = [ cumulative_difficulty(i) for i in offset..H ]

Output: `tests/corpus/difficulty/index.tsv`

    name  height  tip_version  expected_difficulty  timestamps_csv  cumulative_csv

Usage:
    python scripts/fetch-difficulty.py --daemon 127.0.0.1:34568
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

# (name, height, tip hard-fork version, difficulty_blocks_count for it)
CASES = [
    ("v1_hf7", 3_000, 7, 735),
    ("v2_hf8", 30_000, 8, 61),
    ("v3_hf9", 60_000, 9, 61),
    ("v4_hf10", 70_000, 10, 61),
    ("v5_hf11", 90_000, 11, 145),
    ("v5_hf15", 200_000, 15, 145),
    ("v5_hf17", 300_000, 17, 145),
    ("v1_hf19", 400_000, 19, 735),
    ("v6_hf20", 600_000, 20, 147),
    ("v6_tip", 870_000, 20, 147),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--daemon", required=True, help="host:port of a synced daemon RPC")
    ap.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(__file__), "..", "tests", "corpus", "difficulty"),
    )
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    base = args.daemon if args.daemon.startswith("http") else "http://" + args.daemon
    url = base.rstrip("/") + "/json_rpc"

    def rpc(method: str, params: dict, tries: int = 3) -> dict:
        for k in range(tries):
            try:
                body = json.dumps(
                    {"jsonrpc": "2.0", "id": "0", "method": method, "params": params}
                ).encode()
                req = urllib.request.Request(
                    url, data=body, headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=args.timeout) as r:
                    out = json.loads(r.read())
                if "error" in out:
                    raise RuntimeError(out["error"])
                return out["result"]
            except Exception:
                if k == tries - 1:
                    raise
                time.sleep(2)
        raise AssertionError("unreachable")

    def headers(a: int, b: int) -> list[dict]:
        """`get_block_headers_range` is inclusive on both ends."""
        out: list[dict] = []
        h = a
        while h <= b:
            end = min(h + 999, b)
            out.extend(rpc("get_block_headers_range", {"start_height": h, "end_height": end})["headers"])
            h = end + 1
        return out

    rows = []
    for name, height, version, count in CASES:
        offset = height - min(height, count)
        if offset == 0:
            offset = 1
        hs = headers(offset, height - 1)
        if len(hs) != height - offset:
            print(f"{name}: expected {height - offset} headers, got {len(hs)}", file=sys.stderr)
            return 1
        want = rpc("get_block_header_by_height", {"height": height})["block_header"]
        ts = ",".join(str(h["timestamp"]) for h in hs)
        cd = ",".join(
            str((int(h["cumulative_difficulty_top64"]) << 64) | int(h["cumulative_difficulty"]))
            for h in hs
        )
        rows.append("\t".join([name, str(height), str(version), str(want["difficulty"]), ts, cd]))
        print(f"{name:<10} height={height} v{version} want={want['difficulty']} window={len(hs)}",
              file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "index.tsv")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            "# name\theight\ttip_version\texpected_difficulty\ttimestamps_csv\tcumulative_difficulties_csv\n"
        )
        fh.write("\n".join(rows) + "\n")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
