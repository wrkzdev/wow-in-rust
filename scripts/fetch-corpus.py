#!/usr/bin/env python3
"""Generate the M1 block corpus from a Wownero daemon.

`specs/15-testing-and-conformance.md` §7 asks for this script to be committed so
the corpus can be regenerated and extended. §2.2 and §2.3 define what it must
collect:

  * at least 10,000 mainnet blocks spread across every hard-fork era
    (~1000 per era), plus
  * every hard-fork boundary height, plus
  * the specific heights §2.3 lists: the PoW override at 202,612, the six
    hard-coded difficulties around 307,7xx, the HF 18 switch, the HF 20 switch,
    and the RandomWOW seed-epoch boundaries.

Output: `tests/corpus/blocks/mainnet/index.tsv`, one block per line:

    height \\t block_id \\t miner_tx_hash \\t block_blob_hex [\\t sig_data_hex]

`sig_data_hex` is optional and only meaningful for HF >= 18 blocks. The daemon
does not expose `get_sig_data`, so it is left empty unless `--sig-data-from`
points at a file produced by an instrumented build; the Rust test checks the
field only when it is present.

Usage:
    python scripts/fetch-corpus.py --daemon 127.0.0.1:34568
    python scripts/fetch-corpus.py --daemon node.example:34568 --per-era 200

A public node works, but a local synced daemon is faster and is what the
differential-testing harness in §1 wants anyway.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# specs/01-constants.md §3.1 -- mainnet (version, height).
MAINNET_FORKS = [
    (7, 1),
    (8, 6969),
    (9, 53666),
    (10, 63469),
    (11, 81769),
    (12, 82069),
    (13, 114969),
    (14, 115257),
    (15, 160777),
    (16, 253999),
    (17, 254287),
    (18, 331170),
    (19, 331458),
    (20, 514000),
]

# specs/15 §2.3 -- heights that must be present whatever the sampling.
REQUIRED_HEIGHTS = [
    0,  # genesis construction
    1, 6969, 53666, 63469, 81769, 82069,
    114968, 114969,  # CryptoNight -> RandomWOW
    115257, 160777,
    202612,  # the PoW override, specs/03 §5
    253999, 254287,
    307686, 307692, 307735, 307742, 307750, 307766,  # hard-coded difficulties
    307800,  # the v5 overflow-branch change
    331169, 331170, 331171,  # HF 18: BP+, header signing, difficulty reset
    331458,  # HF 19
    331890, 331891,  # end of the difficulty reset window
    513999, 514000, 514001,  # HF 20: view tags, 2021 scaling, 144-block window
    2048, 2112, 2113, 4096,  # RandomWOW seed-epoch boundaries
]


class Daemon:
    def __init__(self, addr: str, timeout: float = 30.0):
        if not addr.startswith("http"):
            addr = "http://" + addr
        self.base = addr.rstrip("/")
        self.timeout = timeout
        self._id = 0

    def _post(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        body = {
            "jsonrpc": "2.0",
            "id": str(self._id),
            "method": method,
            "params": params or {},
        }
        out = self._post("/json_rpc", body)
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    def info(self) -> dict:
        return self._post("/get_info", {})

    def block(self, height: int) -> dict:
        return self.rpc("get_block", {"height": height})


def plan_heights(tip: int, per_era: int) -> list[int]:
    """Sample `per_era` heights from each hard-fork era, plus the required set."""
    heights: set[int] = set()

    bounds = [h for _, h in MAINNET_FORKS] + [tip + 1]
    for i in range(len(MAINNET_FORKS)):
        lo = bounds[i]
        hi = min(bounds[i + 1], tip + 1)
        if hi <= lo:
            continue
        span = hi - lo
        n = min(per_era, span)
        if n <= 0:
            continue
        # Evenly spaced, deterministic -- a regenerated corpus is comparable.
        step = span / n
        for k in range(n):
            heights.add(lo + int(k * step))
        # Always take the first and last block of the era.
        heights.add(lo)
        heights.add(hi - 1)

    for h in REQUIRED_HEIGHTS:
        if h <= tip:
            heights.add(h)

    # ...and the tip itself.
    heights.add(tip)
    return sorted(heights)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--daemon", required=True, help="host:port of a synced daemon RPC (default port 34568)")
    ap.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(__file__), "..", "tests", "corpus", "blocks", "mainnet"),
        help="output directory",
    )
    ap.add_argument("--per-era", type=int, default=1000, help="blocks to sample per hard-fork era (specs/15 §2.2)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument(
        "--sig-data-from",
        help="optional TSV of 'height<TAB>sig_data_hex' from an instrumented C++ build",
    )
    args = ap.parse_args()

    d = Daemon(args.daemon, args.timeout)
    try:
        info = d.info()
    except (urllib.error.URLError, OSError) as e:
        print(f"cannot reach {args.daemon}: {e}", file=sys.stderr)
        return 1

    if info.get("status") != "OK":
        print(f"daemon not ready: {info.get('status')}", file=sys.stderr)
        return 1
    if not info.get("mainnet", False):
        print(f"daemon is on {info.get('nettype')}, not mainnet", file=sys.stderr)
        return 1
    if not info.get("synchronized", False):
        print("warning: daemon reports it is not synchronized", file=sys.stderr)

    tip = int(info["height"]) - 1
    print(f"tip = {tip}")

    sig_data: dict[int, str] = {}
    if args.sig_data_from:
        with open(args.sig_data_from, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                h, s = line.split("\t")[:2]
                sig_data[int(h)] = s

    heights = plan_heights(tip, args.per_era)
    print(f"collecting {len(heights)} blocks")

    os.makedirs(args.out, exist_ok=True)
    index = os.path.join(args.out, "index.tsv")

    with open(index, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            "# height\tblock_id\tminer_tx_hash\tblock_blob_hex\tsig_data_hex\n"
            f"# generated by scripts/fetch-corpus.py from {args.daemon}, tip {tip}\n"
        )
        for n, h in enumerate(heights):
            try:
                b = d.block(h)
            except Exception as e:  # noqa: BLE001 -- report and continue
                print(f"height {h}: {e}", file=sys.stderr)
                continue
            blob = b["blob"]
            header = b["block_header"]
            row = [
                str(h),
                header["hash"],
                header["miner_tx_hash"],
                blob,
                sig_data.get(h, ""),
            ]
            fh.write("\t".join(row) + "\n")
            if n % 500 == 0:
                print(f"  {n}/{len(heights)} (height {h})")

    print(f"wrote {index}")
    print("now run:  cargo test -p wow-types --test roundtrip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
