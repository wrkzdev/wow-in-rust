# HF 18+ boundary blocks

21 real mainnet blocks, committed (unlike `../mainnet/`, which is generated).

They cover the two hard-fork boundaries that change the block header and the
consensus rules around it, plus a spread of the current era:

| Heights | Why |
|---|---|
| 331,169 / 331,170 / 331,171 | the HF 18 switch: Bulletproofs+, **block-header miner signing**, the `vote` field, the difficulty reset |
| 331,457 / 331,458 | HF 19 |
| 331,890 / 331,891 | the end of the HF 18 difficulty-reset window |
| 513,998 … 514,002 | the HF 20 switch: view tags, 2021 fee/weight scaling, the 144-block difficulty window |
| 400k … 873k | a spread of HF 19 and HF 20 |

The point of committing these specifically: from HF 18 every header carries a
Schnorr signature over `sig_data`, made with the coinbase output's one-time key
(`specs/06` §4). Verifying those signatures validates `sig_data`, the Schnorr
verifier, point decoding, the Merkle root and the parser **against consensus
itself** — a stronger check than comparing against an instrumented C++ build,
and one that needs no daemon at test time.

Regenerate or extend with `scripts/fetch-corpus.py`; the format is the same
`index.tsv` (`height`, `block_id`, `miner_tx_hash`, `block_blob_hex`,
`sig_data_hex`).
