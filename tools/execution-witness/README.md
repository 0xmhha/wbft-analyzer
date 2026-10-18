# WBFT execution witness helper

This separate Go module reprocesses original WBFT blocks from their genesis.
It uses a pinned execution implementation without changing the analyzer's
linked Ethereum trie or consensus module. Build with Go 1.26:

```
go build -o /path/to/wbft-execution-witness .
```

```
wbft-execution-witness --manifest FILE --root DIR
```

The `wbft-execution-witness-input/1` manifest contains `format`, `node`,
`genesis` and `blocks`. Each file reference has a relative `path` and exact
`sha256`. `genesis` identifies the complete original genesis JSON. Each block
has a canonical decimal `index` and `file`; the sequence must contain every
full block RLP from zero through the selected end. Header-only bodies cannot
establish transaction execution. `node` is a declared association with a
governance source, not remote peer authentication.

The helper checks strict JSON and RLP, checksums, full heights, parent hashes,
genesis initialization, the committed empty WBFT uncle body, transaction and receipt roots, gas accounting and
every final state root. Nonempty uncle or withdrawal bodies are refused, including at genesis.
It applies the original WBFT finalization, including
contract upgrades, rewards, epoch processing and gas-tip checks. A second
execution path independently provides the actual outer VM return; its state,
logs and gas must match normal transaction processing. Errors before a call
hook are retained with explicit unavailable hook details.

Known error names require the configured governance address, a reviewed
runtime code hash and canonical ABI bytes. Contract configuration is taken
from the parent-finalized state because upgrades run after the block's
transactions; VM fork rules still use the current block. Unknown code,
unknown selectors, empty reverts and malformed returns remain distinct.
Successful children of reverted calls have no retained effect. Nested paths
describe observed VM hooks and are not an inferred SDK mirror path contract.

Only source digests, canonical block/transaction metadata, bounded frame
summaries, receipt log addresses/topics/data digests and known classifications cross the output boundary. Original paths,
raw inputs, public keys, return data and arbitrary error messages do not.
The output is not a specification verdict or a proof of proposal causation.
An analyzer must execute an operator-trusted, fingerprinted binary and bind
its result to independent completed canonical sources; importing an output
report's claim of verification is insufficient.

Bounds are 16 MiB per manifest and source file, 16,384 blocks, 100,000
transactions, observed frames and receipt logs (4,096 logs per transaction), 256 MiB per reader including checksum
rechecks, and 32 MiB of output. Replay accepts at most one billion gas per
block and in total across non-genesis blocks. Inputs exceeding any bound are
refused as a whole; no verified prefix is emitted. The parent process also
bounds execution time and output and rechecks the binary and sources.
