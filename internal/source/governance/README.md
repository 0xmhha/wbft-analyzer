# Governance capture reader

This package reads the WBFT governance RPC contract without an execution-layer dependency. It collects `wbft_mirror`, `wbft_mirrorState`, `wbft_govOps`, `wbft_govProposal`, `wbft_validatorChanges`, and `wbft_mirrorFaults`, with `wbft_nodeInfo` identity bookends. The bookends must agree on node address, chain ID, and genesis hash. Heads may move during collection, so the snapshot always records `atomic: false`.

Archive format `wbft-analyzer-governance/1` records the requested range, instance and proposal selections, ordered method/parameter pairs, and supplied JSON-RPC envelopes. `Load` returns the supplied archive digest. `Fetch` uses one client sequentially and labels reconstructed envelopes explicitly; their hashes are not hashes of original network packets. Normalization retains request ordinals, scopes, availability, error codes, and envelope hashes. Transport endpoints and arbitrary error text are omitted.

Ranges use canonical uint64 hex quantities and contain at most 1,024 indices. Other quantities remain exact hex strings; chain IDs and full node head heights use exact decimal strings. A bounded operation request, a historical state request, and a proposal's full history/current state retain separate scopes. Empty available lists, unavailable calls, legacy gaps without bounds, zero bounds, nullable annotations, and optional state fields remain distinguishable.

Calldata, log data, descriptions, and unsupported annotations retain only hashes and byte lengths. Allowlisted function arguments use standard EVM ABI decoding; noncanonical or unknown calls retain their original outcome claims without invented arguments. Mirror authority, health, verification, projection modes, and epoch differences remain source claims. Canonical header binding and evidence for a validator-change cause belong to the ingestion and analysis layers; this reader does not infer those links.

## Dataset ingestion

```sh
wbft-analyzer ingest governance --db "$WBFT_ANALYZER_DB" --name governance-capture --archive capture.json
wbft-analyzer ingest governance --db "$WBFT_ANALYZER_DB" --name governance-live \
  --rpc http://127.0.0.1:8545 --from 0x1 --to 0x40 \
  --instance 0x1111111111111111111111111111111111111111 \
  --proposal 0x1111111111111111111111111111111111111111:0x1
```

The range and selections are explicit. Instance and proposal flags are repeatable. Archive input cannot be combined with RPC selectors. Proposal history may contain operations outside the bounded range and is stored under its own original request ordinal and scope.

The database stores the normalized capture, original envelope digests, source digest, and request-linked operation, fault/gap, historical state, proposal, and validator-change rows. It never retains the archive file, endpoint, opaque calldata, log data, arbitrary description, or error message. Completion and all rows commit together. An identical capture is skipped; a reused name with changed source configuration or normalized content is refused. Available empty results report zero operations; unavailable operation calls report a null count. A legacy gap with unknown bounds remains distinct from a known zero bound.

Dataset listing supports `kind=governance`. Dataset export includes all owned governance rows and their request pointers; deletion cascades through those rows. These records are source claims. Ingestion does not authenticate a remote node, verify governance execution, bind a claim to a canonical header, or infer a validator-change cause.
