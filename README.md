# wbft-analyzer

wbft-analyzer loads what WBFT networks record and shows how consensus ran.
Its inputs come from the other WBFT repositories:

- block headers (participation, proposers, epochs) over RPC;
- node logs, the consensus event streams and the message journals of
  [wbft](https://github.com/0xmhha/wbft) nodes;
- the JSON reports of [wbft-inspector](https://github.com/0xmhha/wbft-inspector),
  the only source of verdicts: the analyzer does not decide requirements
  itself, it places the inspector's verdicts and observations on the
  timelines it derives.

The data goes into PostgreSQL; derived tables (participation matrix, round
timelines, message latency, observation trends) are served over a REST API
to a static web front end.

## Status

The analyzer is built in stages; the A0 foundation is complete:

| Stage | Content | State |
|---|---|---|
| A0 | command skeleton, inspector report loader with the public-build checks, PostgreSQL store, observation trends and alerts, API and front-end skeleton | complete |
| A1 | header analysis: participation, proposers, epochs | implemented; live multi-node and inspector P0 acceptance remains |
| A2 | node logs and chainbench runs | not started |
| A3 | wbft event streams and mixed networks | not started |
| A4 | governance history | not started |

Every command is listed by `wbft-analyzer help`; a command that is not built
yet says so and exits with code 69.

Built so far:

- `wbft-analyzer ingest reports --db DSN FILE ...` loads inspector reports:
  the public-build checks, one copy per file, and the observation rates of
  each report added to the trends of its network, with the network's alert
  rules evaluated and their webhooks told of state changes.
- `wbft-analyzer ingest range --db DSN --rpc URL --config CONFIG.json
  --from N --to M --name DATASET --node NODE` imports a bounded header
  range and its child. Use `--blocks DIR` instead of `--rpc` for
  zero-padded block RLP files. Configuration is explicit and must name
  the RPC chain ID. Batches contain at most 100 headers, are limited to
  five per second, and retry transport/server failures. Optional RPC
  capabilities are probed. Repeat a name and immutable range/config to
  resume without duplicating canonical facts; another node adds its own
  copies. Dataset status, progress, failure and available nodes are exposed.
  A canonical conflict fails the batch rather than overwriting it.
- `wbft-analyzer serve --db DSN` serves the REST API under `/v1`: networks,
  reports with their results and observations (and `POST /v1/reports`,
  the same loader), observation trends, alert rules (`PUT` replaces a
  network's set) and alert states. It listens on `127.0.0.1:8080` and
  then answers only to a loopback host name; another address needs
  `--auth token`, a bearer token taken from `$WBFT_ANALYZER_TOKEN`. The
  server speaks plain HTTP: reach it over a network through a TLS proxy.
- The API is described by an OpenAPI 3.1 document, built from the route
  table and the Go types of the answers. It is served at
  `GET /v1/openapi.json` and committed as `api/openapi.json` for the front
  end's type generation. After changing the API, rewrite the committed copy
  with `go test ./internal/api -run TestOpenAPIDocument -update`. The tests
  check every answer they receive against the document.

A local PostgreSQL for development and the integration tests:

```
docker compose -f deploy/postgres/compose.yaml up -d
WBFT_ANALYZER_TEST_DSN='postgres://analyzer:analyzer@127.0.0.1:5433/analyzer?sslmode=disable' go test ./...
```

`scripts/dump-check.sh SOURCE_DSN TARGET_DSN OUT_DIR` loads a set of
reports and real public header fixtures, saves the database with `pg_dump`, restores the dump into another
database and checks that the API answers the same from both; CI runs it
on two PostgreSQL servers and keeps the dump as the `analyzer-dump`
artifact. A dump restores with
`pg_restore --no-owner --dbname=DSN analyzer.dump` and opens with `serve`.

## Web front end

`web/` is a static React/d3 page that `serve` delivers at `/`. It
shows loaded networks, header participation/proposers/epochs, the inspector's verdicts across reports, and
observation trends with their alert rules. Its API types are generated from
`api/openapi.json` (`npm run gen`). `npm run build` writes it to
`internal/web/dist/app`, which `go build` embeds. A binary built without
that step (for example by `go install`) serves the API only, and answers its
pages with 503.

The verdict overlay distinguishes partly passed requirements with a
half-filled circle and a `partly passed` label. These are `CANNOT_DECIDE`
results whose coverage has passed and undecided instances, with no failed
instance; they remain undecided. Other undecided results are hatched.

```
cd web && npm ci && npm run build && cd ..
go build ./cmd/wbft-analyzer
```

For development, `npm run dev` serves the page with hot reload and sends
`/v1` to a `wbft-analyzer serve` on `127.0.0.1:8080`.

## Build and test

```
go build ./...
go test ./...
```

Go 1.26.8 or later.


## Required analysis features

The WBFT analyzer must support equivalents of the analysis workflows in
[CometBFT Analyzer Backend](https://github.com/bft-labs/cometbft-analyzer-backend),
[CometBFT Analyzer Frontend](https://github.com/bft-labs/cometbft-analyzer-frontend)
and [CometBFT Analyzer Types](https://github.com/bft-labs/cometbft-analyzer-types).
The reviewed revisions are `60afbea`, `9b83021` and `a7cfae9`, respectively.
These features are required for A2/A3 completion; they are not implemented
by the A0 report views.

| Reference workflow | WBFT equivalent | Stage |
|---|---|---|
| Project/simulation management, uploads and processing status | Networks and run datasets, input selection, ingestion status/errors/retry, repeatable imports | A2 |
| Consensus trace, event table and event details | Node swimlanes by height/round, zoom/pan, node/phase/message filters, cursor pages, linked event details and source evidence | A2/A3 |
| Event and message types | WBFT PRE-PREPARE, PREPARE, COMMIT and ROUND-CHANGE; local/direct/relay paths; full height/round values; generated API types | A2/A3 |
| Pairwise, time-series and end-to-end latency | Directed node pairs by message type and height/round; round entry, proposal acceptance, quorum, decision and import intervals | A2/A3 |
| Vote latency statistics and slow samples | p50/p90/p95/p99 with sample counts, threshold filters, paginated samples and evidence links | A3 |
| Network distributions, node statistics and rankings | Histograms, standard deviation, sends/receives/unmatched counts and bottleneck candidates | A3 |
| Latency heatmaps, distributions, pair details and charts | Directed heatmaps, distributions, rankings, pair/node details and time series sharing the same filters | A3 |

WBFT participation comes from header seals and consensus events. The
CometBFT prevote/precommit phases are not WBFT message types. Local intervals
use monotonic time; cross-node measurements carry the clock model and
matching strength. Link, node and key matches remain distinguishable.
Unknown clocks, skew, journal gaps, negative samples and missing inputs
must be visible; missing observations do not imply zero latency or failed
delivery. An overall percentile is computed from samples, not by averaging
pair percentiles. API, stored data, views and evidence links must be checked
against real runs before these workflows are marked complete.

## Public scope

The analyzer only accepts reports of the public inspector build for the
requirements of the public specification; a report naming anything else is
refused as a whole. It shows improvement IDs as given and carries no
description of them.

## License

LGPL-3.0-or-later. See `LICENSE` and `COPYING`.

## Header analysis

Network participation at height h is the previous prepare/commit bitmap of
h+1, interpreted in V(h). Own seals are dataset/node copies, which the WBFT
block hash excludes. A missing child stays unknown. Genesis has no voting
participation. Inclusion rates expose eligible/known/unknown denominators;
a rate is unavailable when an eligible height is unknown. Proposer rotation
and earlier opportunities use wbft's validator policy; a Coinbase difference
is an observation and carries no analyzer verdict. Full header numbers and
canonical uint64 indices are separate decimal strings in the API and UI.

The wbft module is pinned to `800141cb6e65`. It supplies codec, header validator
lookup, proposer rotation and epoch recomputation. Epoch candidates and the
selected BLS keys are reconstructed from the header, without an execution
state oracle; `matched_header_inputs` explicitly states this limit. Epoch
panels show diligence, selection order and changes between stored headers.
The participation matrix splits governing epochs, has bounded height pages,
node-copy selection and inspector evidence pointers. Previous-seal evidence
selects the preceding height; payload/state values are not persisted.

Validation on 2026-10-13: public testnet heights 22044761..22144760 plus the
child, 100000 requested headers in 289.409 s (345.5 headers/s). All 98 windows
of up to 1024 heights agree per validator with `istanbul_status` previous
prepare/commit totals. All 714 epoch blocks match the header-reconstructed
inputs. Stored facts are 106.1 MiB; tables plus indexes are approximately
289 MiB (147 MiB heights, 76 MiB seals, 65 MiB copies, 1.2 MiB epochs).
Independent live-node duplicate import and an actual inspector testnet P0
report overlay are still acceptance work. Tests use two independent RPC
surfaces replaying real public headers; this is not a live-node claim.
