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
| A1 | header analysis: participation, proposers, epochs | implemented and validated on real testnet/G7 inputs |
| A2 | node logs and chainbench runs | run ingestion, metadata timelines, round causes, inspector source overlay and phase latency implemented; visual replay and independent-run baseline comparison implemented |
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
- `wbft-analyzer ingest run --db DSN --manifest RUN.json` streams JSON
  node logs using the generated `gstable@740526d03` profile or the pinned
  WBFT profile. `--chainbench DIR --rpc URL --name DATASET` reads a local
  formatVersion 3 workspace and independently obtains the network identity
  from RPC. It does not copy launch commands or key paths. Use `--from_t`
  and `--to_t` for a bounded scenario window in chainbench mode, or put them
  in the manifest. Input hashes, captured byte counts and profile hashes
  and the normalizer version bind the dataset. Repeating a complete import skips it; an interrupted or
  failed import can retry the same immutable inputs. A different input or
  network requires another name. Unknown phrases/malformed records leave
  diagnostic counts and a failed status, without storing their raw values.
  Only metadata is persisted; payload, data, arbitrary errors and nested
  objects are removed at both source and store boundaries.
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

The analyzer must support the following WBFT consensus analysis workflows.
These features are required for A2/A3 completion; the A0 report views cover
only report analysis.

| Feature | Required behavior | Stage |
|---|---|---|
| Network and dataset management | Run datasets, input selection, ingestion status/errors/retry and repeatable imports | A2 |
| Consensus timeline and evidence | Node swimlanes by height/round, zoom/pan, node/phase/message filters, cursor pages, event details and linked source evidence | A2/A3 |
| WBFT message analysis | PRE-PREPARE, PREPARE, COMMIT and ROUND-CHANGE; local/direct/relay paths; full height/round values; generated API types | A2/A3 |
| Pairwise, time-series and end-to-end latency | Directed node pairs by message type and height/round; round entry, proposal acceptance, quorum, decision and import intervals | A2/A3 |
| Message latency statistics and slow samples | p50/p90/p95/p99 with sample counts, threshold filters, paginated samples and evidence links | A3 |
| Network distributions, node statistics and rankings | Histograms, standard deviation, sends/receives/unmatched counts and bottleneck candidates | A3 |
| Latency heatmaps and pair details | Directed heatmaps, distributions, rankings, pair/node details and time series sharing the same filters | A3 |

WBFT participation comes from header seals and consensus events. Local
intervals use monotonic time; cross-node measurements carry the clock model
and matching strength. Link, node and key matches remain distinguishable.
Unknown clocks, skew, journal gaps, negative samples and missing inputs
must be visible; missing observations do not imply zero latency or failed
delivery. An overall percentile is computed from samples, not by averaging
pair percentiles. API, stored data, views and evidence links must be checked
against real runs before these workflows are marked complete.

## Message metadata inputs

`ingest messages --db DSN --manifest FILE` accepts immutable journal
or R-01 frame directories. The manifest format is
`wbft-analyzer-messages/1`, with `name`, a `network` (`chain_id`,
`genesis_hash`, `name`), `clock` and `inputs` (`id`, `kind`, `node`, `path`).
`node` is the recording node's consensus address; paths are local-only.
`kind` is `journal` or `frames`. `clock.model` is `unknown`, `shared-host`
or `ntp`; only `ntp` takes a required nonnegative `skew_ms` bound.
An optional input `sha256` checks the canonical, sorted file manifest hash.

The journal reader and message codec come from the pinned WBFT module.
Only decoded metadata, source file hashes and original positions enter
PostgreSQL. Signer recovery does not assert validator membership. Payloads,
step input bytes, configuration, remote endpoints and arbitrary error text
are excluded. R-01 payload hashes and sizes are checked before decoding;
missing payloads and unknown peers remain explicit. Journal gaps and
monotonic regressions are diagnostics. Inherited R-01 timestamps are marked
separately from recorded frame timestamps. An absent R-01 write error is
`no_error_recorded`, not proof of a successful write.

Damage or a torn final journal record retains the readable prefix and
fails the dataset. Retrying the same immutable input compares existing
rows and inserts no duplicates; repairing or extending an input needs a
new dataset name. The reader bounds journal segments to 256 MiB, frame
lines to 4 MiB, payload decoding to 16 MiB and frame sequence tracking to
one million records per input. Artifact symlinks are refused.

The messages page shows dataset status, file provenance, diagnostics,
source-ordered cursor pages, full height/round filters and record details.
Read APIs are `messages/inputs` and `messages/records` below a network's
dataset route. Cursors bind the dataset snapshot and filters. This input
and evidence path does not yet pair node-to-node messages, estimate clock
skew, classify missing votes or perform closed execution replay.

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
Real G7 nodes independently imported heights 1..160 plus the child:
canonical heights (161), seals and epoch 140 are shared, while each node
retains 161 copies. Actual inspector main 2b790c3 reports were imported
for the same testnet/G7 inputs. Evidence matches full heights, canonical
own/child hashes, validator addresses and the selected node; another fork
or node does not mark the cell. The seven implemented content checks pass,
node-key binding is partly decided and other selected P0 checks remain not
run. This does not claim completion of all inspector P0 requirements.

## Run timelines (A2 in progress)

The events view lists run datasets, import diagnostics and immutable input
hashes. It shows node swimlanes and a source-linked event table with wall
clock zoom/pan, node/kind/message/full-height/full-round filters and cursor
pages. A selected source outside the current page can be fetched directly
by its input ID and original line number. Heights and rounds remain decimal
strings. Logs have no monotonic timestamps and do not prove coverage,
missing delivery or a successful wire write. Timestamps may arrive out of
order; their counts are shown without asserting clock skew.

`GET /v1/networks/{net}/datasets/{dataset}/rounds/distribution` reports
per-node/profile decision claims deduplicated by height, and round entries
with cause evidence. Causes are recorded or log-correlated within the same
engine run and height; unknown is preserved. A node's decision claims are
not pooled into one network distribution. Header decision rounds remain
the network-level source. Queries use an explicit wall-time window of at
most 24 hours and at most 100,000 relevant round-analysis records.

A real local G7 run covered normal progress, one proposer stop, two
consecutive proposer stops and a node restart. All original seven files
(1.71 GB) normalized without unknown phrases or malformed records. The
scenario window stored 38,302 events in 55.94 seconds after input-hash preflight. Height 5542 entered
round 1 (five timeout and one F+1 causes); height 5565 entered rounds 1 and
2 (five timeout causes each). Uninterrupted observer nodes claimed rounds
0:70, 1:2, 2:2, agreeing with RPC for those 74 heights. Timestamp ordering
regressions were retained as diagnostics. The committed regression input
is a sanitized, incomplete metadata excerpt of those two heights; it does
not replace the original real-run validation.

Inspector source overlay, node phase latency, visual replay/keyframes and
independent-run baseline comparison are implemented. Complete I2 checker
coverage and A3 message/clock integration remain separate. A3 message matching, directed latency and
follow-mode acceptance are also pending.

## Inspector log evidence

Run timelines can resolve inspector observation pointers to exact log
records. Reports retain only input ID, kind, node, SHA256 and profile;
input paths and launch metadata are discarded. A source jump requires
matching network identity, file SHA256, node, profile (when declared),
original line and height (when declared). Different, missing and ambiguous
sources remain unavailable. The report and dataset input names may differ;
content identity maps them without guessing between duplicate copies.

Selecting a matched pointer highlights its event, adds its node lane when
outside the page filter, and moves the time window when needed. The UI
shows resolution status and the source hash. Header-copy selection lists
only nodes with actual stored copies, separate from log-only inputs.

An independent legacy G7 report matches all 68 representative pointers
from 32 round-change and four engine-restart observations to the original
run inputs. Legacy coverage is not declared complete, so the report's
existing requirements remain 33 undecided and 32 not run. This observation
overlay is not a claim of full I2 checker coverage or A2 completion.


## Node phase latency

The run view provides phase statistics, histograms, cursor-page time series,
node p95 bottleneck candidates and source-linked samples. Summary and sample
endpoints are `/v1/networks/{net}/datasets/{dataset}/phases/summary` and
`/phases/samples`. They require `from_t`/`to_t` (at most 24 hours); optional
filters are node, full height, full round and metric. Sample pages additionally
accept clock, status, percentile threshold, limit (1..1000) and a filter-bound
cursor that also binds the derived snapshot. Appended source records invalidate
a previous cursor. A threshold requires one metric and a wall or monotonic clock.

| Metric | Start | End |
|---|---|---|
| preprepare | ROUND_ENTER | PREPREPARE_ACCEPT |
| prepare_quorum | PREPREPARE_ACCEPT | QUORUM PREPARE |
| commit_quorum | QUORUM PREPARE | QUORUM COMMIT |
| commit | QUORUM COMMIT | decision |
| import | decision | imported head |
| round_to_decision | ROUND_ENTER | decision |
| round_to_import | ROUND_ENTER | imported head |

For the WBFT profile, decision is FINALIZE_HANDOVER and import is NEW_HEAD,
following the engine's phase metric boundaries. In legacy gstable logs,
NEW_HEAD means "block proposal committed", so it establishes decision only;
"handle final committed" does not prove import. Import remains missing.
Unknown profiles are not assigned phase boundaries.

Pairing stays within the same node, input, engine run, height and round;
round and engine boundaries reset anchors. Repeated markers retain the first
source and expose an attempt-level duplicate count. The query includes context
back to each input/run's latest round or engine boundary before its first
selected record, with a 100,000 relevant-record cap. Samples are selected by
end wall time, or available start/attempt time when an endpoint is missing.
Source events outside the current filtered cursor page can be opened directly.

Measurements with two monotonic stamps use those stamps; one absent stamp is
missing_clock and does not silently fall back to wall time. Legacy logs have
no monotonic timestamps. Negative, missing and invalid-clock samples remain
visible and are excluded from valid statistics. Full integers remain strings.
Percentiles use nearest rank on raw valid samples (including overall groups),
standard deviation is population-based, and histogram counts equal valid
sample counts. Clock groups are separate. A bottleneck rank identifies observed
latency, not its cause. Cross-node matching and clock correction belong to A3.

The real G7 scenario window produced 3,689 measurements, including incomplete
attempts at the boundaries and proposer stops. Original-line timestamps and
raw-sample percentile/statistic calculations are independently checked; import
is unavailable for this source profile. This does not establish A2 replay or
complete event coverage.


## Visual replay

Run manifests accept input kind `events` for the pinned WBFT events-v1 schema,
or `log` (the default) for implementation-profile logs. Event files preserve
node/run/sequence, full height/round, monotonic timestamps and step metadata;
duplicate keys, identity mismatches and repeated/decreasing sequence numbers
are refused. Gaps and clock regressions remain diagnostics. Event normalization
is separately versioned; bytes, payloads and arbitrary error text are excluded
at both source and persistence. A source file is not proof of complete coverage.

Run ingestion builds a recorded-state projection with per-node keyframes at
height and lifecycle boundaries and every 1,024 records. Existing datasets can
be indexed with `reindex replay --db DSN --dataset ID`. The projection records
view, state, timer generation, observed quorum counts, partial backlog and the
last imported head or legacy decision claim. It does not execute consensus
rules. A message's view never replaces the node's view. Stale expirations and
cancellations of other generations cannot remove the active timer.

`GET /v1/networks/{net}/datasets/{dataset}/replay/window?from_t&to_t&node`
returns up to 100,000 metadata records with state immediately before the window.
`/replay/keyframe?node&t` folds the nearest preceding snapshot and a bounded tail
through t. The wall-time axis retains nanoseconds and deterministic input/line
ties. Optional `to_input` and `to_line` select an exact inclusive source endpoint
at `to_t`, including a cut within equal timestamps. Stale/missing indexes return
409 until reindexed; oversized windows return 400. GETs do not build indexes.

The run view provides Canvas playback, pause/rewind, source steps by node,
height and round, time or event-proportional speed, selected source loops,
keyboard controls, node states and timer marks, height/round counts, cause
flows and recorded quorum race counts/evidence. Counts are node observations,
not network decisions. Missing state and intermediate counts remain unknown.
A quorum message is linked by the same input/run/step; log-only links are
explicitly inferred. Info-only logs do not produce receive arrows. A3 adds
message pairing, link arrows and cross-node clock/latency analysis.

Real W2 proposer-stop/restart and 103,344-event simulations and real G7 logs
validate ingestion and the projection. Client/server seeks agree at 375
node/time cases across the datasets. An exact 100,000-event source window is
used for laptop Canvas cadence measurements. This validates visual replay;
closed re-execution, what-if and follow-mode acceptance remain separate.


## Independent run baselines

`GET /v1/networks/{net}/rounds/baseline?datasets=ID,ID&from=H&to=H&node=N`
compares 2..16 completed run datasets from the same network over a common
full-height range of at most 100,000 heights. The run view offers the same
selection and displays observer counts, individual rates, mean fraction and
unbiased sample variance/stddev. Source hashes expose provenance; repeated
node/profile/hash copies across selected runs are rejected.

Claims are deduplicated by node/profile/height. Each observer remains separate
from network decisions, and each independent run has equal weight. Rates use
known claims; unknown and missing heights remain explicit. A run with no known
claims contributes no rate, and a single valid run has no sample variance.
These statistics describe the selected runs and do not prescribe a universal
acceptance threshold or infer independent physical execution from a hash alone.

API and persistence verification cover missing observations, unequal known
claim counts, independent source identity and sample variance. Committed
fixtures are explicitly synthetic; original operational evidence stays local.


## Directional message latency

`reindex messages --db DSN --dataset ID` derives metadata pairs for a message
or run dataset. Journal/frame peers identify link direction; event broadcast
and processing records retain node strength; logged tuples retain key strength.
A recovered author is not substituted for a wire peer. Repeated sends/receives,
conflicting views or digests and low64 collisions remain ambiguous. Broadcast groups cover recording nodes without claiming intended recipient
membership. Missing observations do not establish transmission failure. Frame exports without an
explicit successful write remain unconfirmed.

The derived snapshot is committed atomically and is bound to dataset metadata,
progress, status and pairing version. GETs do not reindex. Matching uses the
whole source before window filtering, so an out-of-window retry still prevents
a false unique match. Reindex refuses more than one million source records or
projected endpoints; reads refuse more than 100,000 matching groups. Results
are never silently truncated. Stale indexes return 409.

`/messages/summary` and cursor-paged `/messages/pairs` keep direction, phase,
strength, measurement boundary, local/direct/relay/processing path and clock apart. Percentiles and
histograms use raw valid pairs, including overall and per-node distributions.
Local intervals require same-node/run monotonic stamps. Cross-node intervals
use the declared shared-host clock or NTP uncertainty; unknown clocks retain
raw trends only. Input gaps, partial runs and unavailable diagnostics remain
explicit. Candidate views and immutable source pointers survive ambiguity.
`/messages/source?input&file&ordinal` resolves one original metadata record.

The message latency view connects filters, directional p95 cells, raw-sample
histograms, node statistics and pair/source details. Chart motion is optional
and respects reduced-motion preferences. Event stamps can share one step;
zero elapsed time describes those recorded stamps. This does not complete
arbitrary mixed-log association, physical-link capture, missing-seal classification, follow mode or re-execution.


A message journal can explicitly name one completed native-event companion:

```sh
wbft-analyzer reindex messages --db "$WBFT_ANALYZER_DB" --dataset MESSAGE_ID --events EVENT_ID
```

Both datasets must belong to the same network. Matching names or overlapping
wall times are insufficient: every stepped outcome multiset and its recorded
step clocks must agree across shared node/run identities. Missing or conflicting
anchors refuse the rebuild without replacing the prior index. Runs present in
only one source are counted and excluded from mixed projection. Coverage keeps
both datasets' input IDs and clock/gap diagnostics. Companion deletion or changed
metadata, status or progress invalidates the derived index.

Mixed endpoints use the weaker selected side's evidence grade. Repeated copies
at the selected grade remain ambiguous; lower-grade alternative observations
remain diagnostics with source pointers. A wire peer is not substituted for the
message author. Link latency, broadcast-to-receipt and broadcast-to-processing
are different measurement boundaries and have separate distributions; tail
thresholds spanning boundaries require a metric filter.

`/messages/series` uses fixed UTC seconds and full height/round strings. Each
bucket aggregates original valid pairs and preserves all evidence dimensions.
Absent buckets are not interpolated. The series view links a selected point to
its bucket, full view, table and charts, with mouse or keyboard selection. The
API refuses more than 2,000 bucket/view groups instead of truncating results.


`/messages/issues` exposes source observations that could not be projected,
lower-grade alternatives and message observations from unassociated runs.
State and timer records remain coverage rather than missing-message claims.
Pages have at most 1,000 rows and filter by recording node, diagnostic reason
or original source dataset. Cursors bind to a content snapshot of the complete
pair/issue projection and source metadata; changed sources or companions return
409 until reindexing. Identical rebuilt projections retain the same snapshot.
Reindex existing pairing snapshots to version 7 before using this endpoint.

The latency view offers p50/p90/p95/p99 raw tails and up to 20 non-local
directional p95 candidates within each evidence dimension, with valid sample
counts. These are recorded latency candidates, not causal bottleneck verdicts.
An event or log source opens its own dataset, original input/line and exact
source cut in the event/replay view. The cursor seeks through that record,
including records that share a wall timestamp. A filtered-out point remains
absent. Journal/frame pointers still resolve original metadata; they are not
converted into event pointers without association evidence.


The replay view overlays message relationships from its own event run or an
explicitly verified journal companion. `/messages/flow` selects groups whose
complete candidate time range overlaps the window, so a send before the window
and receive after it still remain visible. All candidates affect those bounds,
including candidates beyond the original-pointer preview. The API refuses more
than 2,000 groups; ordinary latency sample filters still use the send timestamp.

Solid lines identify valid link measurements; dashed lines preserve weaker
identity or uncertain clocks. Ambiguous or missing endpoints remain markers.
Only unique valid link endpoints support packet interpolation. The motion
switch and reduced-motion preference disable it while keeping recorded facts.
NTP bands show elapsed uncertainty relative to the recorded send without
correcting node timestamps. Event-ordinal replay retains evidence in the table;
message geometry uses the wall-time axis. Each relationship opens exact original
pointers in the evidence dataset or its verified event companion.

Native event files may append another node run only at a new `NODE_START` with
sequence zero. Original line numbers, timestamps and clock regressions remain
intact. Mixed execution association verifies complete outcome multisets and
both clocks. Step-entry event stamps may lie within adjacent recorded journal
completion stamps; that basis is exposed as `completed_step_interval`. No clock
tolerance or timestamp correction is applied, and absent bounds remain unproven.


## Recorded vote participation

`reindex missing` stores one explicit canonical index range per event dataset:

```sh
wbft-analyzer reindex messages --db "$DSN" --dataset "$MESSAGES" --events "$EVENTS"
wbft-analyzer reindex missing --db "$DSN" --dataset "$EVENTS" --messages "$MESSAGES" --from 1 --to 55
```

The optional journal must have a verified association with the event execution.
Association separates engine restarts within a node run using recorded engine
boundaries and journal step completions. Pairing version 7 requires a rebuild.
Native event normalization version 4 preserves active validator and sign-floor
metadata; reimport older inputs to obtain these fields.

The vote evidence page distinguishes `SEALED`, `SENT_ACCEPTED_NOT_SEALED`,
`SENT_REJECTED`, `SENT_UNSEEN`, `NOT_SENT` and `UNKNOWN` for each full height,
validator and PREPARE/COMMIT phase. Canonical own-copy or child-carried seals take
priority. Child participation requires the parent hash/index to match; an absent
child cannot establish a network decision round. Own-copy round remains separate.
A recorded send is an attempt, not proof of delivery. Accepted outcomes are local
processing evidence. Complete receiver coverage requires closed native views and
quorum; wire records and imported headers cannot establish this coverage.

`NOT_SENT` requires a closed active native view or a complete active event capture
with matching canonical head bounds and known send identities. An observer,
open prefix, lost records or opaque identity remains unknown. Active sign-floor
metadata retains its original node-start evidence. Sender capture coverage is
never counted as receiver coverage. Original event and header pointers remain
available from a selected matrix cell, including a replay link.

Read-only endpoints `GET /v1/networks/{net}/datasets/{dataset}/missing/index` and
`.../missing?from=1&to=55` serve the stored snapshot. Cell queries support
`validator`, `phase`, `class`, `reason`, `limit` and a snapshot/filter-bound cursor.
GET never builds an index. Source metadata/progress/diagnostics, verified journal
snapshot or header participation changes invalidate it (409); explicitly rebuild.
A failed rebuild preserves the prior projection. Each range permits at most 1024
indices, one million source events/journal records and 100000 cells; overflow is
refused rather than truncated. Evidence previews retain at most 32 event pointers
and disclose the total count. Blank positions on a filtered cursor page do not
mean missing votes. Last-head uncertainty remains visible when its child has not
been captured. This projection does not import live observation RPC or implement
follow mode or closed re-execution.


## Native node observation captures

Import a bounded read-only native RPC range, or a saved capture:

```sh
wbft-analyzer ingest observe --db "$DSN" --name node-observation-1 --rpc http://127.0.0.1:8545 --from 1 --to 56
wbft-analyzer ingest observe --db "$DSN" --name archived-observation-1 --archive capture.json
```

`wbft-analyzer-observe/1` archives contain `from`, `to` and `replies`, each with
`method`, string `params` and a JSON-RPC `response` envelope. Native node identity,
participation and summary requests are required; per-method error/null responses
remain unavailable. Live collection also requests configuration at each full
height and a header copy for every recorded non-gap hash. The node page exposes
request availability and parameters, node role/version/profile/rules metadata,
full-height participation claims and reported versus recomputed validator totals.
Configuration at one archived height does not establish the entire range.

Collections are not atomic node snapshots. Captured participation records are
aggregated with the pinned public WBFT definition; mismatched fields remain
visible. `source=local`, `source=header` and gap records stay distinct. Header-only
records cannot claim local message arrivals. None of these records establishes
complete native event coverage or send absence, including node sign-floor
metadata. These RPC claims do not replace canonical header facts or automatically
bind header copies to the canonical header overlay.

Migration 13 keeps observations separate from event/journal datasets. Imports
are atomic and immutable; retrying a complete identical source skips it, while
changing its content or network under the same name is refused. Node URLs, local
file paths, arbitrary properties, RPC error messages and aggregate signature
bytes are not persisted. Hashes bind the supplied capture/envelope representation;
live envelopes are reconstructed from the client result/error and are not claimed
to be original network packet bytes.

`GET /v1/networks/{net}/datasets/{dataset}/observations` returns node metadata,
request provenance and both summaries. `/observations/participation?from=1&to=56`
returns source-linked rows with bounded, capture/range-bound cursors; full heights
are decimal strings and may exceed uint64. `/observations/calls/{ordinal}` returns
one normalized request/result. Every participation range must return exactly one
record per requested height, including explicit gaps. Queries cannot exceed the
captured range or cross network/dataset scopes. Limits are 1024 heights, 4096 calls
and 32 MiB of response envelopes per collection. Duplicate JSON keys, duplicate
requests, malformed identities and delay aggregates outside int64 are refused.
Live follow, canonical/header comparison and actual takeover sign-floor acceptance
remain separate work.
