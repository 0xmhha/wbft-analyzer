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

To retain original inputs for subsequent replay, pass `--inputs-dir DIR`.
The directory must be private (mode 0700); a missing directory is created.
Files are copied as `DIR/<sha256>` with mode 0600 and verified against the
manifest fingerprint. Objects are published without overwriting existing
files; existing objects must verify too. Each file is bounded to 256 MiB
and a retention request to 16 GiB. Keep this directory outside the checkout.
PostgreSQL migration 16 stores only file names, SHA256, sizes and local paths
in `input_files`; paths and bytes are not exposed through HTTP. Retention
can be added to a completed metadata import using the same manifest and
storage directory. Retention does not prove replay input completeness.
A database dump does not contain these objects; back up the private directory
separately and preserve its path for replay lookups.

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

Native `BUILD_HANDOVER`, `BUILD_STARTED`, and `BUILD_FINISHED` events retain an
explicit build identity within the original input, node, and writer run. Select
a build event in Events to open every matching source candidate, or use
`GET /v1/networks/{net}/datasets/{dataset}/events/{input}/{line}/build`.
Only unique, ordered boundaries in a complete input without recorded gaps yield
an assembly-start-to-submission interval. Duplicate and incomplete candidates
remain visible. A submitted status describes the application call boundary;
it does not establish consensus acceptance.

Scenario fitting version 3 uses these actual assembly boundaries instead of
subtracting a declared wait. Known replacement, cancellation, and failure
outcomes remain separate from successful timing samples. The current simulator
does not model the application's serial request queue, so those outcomes keep
the application model incomplete. Reingest older event datasets to retain the
new metadata before fitting; existing stored datasets are not silently upgraded.

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

Native coverage requires event normalization version 5, which retains inbound-loss
HEALTH conditions. Older or unrecognized normalization cannot establish sender or
receiver coverage; positive seals and recorded sends remain usable. Existing
classification indexes require `reindex missing`. To recover previously discarded
conditions, ingest the original sources under a new dataset name before rebuilding.

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
metadata. These RPC claims do not replace canonical header facts. Explicit structural
binding to independently imported canonical headers is described below.

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


## Canonical observation bindings

After importing independent headers (including the preceding parent and following
carrier when available), explicitly build structural metadata bindings:

```sh
wbft-analyzer reindex observations --db "$DSN" --dataset "$OBSERVATIONS"
```

Migration 14 links full decimal RPC heights to unique canonical facts without
using their low64 indices as identity. The projection compares captured node
heads, node copies and participation records with canonical hash/parent/child,
governing validator ordering, proposer policy, rounds and seal indices. Missing
headers, source gaps and absent child proof stay unknown; conflicting hashes,
rounds or validator indices remain different. A supplied null seal in an
available copy means no seal of that phase, while an unavailable reply means the
copy is unknown. Own-copy round never supplies a missing network decision round.
Matched means structural metadata consistency, not aggregate signature verification.

Only structurally matched copies enter the explicitly scoped header overlay,
marked `rpc_observation_structural`. Source or canonical dependency changes stale
the projection and its copy consumers (409), including header views and missing
classification. Explicit rebuild replaces only this projection's own copies;
failed rebuilds preserve the previous index, rows and copies atomically. GETs do
not reindex. Captured source claims remain immutable and visible in their own API.

`.../observations/headers/index` returns stored scope/counts and independent
canonical validator totals. `.../observations/headers?from=1&to=56` supports
`kind=head|copy|participation`, `status=matched|different|unknown`, `limit` and
snapshot/filter-bound cursors. Head claims and replies without a positioned full
height remain visible independently of range filtering. Each detail retains
request/result-row pointers, canonical full number and index, parent/child proof,
recorded/expected fields and their required/optional status. The node page opens
an exact canonical index and optional bound node copy in the header view.

Canonical proposer opportunities count rounds through the child-proved decision.
RPC summaries can additionally count higher rounds entered by a particular node;
this definition difference stays visible. Canonical expectations include every
resolvable requested non-gap height, even when the RPC row disagrees, so the
comparison never hides discrepancies by excluding them from the denominator.
Local delay/evidence counters cannot be independently reconstructed from headers.
Bindings are bounded to 4096 rows and 6144 canonical dependencies; overflow is
refused. These bindings remain metadata analysis and do not establish complete
event capture or historical send absence.

## Native follow

`follow` continuously captures bounded header ranges and native WBFT participation.
Each source has a separate durable cursor. RPC outages, participation gaps and a
changing summary retain the cursor for retry. Network, node, configuration and
parent-hash conflicts stop that source. Full recorded heights stay distinct from
canonical uint64 indices; no height or round is converted through floating point.

```sh
wbft-analyzer follow --db "$WBFT_ANALYZER_DB" --config genesis.json \
  --name local-follow --from 1 --rpc http://127.0.0.1:8545 --node validator-a \
  --rpc http://127.0.0.1:8546 --node validator-b --poll 5s
```

Repeat the same name, ordered source labels, start index and configuration to
resume. Endpoints may change; their native identities must match. URLs are never
stored. The default runs until SIGINT/SIGTERM; `--duration 1m` bounds a check.
This mode requires native observation RPCs and a non-genesis start index. It
does not infer participation from a legacy endpoint or invent expired records.

A batch advances only after its header dataset and immutable normalized native
observation dataset are complete and their hashes/height coverage agree. A crash
before cursor commit can retry without skipping heights. Committed companions
cannot be deleted while a cursor references them. Payload bytes are not stored.

The follow screen shows each source's stored position, last commit, retry issue
and latest 100 committed batches. `GET /v1/networks/{net}/datasets/{dataset}/follow`
returns the same state. Stored importing status is not a process-liveness proof,
and native RPC claims do not prove event capture or message-delivery completeness.

The 72-hour acceptance run with a node restart and RPC interruption remains a
separate runtime check; short regression tests do not complete that requirement.


### Closed core replay

Retain a journal with `ingest messages --inputs-dir DIR`, then run:

```sh
wbft-analyzer reexec --db DSN --dataset ID --input JOURNAL_ID \
  --chain chain.rlp --from 1 --to 10
```

The command snapshots verified journal and canonical chain objects and runs
WBFT's `conformance/stepdriver.RunTrace` in a bounded child. `--helper FILE`
selects a versioned `wbft-replay/1` executable; the default is the linked core.
The advertised version is checked against the executable's Go build metadata,
and its SHA256 is retained. The checked dependency pin binds its exact module
version and checksum to the full origin commit; short-prefix guesses are not
used. Different or unknown versions are regression
comparisons. Inputs and the helper file are reverified after execution.

Active height means the recorded application head plus one. Completeness
requires contiguous steps from a recorded engine start, readable journal
records, the preceding/current/following canonical headers, and a unique
received-frame capture reference for peer messages. Legacy inline inputs need
a unique content/time witness. Asynchronously sampled legacy timestamps
or duplicate witnesses remain partial; peer identity and cross-node clock
alignment are not inferred. A gap or a configuration change within the same writer prevents
reproduction. New writers load their own recorded options. This does not reconstruct a missing input from its inline step.

A run reports output digest matches, `output_diverged`, validator-set-only
`env_mismatch`, or `not_comparable`. Arbitrary helper errors and payloads are
not persisted. `reproduced` requires matching verified versions and every
requested height complete; a digest match alone is insufficient. The child reports actual exhausted recorded application answers as
`env_exhausted`; other errors remain `replay_error`. It never infers exhaustion
from arbitrary error text.

For a middle-height selection, replay still executes the retained prefix from
its recorded engine start. The `warmup` summary reports this policy, original
source bounds, separate counts and the first prefix issue. A prefix output or
validator-set mismatch prevents reproduction even when every selected output
matches. Incomplete prefix evidence remains partial; an application failure
before the selected range retains its verified original position separately.
These counts do not inflate selected-step totals. The screen can open that
original prefix record. Older stored results without this optional metadata
remain explicitly unverified for prefix handling.

When a recorded engine start is missing, `--warmup-heights` defaults to 2
preceding active heights; set 0 to disable or choose at most 10000. The official
helper must advertise `bounded_warmup_v1`. The first retained step must reach
exactly the requested prefix floor. Missing bytes, inconsistent recorded head
identity, journal gaps and unavailable application answers are not repaired.
The bounded state starts from the recorded head and validator set, with unknown
prior backlog, view and timer state. Steps remain `approximate` until an actual
recorded engine start restores exact state. Matching approximate outputs cannot
establish reproduction; differences are `warmup_suspect`, counted separately
from exact mismatches. The original missing-start completeness issue is retained.
Prefix counts, approximate differences and original source pointers remain
separate from selected-step counts. Older helpers are refused for this mode.

Application answers default to their original source step. Explicit
`--answer-scope context` permits another recorded step only within the same
writer, engine, full head and validator context and call kind/argument key.
The official helper must advertise `context_answers_v1`. Every reported source
is checked against retained metadata and consumed once. Stored steps retain the
original file, ordinal and one-based call position without response values.
Conflicting or unrecorded answers stop execution; structured issues distinguish
`env_ambiguous`, `env_source_mismatch`, `head_mismatch` and `answer_limit`.
Context lookup always reports `counterfactual`, even with original inputs and
matching outputs. It does not reconstruct unrecorded application execution or
the reactions of other nodes. Missing-input omission is a separate policy.

The linked `reexec-helper` advertises `input_schedule_v1` and delegates
`input_schedule` requests to the pinned WBFT replay driver. An explicit context
answer scope and a complete recorded start are required. Missing-input omission
and bounded warmup cannot be combined with scheduling. The driver supports
external-input drop, delay, and receipt-proven swap; original source coordinates,
execution positions, and suppression reasons are returned separately. Completed
experiments remain counterfactual even when all output digests match. Recorded
receipt clocks and source files are preserved. Timer-policy rescheduling and
other-node reactions are separate requirements.

Use `reexec --input-schedule /private/change.json --answer-scope context
--warmup-heights 0` for a stored experiment. Schedule coordinates are decimal
strings to preserve full uint64 values in browsers:

```json
{"action":"drop","writer_run":"synthetic-writer","engine_run":"1","step":"8"}
```

`delay` and `swap` also require `other_step`. The operator's private replay
source configuration must set both `allow_context` and `allow_schedule` to true
before HTTP jobs can request a schedule. The allowed policy is included in the
source fingerprint. Schedule jobs use original-input mode, context answers and
zero warmup; missing-input omission cannot be combined with them. Exact schedule
identity is checked when linking a durable job to its stored result.

The result screen compares recorded and experiment order, preserves original
source links, and shows suppression reasons. Pages and the first difference use
verified execution positions; recorded receipt clocks and source positions stay
unchanged. When application provenance cannot be verified against the execution
slot's full recorded context, comparison stops rather than accepting a response
from a different head or validator context. Timer-policy rescheduling, proven
open-loop validity boundaries and scenario fitting remain separate acceptance
requirements.

Bounds: 10000 active canonical heights, 100000 steps, one million journal
records, a 256 MiB chain file, 64 KiB protocol lines, 64 MiB helper output and
a 5 minute default deadline (`--timeout`, up to 30 minutes). Chain indices must
fit uint64; full recorded numeric strings are never truncated. Raw chain and
journal objects remain in the private input directory and require separate
backup. Migration 17 stores replay summaries and metadata-only steps outside
canonical network facts. Finished runs are immutable.

Read the latest 100 runs at `/networks/{net}/datasets/{dataset}/reexec`, one
summary at `/reexec/{reexec}`, and bounded execution-ordinal pages at
`/reexec/{reexec}/steps?after=0&limit=500&class=match&height=1` (paths below the
same network/dataset prefix). Structured helper failures identify their original writer, engine and step.
Recorded input gaps and exhausted application answers retain that exact source
position; generic failures remain not comparable. Older helpers without
structured positions retain a run-level issue without an inferred step.

The core replay screen shows versions,
completeness, an execution-order difference strip, the first difference and the
exact original journal record. HTTP reads do not execute a replay. Start a
run with the local command or enable the bounded job worker below.

Operators can start `serve --reexec-sources /private/sources.json`. This is
a private regular JSON file (0600, at most 64 KiB) containing 1–16 entries:

```json
[{"id":"retained-node","dataset":1,"input":"journal-node",
  "chain":"chain.rlp","timeout":"5m","allow_loss":false,"allow_context":false}]
```

Paths are resolved relative to this file. An optional `helper` selects an
operator-owned executable; otherwise the linked core helper is used.
The configuration binds retained input, node, chain and helper fingerprints,
deadline and allowed modes. A changed source fails closed. Each HTTP execution
uses a verified private executable snapshot; clients cannot choose paths,
commands or arguments. `allow_loss` explicitly permits the separately labelled
counterfactual input-loss mode. Independent `allow_context` permits context
application lookup. Neither permits original reproduction claims.

Under `/v1/networks/{net}/datasets/{dataset}`, `GET /reexec-sources` lists
enabled source IDs, allowed input modes and `answer_scopes`. Optional
`answer_scope` defaults to `step`; `context` requires operator permission and
forces the linked result to be counterfactual. Migration 21 persists this policy
and checks result links against it. `POST /reexec-jobs` accepts `source_id`, decimal-string
`from_height` and `to_height`, and `mode` (`closed` by default). The strict
request limit is 4 KiB. Heights fit uint64, and the inclusive range is at most
10000 heights. Optional integer `warmup_heights` defaults to 2, accepts 0 to
disable, and is bounded to 10000. Migration 20 durably stores the chosen depth
and the separate `warmup_suspect` step class. The existing bearer token, loopback and same-origin JSON checks
apply. The response is 202 with a durable job ID. `GET /reexec-jobs` lists the
latest 100 jobs, and `GET /reexec-jobs/{job}` returns one scoped job.

Migration 19 stores this queue. At most 32 jobs may be queued or running across
the database/schema, and one worker owns a dedicated database lease. Execution
uses the same stored runner as the CLI and links its result ID. Queue success
means execution finished; the linked result independently reports version,
completeness and reproduction. On restart, queued jobs remain queued; interrupted
running jobs fail with `worker_interrupted`, unless their linked result had
already finished. They are never silently rerun. A clean worker stop records
`cancelled` for its active job. Stored summaries and raw retained inputs need
their usual separate backups; the source configuration is also operator-managed.

The core replay screen queues registered sources, updates active job status
every two seconds, and opens the linked result and original-record evidence.

A missing referenced received frame fails closed with `input_gap`. The explicit
`--omit-missing-captures` option instead runs a counterfactual loss experiment:
it omits that input, compares the actual empty output at the original step,
and continues with recorded application answers. Invalid or ambiguous capture
references are still refused. Migration 18 accepts the separate
`counterfactual` status, and the screen labels omitted inputs and this mode.
Even matching outputs and versions cannot turn this experiment into original
reproduction. Full closed replay
acceptance still requires the complete simulation/restart bundle,
cross-architecture comparisons and the remaining received-message mutation
criteria. Visual event playback is separate from core execution.


### Recorded event evidence for a replay step

Select a journal source in the core replay screen and choose its original
completed event dataset. The read-only `/reexec/{reexec}/events` endpoint takes
`ordinal` and `event_dataset`. It checks the retained input fingerprint, original
journal coordinates, message outcome and clock association, and explicit writer,
engine and step identity in one database snapshot. A copied competing event
input, unavailable source, incomplete association or absent engine identity
remains unavailable. At most 1000 original events are returned; excess sources
are refused rather than truncated. Each link opens the exact original event and
its visual playback position. Event association does not change stored replay
classifications or establish core reproduction.

### Dataset deletion and retained input ownership

New retained inputs use a private namespace for each dataset under the chosen
`--inputs-dir`. Equal SHA objects in another dataset remain independent. Chain
objects retained for replay use the same namespace. Namespace ownership is bound
to the database, schema and server endpoint; a restored database cannot delete
its source database's bytes.

The datasets screen shows input ownership. Confirm the exact dataset name to
delete its records, replay results and owned input objects. Active imports or
replays and referenced follow captures block deletion. Queued replay jobs are
cancelled. Canonical network header facts and the original external source files
are preserved. There is no automatic retention timer.

`dataset delete --db DSN --network N --dataset N --confirm-name NAME` uses the
same operation as `DELETE /v1/networks/{net}/datasets/{dataset}` with JSON
`{"confirm_name":"NAME"}`. Deletion intent is committed before file cleanup;
interrupted cleanup remains `deleting` and retries with the same name. The
`dataset deletion` command and `/deletion` endpoint retain the completed result.
Only validated objects in the owned namespace are removed. Arbitrary files,
symlinks and changed ownership refuse cleanup. An empty ownership marker remains
for retry verification; it contains no journal or chain bytes.

A database dump contains metadata and references; retained input objects need
their own filesystem backup. Adoption requires the source objects to remain
available.

Older shared inputs and inputs restored from another database must first be
copied and verified with `dataset adopt-inputs --db DSN --network N --dataset N
--inputs-dir /private/inputs`. References change atomically after all source
objects verify; the original shared or source-database objects are preserved.
Interrupted adoption retains its candidate namespace and resumes with the same
root. Other imports and deletion wait for adoption to finish. Paths and ownership
identities are not exposed by the API.


### Declared legacy execution scopes

A run manifest may add `legacy_associations` entries binding an original legacy
log input and native event input by their exact SHA256 fingerprints, the legacy
logger's own `address`, and explicit `from_t`/`to_t` bounds (at most 24 hours).
Reindexing a journal with this event companion still requires the existing
native stepped outcome and clock proof. Legacy records are selected only inside
the declared scope after logger identity and at least two unique matching head
number/hash witnesses corroborate it. Conflicting or repeated head witnesses,
changed inputs, copied declarations and insufficient evidence refuse reindexing.

The separate `declared_head_anchors` grade is visible in the index and legacy
source pointers. This corroborates an operator declaration; it is not native
step identity or wire receipt proof. Original input/run namespaces are preserved,
and excluded message observations remain source-linked diagnostics. All head
witnesses are checked; the index previews at most 16 original head pointers per
scope. Legacy message tuples remain weak `key` evidence. Native-to-log values
measure propagation to processing, while log broadcasts paired with journal
receipts use `broadcast_to_receipt`; neither is promoted to link latency. A
missing or incompatible clock model retains raw trends only.

Legacy extra-seal processing entries can supply weak `key` receive evidence for PREPARE and COMMIT. Their recorded processing time is not transport arrival time. Repeated copies remain ambiguous; native extra-seal entries are not counted again alongside message outcomes.

When a received wire observation is unavailable, a unique associated native processing event may supply `node` evidence. Its processing timestamp and original source pointer are retained; the metric becomes `propagation_processing`, and it is excluded from wire-link latency. Missing or repeated processing observations remain unavailable or ambiguous.


New live journal steps retain measured entry monotonic and wall stamps separately
from recorded completion stamps. Original source metadata and replay evidence
preserve both; measured entry zero is retained. Older journals and reconstructed
WAL steps keep entry unknown. Message normalization version 5 binds this metadata
projection into new dataset fingerprints. These stamps do not establish timer
policy replay on their own; changed-duration expiry regeneration remains pending.


Measured timer journal records are available in the message metadata view and
original source panels. Operation sequence, timestamp, arm cause, full view,
generation, deadline and cancellation kinds remain exact decimal strings.
A timer operation is local scheduler evidence, not a wire message. Missing arm
context stays explicit; lifecycle/restoration coordinates do not invent a
source core output. The timeout context is identified by its SHA256; payload
bytes are retained only in the original source. Legacy journals do not acquire
guessed operation times. Projection version 6 invalidates older normalization
fingerprints without changing retained source files.

### Timer policy experiments

`whatif` executes a bounded counterfactual policy against a complete retained
journal and its recorded chain. It verifies original core outputs and measured
timer operations before regenerating expiries and internal inputs. Undeclared
or incomplete timing evidence, WAL timing, and unrecorded application or signing
answers are refused. Generated inputs have execution coordinates and nullable
source references; they never acquire an invented original ordinal.

```sh
wbft-analyzer whatif --db "$WBFT_ANALYZER_DB" --dataset 1 --input journal \
  --chain ./chain.rlp --timer-policy ./timer-policy.json
```

Policy values are exact decimal strings. Omitted fields preserve the source
configuration; duplicate fields, numeric values, zero request timeouts and
values outside the duration range are rejected.

```json
{"request_timeout_seconds":"2"}
```

To enable HTTP jobs, register retained inputs with `--reexec-sources`. A timer
source must explicitly set both `allow_timer` and `allow_context`. The worker
pins source, chain and helper hashes and snapshots the helper executable before
running it. External helpers must declare `timed_inputs_v1`, `timed_state_v1`
`timed_actions_v1` and `context_answers_v1`, and identify the exact known core version.

```json
[{"id":"local-node","dataset":1,"input":"journal","chain":"./chain.rlp",
  "allow_context":true,"allow_timer":true,"timeout":"5m"}]
```

The **timer experiments** page submits a policy, follows durable job status and
opens the linked result. Read routes are dataset-scoped `/whatif`,
`/whatif/{id}`, `/whatif/{id}/results`, and `/whatif-jobs`; POST `/whatif`
returns a job. Replay and timer jobs share a queue bound and one worker owner.
Interrupted running jobs become failed; already stored execution rows remain
partial. Completed jobs retain their finite source horizon and pending work.

Ordered output fingerprints distinguish timer changes from network output
intents. The detail view shows executed outputs and original slot outputs
separately, exact recorded signing inputs and producer output numbers,
application-question positions, and generated/failure parent outputs. Network
byte fingerprints are available only for recorded signing results or core relay
bytes; unsigned requests remain explicit. Eligible recipients describe validator
membership intent, not transmission or arrival. Historical rows without action
evidence retain nullable arrays and an unavailable comparison. The consumer
checks original fingerprints, signing bytes and question references against the
retained source, rejects repeated source/signing evidence, and requires all
original external and suppressed internal slots before accepting source-horizon
completion. Original timeout inputs are independently identified, listed as
replaced, and never assigned to a generated expiry.

Experiments hold recorded external slots fixed, assign zero processing cost to
generated inputs, and reuse only recorded signing results and application
answers. Every result remains counterfactual. Changed-output delivery and other
nodes' reactions are not reconstructed; completion cannot establish a network
future. Canonical facts, source-ordinal replay rows and experiment execution
rows remain separate. Seed fitting, network simulation and round distributions
require separate validation.

`dump-check.sh` includes a complete synthetic timer journal, non-empty stored
experiment results and exact original-record lookup. Its retained timer inputs
remain alongside the database dump. A restored database must adopt retained
objects into its own namespace before modifying or deleting them.

### Original network links and experiment influence

Timer experiments retain separate original-output network bindings and
execution-ordered network/commit effects. Bindings compare verified original
producer fingerprints with complete retained frame bytes, direction, peer,
code, writer and send cause. Repeated producers or writes stay ambiguous;
missing receivers, failed writes and unknown clocks never become arrivals.
The original receive interval uses only the declared shared-host or bounded
NTP clock scope. Every selected input hash and clock declaration is retained.

The detail view shows each effect and its exact original send/receive pointers.
A generated or relocated output can reuse recorded signing bytes without
reusing their arrival time. Commit delivery through the application remains
explicitly unproved. Original deletion effects are added only after full source
completion, in the same transaction as finalization; interrupted runs cannot
acquire a fabricated deleted suffix. Execution rows and derived effects are
also persisted atomically. Recovery reconciles counts from preserved rows.

`network-bindings` and `network-effects` below a dataset-scoped `whatif/{id}`
provide bounded cursor pages. The summary separates the first unproved executed
output from an observed receive for a removed original intent. New bytes never
inherit an old latency. Hatched rows mark unproved model regions; bounded
original-receive regions use exact nanosecond original entry stamps and declared
clock uncertainty. Generated inputs without a recorded wall stamp remain
unaligned. A source-horizon completion is not proof of other nodes' reactions.
Historical runs without this evidence are explicitly unavailable.

### Network fitting and independent seed experiments

The default fitting model is `declared-runtime`. Use `scenario fit --model
empirical-core`, or set `"model":"empirical-core"` in a registered source,
to explicitly choose a fake application with per-node empirical delays. This
mode keeps the declared runtime assessment separately. It does not claim that
successful measurements prove a physical executor policy.

Frame-only nodes require matching runtime configuration and exact core
lifecycle evidence before substitution with WBFT cores with every improvement
disabled. Substitutes use fresh test keys from genesis with no WAL replay; this
is a model assumption, not an observed signing state. Native nodes retain their
recorded options and verified replay/signing policy. The model records these
choices and source hashes in immutable experiment provenance and labels
substituted nodes on the experiment screen.

Runtime assembly samples measure worker entry to task offer, including assemblies
whose later seal was cancelled. They exclude sealing, delivery, and consensus
acceptance. Import samples require a successful single-block call; batches are
not divided into invented per-block durations. Known native non-success outcomes
and excluded runtime intervals remain visible. Native delay distributions are
conditioned on successful observations. Missing clock, continuous receiver
coverage, settled horizons, configuration, or lifecycle evidence still prevents
execution. A complete fit still requires independent baseline validation.

`scenario fit --db DSN --dataset ID --chain chain.rlp --events-manifest events.json
--origin 2026-01-01T00:00:00Z --from 1 --to 60 --duration 2m --seeds 32`
inspects retained message inputs and canonical headers without migrating the
database. Native journals and captured wire frames retain their original input
hashes and source positions. A model with missing node options, startup policy,
application timing or directed-link coverage stays partial and cannot execute.
An absent receipt is not treated as packet loss without independently verified
receiver coverage and a settled observation horizon. Older engine records that
omit replay configuration do not prove that WAL replay was disabled.

`serve --scenario-sources /private/network-sources.json` registers a private,
owner-readable JSON array of source declarations. Each entry selects an `id`,
`dataset`, `chain`, optional `events_manifest`, RFC3339Nano `origin`, numeric
`from` and `to`, Go duration `duration`, declared `clock`, `skew_ms`, and `seeds`.
Optional receiver `coverage` entries must come from an independently verified
recording interval. Caller-supplied runtime policy cannot replace recorded
engine startup evidence. The server pins declarations and retained chain/event
objects; changing a registered source ID's evidence is refused.

The network experiments screen shows source coverage, queues a bounded outgoing
link cut, and reads durable jobs and seed results. It uses the same execution
worker, database lease and queue limit as core replay. Execution availability is
reported separately from readable source and result metadata. Incomplete models
remain readable. Recovery preserves saved seed prefixes and records interrupted
executions without inventing a completed suffix.

Comparison charts keep one recorded chain separate from baseline and changed
seed groups. Round and block-period ECDFs share axes; elapsed header-time bands
show the seed minimum, lower median and maximum, rather than confidence
intervals. Integer labels remain exact, and partial groups are not pooled into a
complete distribution. Animated chart reveals respect reduced-motion settings.
Fitting completeness, completed simulation, baseline round agreement and the
unconfigured timing acceptance threshold remain separate evidence. This feature
does not establish a complete fit of a physical mixed-node capture.

Fitting selects application samples and link pairs in the registered height
range after pairing the whole immutable source. Only records whose full heights
prove that they are outside the range are excluded; unknown heights and
ambiguous candidate views remain unproved. Source coverage reports the excluded
and unresolved counts. Lifecycle evidence and original retained bytes are
preserved, and scope counts are part of the immutable model identity.

A fitting interpretation change requires a new registered source ID; existing
source bindings and stored experiment results are never silently rewritten.

Network fitting retains candidate membership at each recorded epoch and
verifies the epoch header against canonical proposer and seal inputs. It maps
new candidate identities to deterministic test keys, preserving the original
genesis membership and candidate order. Simulated diligence and validator
selection are recomputed from each run; recorded winners are not forced into
a changed execution. Header-input agreement does not prove execution-state
registration. Key rotation and parameter transitions that cannot be represented
remain unavailable. Source metadata exposes the recorded epoch evidence.

Message normalization retains optional transport I/O endpoints from journals
and R-01 frames as exact nanosecond strings and RFC 3339 wall timestamps. The
message source view shows these separately from the original callback time.
Older records retain absent intervals, measured zero remains known, and wall
clock regressions are not corrected. Invalid or incomplete interval evidence
is refused. The normalization version is part of dataset identity; use a fresh
dataset for a changed interpretation. Existing latency values and pairing rules
remain unchanged; interval presence does not establish corrected latency or
complete transport coverage.


The optional `write_start_to_read_complete` message metric measures recorded
write entry to payload read completion. It includes the write call, excludes
sender queue wait, and remains separate from the `link` callback metric.
Projection retains unmeasured candidates so repeated copies cannot become
unique by dropping their missing clocks. The source position still opens the
original record; projected endpoints retain the original callback stamps.
Message pairing identity advances to version 9.

The latency view and replay timing selector keep these measurements separate.
Only unique valid measured endpoints animate; clock uncertainty, absent timing,
negative observations, and ambiguous copies remain visible without correction.
For network fitting, explicitly select
`scenario fit --wire-metric write_start_to_read_complete`, or set `wire_metric`
on a registered source. The default remains `link`. The selected definition is
included in the model identity and source metadata (fitting version 2); use a
new source ID when changing it. Neither I/O timing nor received messages alone
prove receiver coverage or zero loss. A full baseline still needs runtime and
application inputs and the original independent-seed credibility checks.

Runtime sidecars can be imported separately with `ingest runtime --file FILE
--name NAME --chain-id DECIMAL --genesis HASH`. The network identity is declared
by the operator; the sidecar alone does not prove chain membership. Original
node, writer run, source SHA256, line numbers and exact operation IDs remain
bound together. The runtime calls screen and read-only `/runtime`,
`/runtime/calls`, and `/runtime/calls/{call}` endpoints retain known return paths
and missing evidence. Call pages contain at most 100 intervals. Configuration
scalars and times remain decimal strings. Complete capture evidence is separate
from a complete execution model, remote delivery, or application request
completion; runtime sidecars do not become native consensus events.

Scenario fitting accepts `--runtime-manifest FILE`, or `runtime_manifest` on
an operator-registered source. The manifest format is
`wbft-analyzer-runtime-manifest/1`, with the declared network and inputs containing
`id`, `node`, `path`, and `sha256`. Original sidecar bytes are retained as immutable
SHA256 objects. Worker reload uses those retained objects; changing external
files does not rewrite a registered source. Runtime IDs and hashes are part of
fitting provenance. Register a new source identity for changed inputs.

Each runtime binding retains the exact startup line, writer run, configuration
comparison, and observed call count. Startup scalars are checked at their
recorded full height against chain configuration. This establishes neither
chain membership nor native engine options, sign-floor/WAL state, remote delivery,
or application request completion. Later configuration remains unproved when
transition or upgrade counts are present. These execution models remain partial;
observed worker return intervals never become successful proposal timing samples.

Task-stage normalization preserves exact task tokens and all recorded
sealing stages. The source panel separates worker return, task transfer, Seal
return, actual request post, result handover and cancellation. Intervals use
unique original local monotonic boundaries; duplicate or incomplete candidates
never select a preferred record, and reversed clocks are not corrected. Selecting
a call brings its source panel into view and moves keyboard focus; reduced-motion
preferences disable smooth scrolling. Older stored captures without task stages
remain unavailable for asynchronous completion. Reingest under a new dataset
name for the new metadata. Fitting provenance retains task-state counts
without claiming a complete engine, application queue, or delivery model.


Runtime normalization preserves concrete core instances, their exact
startup parent, creation point and every lifecycle stage candidate. Runtime
summary and fitting provenance retain core-state counts. Selecting
either the exact start or stop parent exposes the same complete candidate set;
unrelated calls are never joined by nearby time or height. The bounded API
refuses oversized sets without choosing a subset. Stage parents, IDs and
nanoseconds remain decimal strings. Older stored captures have unknown lifecycle
evidence; import a new dataset name to retain the new metadata. A recorded
startup or shutdown does not prove current process liveness, native options,
input processing, application queues or receiver coverage. Execution models
remain partial until those inputs and semantics are established.


Runtime normalization version 4 retains every historical startup candidate and
all exact per-instance configuration snapshots. The runtime API and source panel
show original engine/parent identities, lines, full heights and scalar settings;
creation, lifecycle and configuration candidates share one response bound.

Fitting provenance version 7 compares every exact snapshot at its own full
recorded height. One mismatch remains visible even when another snapshot passes.
Ambiguous configurations and multiple unbound legacy startup rows never become a
preferred first value or a complete execution model. The single `startup` field
is a historical compatibility field; use `startups` and `configurations` to read
the full history. Later effective settings, native options, input handling,
application queues and receiver coverage remain unproved by these snapshots.

### Declared application execution policies

Event normalization version 9 retains the closed optional
`NODE_START.application_model` declaration through persistence. Network fitting
version 8 includes every startup source, node, writer and line in model
provenance and exposes them in the network experiment source screen. Existing
datasets are preserved; import a new dataset to retain the new metadata.

The supported declaration is the per-node `serial-latest` simulator queue,
`sampled` assembly return and `callbacks_then_done_then_pending` selection,
with an explicit `failed` or `submitted` Done result. Every startup must agree
for that node. Missing, duplicate or conflicting declarations keep fitting
partial. Measured successful durations never supply a queue or executor policy.
Known unsupported failures and cancellations remain separate from successful
timing samples. Physical executors, other application queues, input handling
and receiver coverage still require their own evidence and execution models.


### Scoped transport inputs and empirical parameter evidence

Network fitting version 11 accepts repeated `scenario fit --transport-input ID`
flags, or `transport_inputs` on a registered source. Select at most one message
input for each node when the same traffic has both journal and frame observations.
Unknown IDs, duplicate choices, aliases from the same node and nodes outside the
fitted validator scope are refused. Missing nodes still leave the model partial.
Without a selection, all candidates remain; absent timing never removes a copy.
Selected input IDs, nodes and exact hashes are exposed by the source screen and
bound into model and execution provenance. All other snapshots remain retained,
validated and included in source provenance for configuration and inspection.

Message normalization version 9 retains the optional closed `payload_source`
field. `consumed` identifies observed reader bytes; `provided_reader_snapshot`
is accepted only for a failed outbound write with payload evidence. Such a
snapshot retains the attempted message identity and the write failure. It does
not establish byte consumption, a successful write, receiver coverage or loss.
Older captures retain unknown payload origin; use a fresh dataset to normalize
new metadata. Arbitrary source fields remain excluded from persisted records.

The empirical core model distinguishes static WBFT parameters from contract
execution. Every observed configuration must match the chain scalars and all
other snapshots, declare zero WBFT transitions and retain complete capture
evidence. System contract upgrades are counted separately because this model
uses recorded epoch candidate inputs with a fake application. The source screen
labels the parameter evidence and this substitution explicitly. Nonzero WBFT
transitions, scalar changes, ambiguous snapshots and recording gaps remain
unproved. The independent declared-runtime assessment and its unavailable
evidence remain unchanged.

### Recorded consensus engine lifecycles

Fitting version 12 distinguishes process starts from consensus engine instances.
Native event history binds each generation to its original writer, source line
and recorded wall time. A complete closed history can drive `engine_stop` and
`engine_start` on the same simulator runner; application imports, transport,
signer and WAL remain alive across a pause. Node shutdown teardown never becomes
a second engine pause or a fabricated node restart. Every generation must carry
its own compatible replay policy.

Missing stops, repeated or skipped generations, unrelated writers, unclosed
history and reversed clocks remain partial. No ambiguous candidate becomes a
preferred first value. The source screen displays all retained engine instances,
shutdown scope, missing evidence and replay policy coordinates. These observed
controls remain part of the empirical fake-application model and its immutable
identity. A complete lifecycle does not establish peer availability, physical
executor equivalence, or baseline round and time credibility.


### Closed observer transport scope

`scenario fit --transport-manifest FILE` and a registered source's
`transport_manifest` retain a closed capture's controller, per-node RPC header
copies and recording certificates as private SHA256 objects. The manifest uses
format `wbft-analyzer-transport-manifest/1`, an `id`, the message `network`, a
`controller` file, a `headers` file array and `windows` entries containing a
message `input` ID and a `certificate` file. Each file has `id`, `node`, `path`
and `sha256`; the controller node is `network`. Paths resolve relative to the
manifest and never appear in the fitted public scope.

The controller format is `wbft-local-takeover-case/1`. Its stopped processes,
normal exit codes, launch identities, independent `captured` cutoff and verified
header range are checked against the original frame streams and chain. Every
node's header hashes must match the retained RLP chain. Recording certificates
use `wbft-transport-recording-window/1` and keep
`delivery_coverage_proven=false`. Exact frame hashes, sequence, source lines,
closed peer sessions, pending operations and native node shutdown/restart gaps
are verified. An engine pause cannot establish a process recording gap.

Version 13 supports this explicit empirical model for shared-host clocks with
zero skew and selected frame inputs. A separate `coverage` override is refused.
Local outbound session intervals become directed simulator partitions; the
simulator still lists all other live nodes as peers and drops in-flight delivery
at a closing boundary. Boundary clock uncertainty is not modeled. These choices,
all retained witness hashes and the finite receiver windows belong to immutable
model provenance. Controller process-state claims are attestations; content
hashes establish source identity, not authenticity or physical network delivery.

Stored sources reload the owned witness objects after external files change.
Dataset adoption, deletion and dump/restore include these objects. The source
screen shows windows, sessions, assumptions and exact source coordinates.
Completing this transport model does not establish baseline round or time
credibility, executor equivalence or a validated counterfactual.


### Scenario wall-clock origin

Recorded network fitting binds the declared `origin` to simulated time zero,
including fractional seconds. Every node incarnation retains this per-run UTC
origin and its declared skew. The source response and stored experiment show
`wall_origin`; the execution hash includes its canonical instant. Fitting
version 14 changes this execution scope, so an earlier registered source must
be retained and a changed fitting registered under a new source ID. Historical
experiments without this field remain readable with unavailable clock metadata.

Without an explicit processing policy, the empirical model records that receive
checks and core steps consume no simulated time. Clock alignment does not establish baseline
reproducibility. Round and time
checks remain independent; an unconfigured time criterion stays unproved.

### Header interval baseline evidence

Fitting version 15 binds `wbft-header-interval-baseline/1` to the model hash.
Experiment version 2 derives `baseline_time` from retained canonical recorded
headers and complete baseline seed rows. Storage independently recomputes it
before finalization. Changed criteria require a new source identity; existing
version 1 experiments retain their original unconfigured time check.

The criterion compares the full integer-second header interval distribution
over the same contiguous height range. Nodes do not supply extra independent
observations. Every category is retained, including long intervals. At
significance level 0.01, homogeneous runs use a fixed-row-and-column-margin
probability-mass test. Heterogeneous runs require at least two recorded runs
and use a whole-run CDF permutation test preserving within-run order. A single
recorded chain cannot satisfy that replicate requirement. Homogeneity
non-rejection does not establish independence within a run. See the
[conditional table definition](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.fisher_exact.html).

Bounded complete enumeration is preferred. Larger tables or label spaces use
deterministic conditional Monte Carlo with a plus-one p-value, following the
[random permutation correction](https://arxiv.org/abs/1603.05766). The sample
count is fixed before sampling, up to 200,000 samples and a bounded work budget.
Fixed-sample Bernoulli Chernoff/KL tail bounds quantify numerical uncertainty
with error probability at most 0.000001 per sampled test. The summary includes
their union bound across all sampled tests. Acceptance is unproved if those
bounds straddle 0.01, precision cannot resolve probability-mass ties, recorded
times are missing, or dimension/work limits are exceeded. Monte Carlo never
reports a zero p-value. Exact floating-point underflow retains log(p).

`baseline_time_check` distinguishes `passed`, `failed`, and `unproved`;
`pending` precedes baseline completion. A rejected time distribution yields
`baseline_time_failed` when model and round gates otherwise pass. A failed
baseline retains counterfactual outputs. Statistical non-rejection is
conditional on the stated sampling assumptions and does not prove physical
equivalence. The UI shows homogeneity and comparison methods, numerical bounds,
complete histograms, and assumptions separately from execution completion.

### Recorded processing service policy

Fitting version 16 optionally accepts `--processing-policy native-pre-dispatch/1`
and an explicit `--processing-workers` count from 1 through 256 for the empirical
core model. Registered source configuration uses `processing_policy` and
`processing_workers`. Existing source identities remain immutable; register a
new ID when enabling this policy. Experiment version 2 keeps its header interval
criterion across fitting versions, including previously stored version 15 runs.

The verified native journal decoder extracts whole-step monotonic entry and
completion intervals in the recorded `head + 1` height range. Source fingerprints
are checked before and after inspection. The model retains each original file,
ordinal, writer, engine generation, step, exact integer timestamps, interval and
excluded source position. Measured zero remains a sample; a missing entry stamp
is unavailable. Lifecycle and WAL replay steps are excluded. Missing native
evidence or incomplete in-scope measurements prevent a complete fitted model.

Native nodes sample the retained durations by input kind and protocol code,
preserving sample order and multiplicity. A core input occupies its serialized
service slot before the existing operation dispatches atomically. This is a
declared pre-dispatch approximation: it does not reconstruct internal CPU, WAL,
signing or output milestones. Receive-check costs, frame-only substitutes and
unlisted work classes remain unmeasured and have zero modeled cost. The receive
worker count is declared, not measured; samples do not condition on host load or
internal execution branches. Lifecycle and replay remain synchronous.

Processing evidence and assumptions belong to the model hash; workers and
execution cost samples also belong to the execution hash. Source and stored
experiment screens show measured ranges, paginated samples and exclusions, and
links to original timing records. Enabling the policy does not establish round
or time baseline credibility; those checks retain their independent criteria.
