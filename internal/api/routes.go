package api

import (
	"github.com/0xmhha/wbft-analyzer/internal/derive/baseline"
	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/derive/rounds"
	"github.com/0xmhha/wbft-analyzer/internal/replayjob"
	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	sourcemessages "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"net/http"
)

// route is one operation of the API. The table below is both what the
// server mounts and what the OpenAPI document describes (openapi.go), so
// the two cannot disagree. GET /v1/openapi.json, the document itself, is
// mounted and described apart: listing it here would make the table
// depend on itself.
type route struct {
	method, path string
	id, summary  string
	params       []param
	// body is a value of the request body type, nil without a body;
	// rawBody describes a body that is not one of the API's types.
	body    any
	rawBody string
	// answers are the success answers by status code; every operation
	// also answers 4XX and 5XX with Error.
	answers map[int]any
	handle  func(*Server, http.ResponseWriter, *http.Request)
}

// param is a path or query parameter.
type param struct {
	name, in, doc string
	typ, format   string // JSON Schema type and format
	required      bool
}

var (
	netPath    = param{name: "net", in: "path", doc: "network ID", typ: "integer", format: "int64", required: true}
	reportPath = param{name: "id", in: "path", doc: "report ID: the lowercase hex sha256 of the report file", typ: "string", required: true}
	netQuery   = param{name: "net", in: "query", doc: "only this network", typ: "integer", format: "int64"}
)

var routes = []route{
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-messages", id: "listScenarioMessages", summary: "At most 100 scanned frames from a registered transport input, projected into exact recorded message coordinates; queueing performs full validation.", params: append(runParams(), param{name: "source", in: "query", typ: "string", required: true, doc: "registered source ID"}, param{name: "input", in: "query", typ: "string", required: true, doc: "selected transport input ID"}, param{name: "height", in: "query", typ: "string", doc: "full decimal height"}, param{name: "round", in: "query", typ: "string", doc: "full decimal round"}, param{name: "cursor", in: "query", typ: "string", doc: "opaque cursor scoped to this source and filters"}), answers: map[int]any{200: ScenarioMessagePage{}}, handle: (*Server).scenarioMessages},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/runtime", id: "getRuntimeCapture", summary: "Runtime sidecar provenance and capture completeness, separate from execution model evidence.", params: runParams(), answers: map[int]any{200: RuntimeSummary{}}, handle: (*Server).runtimeSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/runtime/calls", id: "listRuntimeCalls", summary: "At most 100 exact recorded operation intervals; missing calls are not inferred.", params: append(runParams(), param{name: "after", in: "query", typ: "integer", doc: "zero-based immutable call offset"}), answers: map[int]any{200: RuntimeCallPage{}}, handle: (*Server).runtimeCalls},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/runtime/calls/{call}", id: "getRuntimeCall", summary: "Exact original operation start and end lines within one capture identity.", params: append(runParams(), param{name: "call", in: "path", typ: "string", required: true, doc: "full decimal operation ID"}), answers: map[int]any{200: RuntimeCallSource{}}, handle: (*Server).runtimeCall},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-runs/{scenario}/comparison", id: "getScenarioComparison", summary: "Exact recorded and complete-seed ECDFs and elapsed header-time bands from one database snapshot; incomplete groups remain unavailable.", params: scenarioParams(false), answers: map[int]any{200: scenario.ComparisonPlot{}}, handle: (*Server).scenarioComparison},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-sources", id: "listScenarioSources", summary: "Registered network fitting models, coverage and immutable identities; no server paths.", params: runParams(), answers: map[int]any{200: ScenarioSources{}}, handle: (*Server).scenarioSources},
	{method: "POST", path: "/v1/networks/{net}/datasets/{dataset}/scenario-jobs", id: "createScenarioJob", summary: "Queue a bounded baseline and directed network change on a complete registered model.", params: runParams(), body: ScenarioRequest{}, answers: map[int]any{202: store.ScenarioJob{}}, handle: (*Server).postScenarioJob},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-jobs", id: "listScenarioJobs", summary: "Latest 100 durable network experiment jobs and linked runs.", params: runParams(), answers: map[int]any{200: ScenarioJobs{}}, handle: (*Server).scenarioJobs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-jobs/{job}", id: "getScenarioJob", summary: "One scoped network experiment job with explicit interruption and failure status.", params: append(runParams(), param{name: "job", in: "path", doc: "network experiment job ID", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: store.ScenarioJob{}}, handle: (*Server).scenarioJob},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-runs", id: "listScenarioRuns", summary: "Latest 100 network experiment summaries with execution and baseline credibility separated.", params: runParams(), answers: map[int]any{200: ScenarioRuns{}}, handle: (*Server).scenarioRuns},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-runs/{scenario}", id: "getScenarioRun", summary: "Immutable source, fitting, execution and change hashes with baseline checks.", params: scenarioParams(false), answers: map[int]any{200: store.ScenarioRunInfo{}}, handle: (*Server).scenarioSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/scenario-runs/{scenario}/seeds", id: "listScenarioSeeds", summary: "Ordered baseline or counterfactual seed results; interrupted prefixes remain available.", params: scenarioParams(true), answers: map[int]any{200: ScenarioSeedPage{}}, handle: (*Server).scenarioSeeds},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec-sources", id: "listReexecSources", summary: "Configured retained journal IDs and allowed modes; no server paths.", params: runParams(), answers: map[int]any{200: ReexecSources{}}, handle: (*Server).reexecSources},
	{method: "POST", path: "/v1/networks/{net}/datasets/{dataset}/reexec-jobs", id: "createReexecJob", summary: "Queue a retained journal replay through the configured bounded worker.", params: runParams(), body: replayjob.Request{}, answers: map[int]any{202: store.ReexecJob{}}, handle: (*Server).postReexecJob},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec-jobs", id: "listReexecJobs", summary: "Latest 100 durable replay jobs and linked result IDs.", params: runParams(), answers: map[int]any{200: ReexecJobs{}}, handle: (*Server).reexecJobs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec-jobs/{job}", id: "getReexecJob", summary: "One scoped replay job with durable status and linked result.", params: append(runParams(), param{name: "job", in: "path", doc: "replay job ID", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: store.ReexecJob{}}, handle: (*Server).reexecJob},

	{method: "POST", path: "/v1/networks/{net}/datasets/{dataset}/whatif", id: "enqueueWhatif", summary: "Queue a full retained timer experiment on an operator-registered immutable source.", params: runParams(), body: replayjob.WhatifRequest{}, answers: map[int]any{202: store.WhatifJob{}}, handle: (*Server).postWhatifJob},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif-jobs", id: "listWhatifJobs", summary: "Latest 100 durable timer experiment jobs, including explicit interrupted and failed states.", params: runParams(), answers: map[int]any{200: WhatifJobs{}}, handle: (*Server).whatifJobs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif-jobs/{job}", id: "getWhatifJob", summary: "Timer policy and registered-source identity with its independently linked experiment result.", params: append(runParams(), param{name: "job", in: "path", typ: "integer", format: "int64", required: true, doc: "timer experiment job ID"}), answers: map[int]any{200: store.WhatifJob{}}, handle: (*Server).whatifJob},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif", id: "listWhatifRuns", summary: "Latest bounded timer-policy experiments, separate from canonical network facts.", params: runParams(), answers: map[int]any{200: WhatifList{}}, handle: (*Server).whatifList},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif/{whatif}", id: "getWhatifRun", summary: "Exact source, policy and helper identity with explicit counterfactual horizon and failures.", params: whatifParams(false), answers: map[int]any{200: store.WhatifRun{}}, handle: (*Server).whatifSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif/{whatif}/network-bindings", id: "listWhatifNetworkBindings", summary: "Verified original producer and byte-link evidence; repeated copies and missing clocks remain explicit.", params: networkEvidenceParams(), answers: map[int]any{200: WhatifNetworkBindingPage{}}, handle: (*Server).whatifNetworkBindings},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif/{whatif}/network-effects", id: "listWhatifNetworkEffects", summary: "Executed and removed output intents; observed original arrivals never predict new deliveries.", params: networkEvidenceParams(), answers: map[int]any{200: WhatifNetworkEffectPage{}}, handle: (*Server).whatifNetworkEffects},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/whatif/{whatif}/results", id: "listWhatifResults", summary: "Execution-ordered experiment metadata with nullable original evidence; no input bytes or block hashes.", params: whatifParams(true), answers: map[int]any{200: WhatifPage{}}, handle: (*Server).whatifSteps},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec", id: "listReexecRuns", summary: "Latest 100 closed replay observations, separate from visual playback and canonical facts.", params: runParams(), answers: map[int]any{200: ReexecList{}}, handle: (*Server).reexecList},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec/{reexec}", id: "getReexecRun", summary: "Version identity, source completeness and output comparison; no payloads or filesystem paths.", params: reexecParams(false), answers: map[int]any{200: store.ReexecRun{}}, handle: (*Server).reexecSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec/{reexec}/events", id: "getReexecEvents", summary: "Fresh source-bound event evidence for one replay step; at most 1000 explicit events, no inferred engine identity.", params: append(reexecParams(false), param{name: "ordinal", in: "query", doc: "positive original source ordinal", typ: "integer", format: "int64", required: true}, param{name: "event_dataset", in: "query", doc: "completed event dataset on the same network", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: store.ReexecEventEvidence{}}, handle: (*Server).reexecEvents},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/reexec/{reexec}/steps", id: "listReexecSteps", summary: "Immutable source-ordinal pages of output digests and known classifications, at most 1000 rows.", params: reexecParams(true), answers: map[int]any{200: ReexecPage{}}, handle: (*Server).reexecSteps},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/follow", id: "getFollowState", summary: "Durable native follow cursor and latest completed header/observation companions; no event completeness claim.", params: runParams(), answers: map[int]any{200: store.FollowState{}}, handle: (*Server).followState},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/observations/headers/index", id: "getObservationHeaderIndex", summary: "Stored structural metadata bindings and independent canonical totals; source/header changes require explicit reindex.", params: runParams(), answers: map[int]any{200: store.ObservationHeaderIndex{}}, handle: (*Server).observationHeaderIndex},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/observations/headers", id: "listObservationHeaderBindings", summary: "Canonical full-number/hash/parent/validator comparisons with original RPC pointers; no signature or event-completeness claim.", params: observationHeaderParams(), answers: map[int]any{200: ObservationHeaderPage{}}, handle: (*Server).observationHeaderRows},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/observations", id: "getObservationCapture", summary: "Native RPC node metadata, request availability and reported versus recomputed participation summary; never event completeness evidence.", params: runParams(), answers: map[int]any{200: store.ObservationCapture{}}, handle: (*Server).observationCapture},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/observations/participation", id: "listObservedParticipation", summary: "Original full-height participation claims, preserving local/header/gap source and immutable request pointers.", params: observationParams(), answers: map[int]any{200: ObservationPage{}}, handle: (*Server).observationRows},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/observations/calls/{ordinal}", id: "getObservationCall", summary: "One normalized read-only RPC request/result with captured envelope hash; arbitrary properties and error messages are stripped.", params: append(runParams(), param{name: "ordinal", in: "path", doc: "positive original request ordinal", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: observe.Call{}}, handle: (*Server).observationCall},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/missing/index", id: "getMissingIndex", summary: "The stored classification scope and source snapshot; never builds a projection.", params: runParams(), answers: map[int]any{200: store.MissingIndex{}}, handle: (*Server).missingIndex},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/missing", id: "listMissingCells", summary: "Source-backed participation classifications over an explicitly indexed canonical range; stale inputs or headers require reindexing.", params: missingParams(), answers: map[int]any{200: MissingPage{}}, handle: (*Server).missingCells},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/flow", id: "getMessageFlow", summary: "Source-linked message observations overlapping a bounded event execution window; verified companion required, at most 2000 groups.", params: append(pairParams(false), param{name: "events", in: "query", doc: "event run dataset ID for the same verified execution", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: MessageFlow{}}, handle: (*Server).messageFlow},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/issues", id: "listMessageIssues", summary: "Unprojected observations and original source pointers; snapshot and source-filter bound pages.", params: issueParams(), answers: map[int]any{200: MessageIssuePage{}}, handle: (*Server).messageIssues},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/series", id: "getMessageTimeSeries", summary: "Raw-pair UTC series with exact full views and separate evidence dimensions; at most 2000 buckets/views.", params: pairParams(false), answers: map[int]any{200: PairTimeSeries{}}, handle: (*Server).pairSeries},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/source", id: "getMessageSource", summary: "One original metadata record by immutable input, file and ordinal; no payload bytes.", params: append(runParams(), param{name: "input", in: "query", doc: "original input ID", typ: "string", required: true}, param{name: "file", in: "query", doc: "original journal/frame file name", typ: "string", required: true}, param{name: "ordinal", in: "query", doc: "positive full decimal original source ordinal", typ: "string", required: true}), answers: map[int]any{200: sourcemessages.Record{}}, handle: (*Server).messageSource},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/pairs", id: "listMessagePairs", summary: "Directional source-linked message pairs; matching uses the entire dataset before window filtering. Reindex required.", params: pairParams(true), answers: map[int]any{200: PairPage{}}, handle: (*Server).pairSamples},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/summary", id: "summarizeMessagePairs", summary: "Raw-pair distributions separated by direction, matching strength, path and clock; coverage remains explicit.", params: pairParams(false), answers: map[int]any{200: PairSummary{}}, handle: (*Server).pairSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/inputs", id: "listMessageInputs", summary: "Immutable journal/frame file hashes and normalization diagnostics; no payload bytes.", params: runParams(), answers: map[int]any{200: MessageInputList{}}, handle: (*Server).messageInputs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/records", id: "listMessageRecords", summary: "Source-ordered message metadata with snapshot/filter-bound cursor; at most 1000 rows.", params: messageParams(), answers: map[int]any{200: MessagePage{}}, handle: (*Server).messageRecords},
	{method: "GET", path: "/v1/networks/{net}/rounds/baseline", id: "compareRunRoundBaselines", summary: "Independent run observer round rates over a common full-height range; no network pooling.", params: append(headerParams(), param{name: "datasets", in: "query", doc: "2..16 comma-separated completed run dataset IDs", typ: "string", required: true}, param{name: "node", in: "query", doc: "optional observer node", typ: "string"}), answers: map[int]any{200: baseline.Summary{}}, handle: (*Server).roundBaseline},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/replay/window", id: "getReplayWindow", summary: "Metadata visual replay window, at most 100000 events, with preceding state; reindex required if stale.", params: append(append(runParams(), eventParams()[2:4]...), param{name: "node", in: "query", doc: "one node label", typ: "string"}, param{name: "to_input", in: "query", doc: "optional inclusive end source at to_t; requires to_line", typ: "string"}, param{name: "to_line", in: "query", doc: "inclusive original source line at to_t", typ: "integer", format: "int64"}), answers: map[int]any{200: store.ReplayWindow{}}, handle: (*Server).replayWindow},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/replay/keyframe", id: "getReplayKeyframe", summary: "Nearest prior keyframe plus bounded tail folded through t; exact nanosecond axis.", params: append(runParams(), param{name: "node", in: "query", doc: "node label", typ: "string", required: true}, param{name: "t", in: "query", doc: "inclusive RFC3339 target", typ: "string", format: "date-time", required: true}), answers: map[int]any{200: store.ReplayState{}}, handle: (*Server).replayKeyframe},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/phases/summary", id: "summarizePhaseLatency", summary: "WBFT consecutive phase distributions, counts and raw-sample overall percentiles; missing and negative samples remain explicit.", params: phaseParams(false), answers: map[int]any{200: latency.Summary{}}, handle: (*Server).phaseSummary},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/phases/samples", id: "listPhaseSamples", summary: "Source-linked WBFT phase samples and percentile-threshold spikes, with filter-bound cursor pages.", params: phaseParams(true), answers: map[int]any{200: PhasePage{}}, handle: (*Server).phaseSamples},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/evidence", id: "resolveLogEvidence", summary: "Resolve an inspector source pointer only when network, file hash, node and original line match.", params: append(runParams(), param{name: "report", in: "query", doc: "report SHA256 ID", typ: "string", required: true}, param{name: "observation", in: "query", doc: "observation ID", typ: "string", required: true}, param{name: "index", in: "query", doc: "evidence ordinal 0..19", typ: "integer", required: true}), answers: map[int]any{200: store.LogEvidence{}}, handle: (*Server).logEvidence},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}", id: "getLogEvent", summary: "One event by its immutable input ID and source line.", params: append(runParams(), param{name: "input", in: "path", doc: "log input ID", typ: "string", required: true}, param{name: "line", in: "path", doc: "positive source line", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: store.LogEvent{}}, handle: (*Server).logEvent},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}/build", id: "getBuildSource", summary: "Exact application build lifecycle candidates for an immutable source event.", params: append(runParams(), param{name: "input", in: "path", doc: "event input ID", typ: "string", required: true}, param{name: "line", in: "path", doc: "positive source line", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: store.BuildLifecycle{}}, handle: (*Server).buildSource},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/rounds/distribution", id: "getLogRoundDistribution", summary: "Per-node decision claims and round entries with correlated cause evidence, at most 100000 relevant events.", params: append(runParams(), eventParams()[2:4]...), answers: map[int]any{200: rounds.Summary{}}, handle: (*Server).logRounds},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/inputs", id: "listLogInputs", summary: "Immutable log input hashes, byte counts and normalization diagnostics.", params: runParams(), answers: map[int]any{200: LogInputList{}}, handle: (*Server).logInputs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/event-bounds", id: "getEventBounds", summary: "Stored run event bounds and count.", params: runParams(), answers: map[int]any{200: store.EventBounds{}}, handle: (*Server).eventBounds},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/events", id: "listLogEvents", summary: "Cursor-paged metadata-only events; at most 1000 rows in a 24-hour window.", params: eventParams(), answers: map[int]any{200: LogEventPage{}}, handle: (*Server).logEvents},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/input-storage", id: "getDatasetInputStorage", summary: "Retained input ownership and object counts; no paths or owner identities.", params: runParams(), answers: map[int]any{200: store.DatasetInputStorage{}}, handle: (*Server).datasetStorage},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/deletion", id: "getDatasetDeletion", summary: "Durable deletion status, including a completed dataset deletion.", params: runParams(), answers: map[int]any{200: store.DatasetDeletion{}}, handle: (*Server).datasetDeletion},
	{method: "DELETE", path: "/v1/networks/{net}/datasets/{dataset}", id: "deleteDataset", summary: "Delete dataset rows and owned input bytes after exact name confirmation; active or shared sources are refused.", params: runParams(), body: DeleteDatasetRequest{}, answers: map[int]any{200: store.DatasetDeletion{}}, handle: (*Server).deleteDataset},

	{method: "GET", path: "/v1/networks/{net}/datasets", id: "listDatasets", summary: "Datasets and their import status, progress and errors; optionally restricted to one kind before node metadata is computed.", params: []param{netPath, {name: "kind", in: "query", doc: "optional dataset kind: run, range, follow, reports, messages, observations, runtime or governance", typ: "string"}}, answers: map[int]any{200: DatasetList{}}, handle: (*Server).datasets},
	{method: "GET", path: "/v1/networks/{net}/header-bounds", id: "getHeaderBounds", summary: "Stored canonical header bounds and fact bytes.", params: []param{netPath}, answers: map[int]any{200: store.HeaderBounds{}}, handle: (*Server).headerBounds},
	{method: "GET", path: "/v1/networks/{net}/headers", id: "listHeaders", summary: "At most 1024 heights with participation, proposer and optional node copies.", params: append(headerParams(), param{name: "dataset", in: "query", doc: "copy dataset ID; requires node", typ: "integer", format: "int64"}, param{name: "node", in: "query", doc: "copy node label; requires dataset", typ: "string"}), answers: map[int]any{200: HeaderList{}}, handle: (*Server).headers},
	{method: "GET", path: "/v1/networks/{net}/epochs", id: "listEpochs", summary: "At most 1024 epochs in a window of at most one million heights.", params: headerParams(), answers: map[int]any{200: EpochList{}}, handle: (*Server).epochs},
	{method: "GET", path: "/v1/networks/{net}/headers/summary", id: "summarizeHeaders", summary: "Participation denominators, proposer totals and decision round distribution for at most 100000 heights.", params: headerParams(), answers: map[int]any{200: store.HeaderSummary{}}, handle: (*Server).headerSummary},

	{method: "GET", path: "/v1/networks", id: "listNetworks", summary: "The networks with their report counts.",
		answers: map[int]any{200: NetworkList{}}, handle: (*Server).networks},
	{method: "GET", path: "/v1/networks/{net}", id: "getNetwork", summary: "One network.",
		params: []param{netPath}, answers: map[int]any{200: Network{}}, handle: (*Server).network},
	{method: "GET", path: "/v1/networks/{net}/trends/observations", id: "listTrendPoints",
		summary: "The rates of one observation kind in the reports finished in a window, which must be given.",
		params: []param{netPath,
			{name: "kind", in: "query", doc: "observation kind", typ: "string", required: true},
			{name: "node", in: "query", doc: "node; absent for the rate over all nodes", typ: "string"},
			{name: "from_t", in: "query", doc: "window start", typ: "string", format: "date-time", required: true},
			{name: "to_t", in: "query", doc: "window end, included", typ: "string", format: "date-time", required: true}},
		answers: map[int]any{200: TrendPointList{}}, handle: (*Server).trendPoints},
	{method: "GET", path: "/v1/networks/{net}/alert-rules", id: "listAlertRules", summary: "The alert rules of a network.",
		params: []param{netPath}, answers: map[int]any{200: AlertRuleList{}}, handle: (*Server).alertRules},
	{method: "PUT", path: "/v1/networks/{net}/alert-rules", id: "replaceAlertRules",
		summary: "Replace the alert rules of a network; a rule equal to a stored one keeps its ID and state, IDs in the body are ignored.",
		params:  []param{netPath}, body: AlertRuleList{}, answers: map[int]any{200: AlertRuleList{}}, handle: (*Server).putAlertRules},
	{method: "GET", path: "/v1/alerts", id: "listAlerts", summary: "The states of the evaluated alert rules.",
		params: []param{netQuery}, answers: map[int]any{200: AlertList{}}, handle: (*Server).alerts},
	{method: "GET", path: "/v1/reports", id: "listReports", summary: "The stored inspector reports, by finish time.",
		params: []param{netQuery}, answers: map[int]any{200: ReportList{}}, handle: (*Server).reports},
	{method: "POST", path: "/v1/reports", id: "loadReport",
		summary: "Load an inspector report: 201 added, 200 already stored, 422 refused by the public build or not a report.",
		rawBody: "a wbft-inspector-report/1 report file",
		answers: map[int]any{200: LoadResult{}, 201: LoadResult{}, 422: LoadResult{}}, handle: (*Server).postReport},
	{method: "GET", path: "/v1/reports/{id}", id: "getReport", summary: "One report without its results and observations.",
		params: []param{reportPath}, answers: map[int]any{200: Report{}}, handle: (*Server).report},
	{method: "GET", path: "/v1/reports/{id}/results", id: "listResults", summary: "The verdicts of a report.",
		params: []param{reportPath,
			{name: "verdict", in: "query", doc: "only this verdict", typ: "string"},
			{name: "node", in: "query", doc: "only this node; empty for the results of the whole run", typ: "string"}},
		answers: map[int]any{200: ResultList{}}, handle: (*Server).results},
	{method: "GET", path: "/v1/reports/{id}/observations", id: "listObservations", summary: "The observations of a report.",
		params: []param{reportPath}, answers: map[int]any{200: ObservationList{}}, handle: (*Server).observations},
}

func headerParams() []param {
	return []param{netPath, {name: "from", in: "query", doc: "first decimal canonical index (uint64)", typ: "string", required: true}, {name: "to", in: "query", doc: "last decimal canonical index, included", typ: "string", required: true}}
}

func runParams() []param {
	return []param{netPath, {name: "dataset", in: "path", doc: "run dataset ID belonging to the network", typ: "integer", format: "int64", required: true}}
}
func eventParams() []param {
	return append(runParams(),
		param{name: "from_t", in: "query", doc: "inclusive RFC3339 window start", typ: "string", format: "date-time", required: true},
		param{name: "to_t", in: "query", doc: "inclusive RFC3339 window end", typ: "string", format: "date-time", required: true},
		param{name: "node", in: "query", doc: "one node label", typ: "string"},
		param{name: "kind", in: "query", doc: "WBFT event kind", typ: "string"},
		param{name: "phase", in: "query", doc: "WBFT PRE-PREPARE, PREPARE, COMMIT or ROUND-CHANGE", typ: "string"},
		param{name: "height", in: "query", doc: "full decimal height, up to 156 decimal digits", typ: "string"},
		param{name: "round", in: "query", doc: "full decimal round, up to 156 decimal digits", typ: "string"},
		param{name: "limit", in: "query", doc: "page size 1..1000, default 500", typ: "integer"},
		param{name: "cursor", in: "query", doc: "opaque next cursor bound to dataset and filters", typ: "string"})
}

func phaseParams(pages bool) []param {
	out := append(runParams(), eventParams()[2:4]...)
	out = append(out, param{name: "node", in: "query", doc: "node label", typ: "string"}, param{name: "height", in: "query", doc: "full decimal height", typ: "string"}, param{name: "round", in: "query", doc: "full decimal round", typ: "string"}, param{name: "metric", in: "query", doc: "preprepare, prepare_quorum, commit_quorum, commit, import, round_to_decision, round_to_import", typ: "string"})
	if pages {
		out = append(out, param{name: "status", in: "query", doc: "valid, negative, missing_start/end/both/clock or invalid_clock", typ: "string"}, param{name: "clock", in: "query", doc: "wall, monotonic or unavailable", typ: "string"}, param{name: "threshold", in: "query", doc: "p50, p90, p95 or p99; requires metric and clock", typ: "string"}, param{name: "limit", in: "query", doc: "page size 1..1000, default500", typ: "integer"}, param{name: "cursor", in: "query", doc: "next cursor bound to filters", typ: "string"})
	}
	return out
}

func messageParams() []param {
	return append(runParams(), param{name: "input", in: "query", doc: "input ID", typ: "string"}, param{name: "type", in: "query", doc: "segment, conn, frame, outcome, send_suppressed, step or gap", typ: "string"}, param{name: "node", in: "query", doc: "recording node address", typ: "string"}, param{name: "phase", in: "query", doc: "WBFT PRE-PREPARE, PREPARE, COMMIT or ROUND-CHANGE", typ: "string"}, param{name: "height", in: "query", doc: "full decimal height", typ: "string"}, param{name: "round", in: "query", doc: "full decimal round", typ: "string"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "source cursor bound to snapshot and filters", typ: "string"})
}

func pairParams(pages bool) []param {
	out := append(runParams(), param{name: "from_t", in: "query", doc: "optional inclusive RFC3339 start; requires to_t, at most 24h", typ: "string", format: "date-time"}, param{name: "to_t", in: "query", doc: "optional inclusive RFC3339 end; requires from_t", typ: "string", format: "date-time"})
	for _, name := range []string{"sender", "receiver", "node", "phase", "height", "round", "strength", "path", "clock", "status", "metric"} {
		out = append(out, param{name: name, in: "query", doc: "exact message evidence filter", typ: "string"})
	}
	if pages {
		out = append(out, param{name: "threshold", in: "query", doc: "p50/p90/p95/p99; requires one phase, strength, path and clock", typ: "string"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "snapshot and filter bound cursor", typ: "string"})
	}
	return out
}

func issueParams() []param {
	return append(runParams(), param{name: "node", in: "query", doc: "recording source node", typ: "string"}, param{name: "reason", in: "query", doc: "exact projection diagnostic reason", typ: "string"}, param{name: "source_dataset", in: "query", doc: "original source dataset ID", typ: "integer", format: "int64"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "snapshot and source-filter bound cursor", typ: "string"})
}

func reexecParams(steps bool) []param {
	out := append(runParams(), param{name: "reexec", in: "path", doc: "closed replay run ID belonging to this dataset", typ: "integer", format: "int64", required: true})
	if steps {
		out = append(out, param{name: "after", in: "query", doc: "exclusive original source ordinal", typ: "integer", format: "int64"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "class", in: "query", doc: "match, output_diverged, env_mismatch, env_exhausted, input_gap, warmup_suspect or not_comparable", typ: "string"}, param{name: "height", in: "query", doc: "full recorded active height", typ: "string"})
	}
	return out
}

func scenarioParams(page bool) []param {
	params := append(runParams(), param{name: "scenario", in: "path", doc: "network experiment run ID", typ: "integer", format: "int64", required: true})
	if page {
		params = append(params,
			param{name: "mode", in: "query", doc: "baseline (default) or counterfactual", typ: "string"},
			param{name: "after", in: "query", doc: "exclusive saved seed index, 0 through 128", typ: "integer"},
			param{name: "limit", in: "query", doc: "1 through 128, default 32", typ: "integer"})
	}
	return params
}
