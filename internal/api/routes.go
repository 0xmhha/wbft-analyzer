package api

import (
	"github.com/0xmhha/wbft-analyzer/internal/derive/baseline"
	"github.com/0xmhha/wbft-analyzer/internal/derive/latency"
	"github.com/0xmhha/wbft-analyzer/internal/derive/rounds"
	sourcemessages "github.com/0xmhha/wbft-analyzer/internal/source/messages"
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
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/messages/source", id: "getMessageSource", summary: "One original metadata record by immutable input, file and ordinal; no payload bytes.", params: append(runParams(), param{name: "input", in: "query", doc: "original input ID", typ: "string", required: true}, param{name: "file", in: "query", doc: "original journal/frame file name", typ: "string", required: true}, param{name: "ordinal", in: "query", doc: "positive original source ordinal", typ: "integer", format: "int64", required: true}), answers: map[int]any{200: sourcemessages.Record{}}, handle: (*Server).messageSource},
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

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/rounds/distribution", id: "getLogRoundDistribution", summary: "Per-node decision claims and round entries with correlated cause evidence, at most 100000 relevant events.", params: append(runParams(), eventParams()[2:4]...), answers: map[int]any{200: rounds.Summary{}}, handle: (*Server).logRounds},

	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/inputs", id: "listLogInputs", summary: "Immutable log input hashes, byte counts and normalization diagnostics.", params: runParams(), answers: map[int]any{200: LogInputList{}}, handle: (*Server).logInputs},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/event-bounds", id: "getEventBounds", summary: "Stored run event bounds and count.", params: runParams(), answers: map[int]any{200: store.EventBounds{}}, handle: (*Server).eventBounds},
	{method: "GET", path: "/v1/networks/{net}/datasets/{dataset}/events", id: "listLogEvents", summary: "Cursor-paged metadata-only events; at most 1000 rows in a 24-hour window.", params: eventParams(), answers: map[int]any{200: LogEventPage{}}, handle: (*Server).logEvents},

	{method: "GET", path: "/v1/networks/{net}/datasets", id: "listDatasets", summary: "Datasets and their import status, progress and errors.", params: []param{netPath}, answers: map[int]any{200: DatasetList{}}, handle: (*Server).datasets},
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
	for _, name := range []string{"sender", "receiver", "node", "phase", "height", "round", "strength", "path", "clock", "status"} {
		out = append(out, param{name: name, in: "query", doc: "exact message evidence filter", typ: "string"})
	}
	if pages {
		out = append(out, param{name: "threshold", in: "query", doc: "p50/p90/p95/p99; requires one phase, strength, path and clock", typ: "string"}, param{name: "limit", in: "query", doc: "page size 1..1000", typ: "integer"}, param{name: "cursor", in: "query", doc: "snapshot and filter bound cursor", typ: "string"})
	}
	return out
}
