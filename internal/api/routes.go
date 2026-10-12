package api

import (
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
