#!/usr/bin/env bash
# dump-check.sh loads a set of reports into an analyzer database, saves the
# database with pg_dump, restores the dump into another (empty) database and
# checks that the API answers the same from both (roadmap A0).
#
# Usage: scripts/dump-check.sh SOURCE_DSN TARGET_DSN OUT_DIR
#
#   SOURCE_DSN  an empty database to load (postgres://...)
#   TARGET_DSN  another empty database, ideally on another server, to restore into
#   OUT_DIR     receives analyzer.dump and the answers (source/, target/)
#
# Needs go, curl, jq and pg_dump/pg_restore of the server's major version or
# newer. Ports 18091 and 18092 on 127.0.0.1 must be free.
set -euo pipefail

if [ $# -ne 3 ]; then
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	exit 64
fi
src=$1 dst=$2 out=$3
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
work=$(mktemp -d)
pid=""
cleanup() {
	if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT

bin=$work/wbft-analyzer
(cd "$root" && go build -o "$bin" ./cmd/wbft-analyzer)

# report I COUNT writes report I of one network: blocks 100*I+1 .. 100*I+100,
# COUNT observations of kind late_seal.
report() {
	jq --argjson i "$1" --argjson n "$2" '
		.run.id = "run-\($i)"
		| .run.finished_at = "2026-10-12T00:\(if $i < 10 then "0" else "" end)\($i):00Z"
		| .run.network = {name: "testnet", chain_id: 8282, genesis_hash: ("0x" + "0" * 63 + "1")}
		| .run.range = {from: (100 * $i + 1), to: (100 * $i + 100)}
		| .observations = [{id: "o1", kind: "late_seal", imp: [], checker: "c", count: $n, evidence: [],
			requirements: ["WBFT-SM-083"]}]' "$root/internal/reports/testdata/report.json" >"$work/r$1.json"
}

# serve DSN PORT starts the server and waits until it answers.
serve() {
	"$bin" serve --db "$1" --listen "127.0.0.1:$2" 2>>"$out/serve.log" &
	pid=$!
	for _ in $(seq 50); do
		if curl -sf -o /dev/null "http://127.0.0.1:$2/v1/networks"; then return 0; fi
		sleep 0.2
	done
	echo "dump-check: the server on port $2 did not start" >&2
	exit 1
}

stop() {
	kill -INT "$pid"
	wait "$pid"
	pid=""
}

# capture PORT DIR writes the answers of the read endpoints to DIR.
capture() {
	local base=http://127.0.0.1:$1/v1 dir=$2
	mkdir -p "$dir"
	get() { curl -sf "$base$1" | jq -S . >"$dir/$2.json"; }
	get /networks networks
	get /networks/1 network-1
	get /reports reports
	get /networks/1/alert-rules alert-rules
	get /alerts alerts
	get "/networks/1/trends/observations?kind=late_seal&from_t=2026-10-12T00:00:00Z&to_t=2026-10-12T23:59:59Z" trends
	for id in $(jq -r '.reports[].id' "$dir/reports.json"); do
		get "/reports/$id" "report-$id"
		get "/reports/$id/results" "results-$id"
		get "/reports/$id/observations" "observations-$id"
	done
}

# Load: the first report from the command line creates the network; the
# rules are set over the API; the other reports are posted, so that the
# alert states move (a relative rule fires and resolves, an absolute rule
# stays firing).
counts=(2 2 3 2 2 3 5 8 9 10 2 2 2)
for i in "${!counts[@]}"; do report "$i" "${counts[$i]}"; done
"$bin" ingest reports --db "$src" "$work/r0.json" >"$out/ingest.log"
serve "$src" 18091
curl -sf -X PUT -H 'Content-Type: application/json' http://127.0.0.1:18091/v1/networks/1/alert-rules -d '{"rules": [
	{"kind": "late_seal", "window": 3, "baseline": 5, "mode": "relative", "threshold": 2},
	{"kind": "late_seal", "window": 3, "mode": "absolute", "threshold": 0.01}]}' >/dev/null
for i in $(seq 1 $((${#counts[@]} - 1))); do
	curl -sf -X POST -H 'Content-Type: application/json' --data-binary "@$work/r$i.json" http://127.0.0.1:18091/v1/reports >/dev/null
done
capture 18091 "$out/source"
stop

reports=$(jq '.reports | length' "$out/source/reports.json")
states=$(jq -r '[.alerts[].state] | join(",")' "$out/source/alerts.json")
if [ "$reports" != "${#counts[@]}" ] || [ "$states" != "resolved,firing" ]; then
	echo "dump-check: the source holds $reports reports and alerts [$states], want ${#counts[@]} and [resolved,firing]" >&2
	exit 1
fi

pg_dump --format=custom --no-owner --dbname="$src" --file="$out/analyzer.dump"
pg_restore --no-owner --exit-on-error --dbname="$dst" "$out/analyzer.dump"

serve "$dst" 18092
capture 18092 "$out/target"
stop

if ! diff -r "$out/source" "$out/target"; then
	echo "dump-check: the restored database answers differently" >&2
	exit 1
fi
echo "dump-check: $reports reports, alerts [$states]; the restored database answers the same ($(find "$out/source" -name '*.json' | wc -l | tr -d ' ') endpoints)"
