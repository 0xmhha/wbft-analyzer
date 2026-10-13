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
# Needs go, python3, curl, jq and pg_dump/pg_restore of the server's major version or
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
	local base=http://127.0.0.1:$1/v1 dir=$2 header_net run_net run_id log_report baseline_net baseline_ids message_net message_id missing_id
	mkdir -p "$dir"
	get() { curl -sf "$base$1" | jq -S . >"$dir/$2.json"; }
	get /networks networks
	header_net=$(jq -r --arg genesis "$(jq -r .hash "$root/internal/source/headers/testdata/0.json")" '.networks[] | select(.chain_id == "8283" and .genesis_hash == $genesis) | .id' "$dir/networks.json")
	test -n "$header_net"
	get "/networks/$header_net/datasets" header-datasets
	get "/networks/$header_net/header-bounds" header-bounds
	get "/networks/$header_net/headers?from=0&to=3&dataset=1&node=fixture" header-rows
	get "/networks/$header_net/headers/summary?from=0&to=3" header-summary
	get "/networks/$header_net/epochs?from=0&to=3" header-epochs
 missing_id=$(jq -r '.datasets[] | select(.kind=="run" and .name=="synthetic-vote-evidence") | .id' "$dir/header-datasets.json")
 get "/networks/$header_net/datasets/$missing_id/missing/index" missing-index
 get "/networks/$header_net/datasets/$missing_id/missing?from=1&to=2&phase=PREPARE&limit=1000" missing-cells
	run_net=$(jq -r '.networks[] | select(.genesis_hash == "0xe4dbf0369f658041a30759c9341973c7239e0467fdeecd1c21790e15c32c086f") | .id' "$dir/networks.json")
 get "/networks/$run_net/datasets" run-datasets
 run_id=$(jq -r '.datasets[] | select(.kind=="run" and .name=="g7-excerpt") | .id' "$dir/run-datasets.json")
 get "/networks/$run_net/datasets/$run_id/inputs" run-inputs
 get "/networks/$run_net/datasets/$run_id/event-bounds" run-bounds
 get "/networks/$run_net/datasets/$run_id/events?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z&limit=1000" run-events
 get "/networks/$run_net/datasets/$run_id/rounds/distribution?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z" run-rounds
 get "/networks/$run_net/datasets/$run_id/phases/summary?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z" run-phase-summary
 get "/networks/$run_net/datasets/$run_id/phases/samples?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z&metric=round_to_decision&limit=1000" run-phase-samples
 get "/networks/$run_net/datasets/$run_id/phases/samples?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z&metric=round_to_decision&clock=wall&threshold=p95" run-phase-threshold
 get "/networks/$run_net/datasets/$run_id/replay/window?from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:30Z" run-replay-window
 get "/networks/$run_net/datasets/$run_id/replay/keyframe?node=node2&t=2026-10-12T17:23:01Z" run-replay-state
 baseline_net=$(jq -r '.networks[]|select(.chain_id=="7" and .name=="synthetic-baseline")|.id' "$dir/networks.json")
 get "/networks/$baseline_net/datasets" baseline-datasets
 baseline_ids=$(jq -r '.datasets[].id' "$dir/baseline-datasets.json" | paste -sd, -)
 get "/networks/$baseline_net/rounds/baseline?datasets=$baseline_ids&from=31&to=32&node=n1" run-baseline
 message_net=$(jq -r '.networks[]|select(.name=="synthetic-messages")|.id' "$dir/networks.json")
 get "/networks/$message_net/datasets" message-datasets
 message_id=$(jq -r '.datasets[0].id' "$dir/message-datasets.json")
 get "/networks/$message_net/datasets/$message_id/messages/inputs" message-inputs
 get "/networks/$message_net/datasets/$message_id/messages/records?limit=1000" message-records
 get "/networks/$message_net/datasets/$message_id/messages/records?phase=PREPARE" message-prepare
 get "/networks/$message_net/datasets/$message_id/messages/summary" message-summary
 get "/networks/$message_net/datasets/$message_id/messages/series" message-series
 get "/networks/$message_net/datasets/$message_id/messages/issues?limit=1000" message-issues
 get "/networks/$message_net/datasets/$message_id/messages/pairs?limit=1000" message-pairs
 get "/networks/$message_net/datasets/$message_id/messages/source?input=frames&file=frames-synthetic.jsonl&ordinal=1" message-source
 get "/networks/$run_net/datasets/$run_id/messages/summary" run-message-summary
 get "/networks/$run_net/datasets/$run_id/messages/series?metric=propagation_processing" run-message-series
 get "/networks/$run_net/datasets/$run_id/messages/issues?limit=1000" run-message-issues
 get "/networks/$run_net/datasets/$run_id/messages/flow?events=$run_id&from_t=2026-10-12T17:22:56Z&to_t=2026-10-12T17:23:10Z" run-message-flow
 get "/networks/$run_net/datasets/$run_id/messages/pairs?limit=1000" run-message-pairs
 get /reports reports
 log_report=$(jq -r '.reports[] | select(.run_id=="log-evidence-dump") | .id' "$dir/reports.json")
 get "/networks/$run_net/datasets/$run_id/evidence?report=$log_report&observation=log-source&index=0" log-evidence
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
"$bin" ingest range --db "$src" --blocks "$root/internal/source/headers/testdata" --config "$root/internal/source/headers/testdata/config.json" --from 0 --to 3 --name dump-headers --node fixture >"$out/headers.log"
# Hand-authored native events share only the existing synthetic header network.
python3 - "$root" "$work" <<'PYMISSING'
import hashlib,json,sys
from pathlib import Path
root,work=map(Path,sys.argv[1:])
config=json.loads((root/'internal/source/headers/testdata/config.json').read_text())
node=config['anzeon']['init']['validators'][0]
common=dict(v=1,node=node,run='synthetic-votes',t_wall='2020-01-01T00:00:00Z')
rows=[dict(kind='NODE_START',impl='wbft',mode='standalone',validator=True,sign_floor=None,wal_recovery=dict(records=0,torn_bytes=0,corrupted=0)),
      dict(kind='ROUND_ENTER',view=dict(seq='1',round='0'),step=1,branch='INITIAL',cause='start',is_proposer=False,proposer=node,requested_round='0',valset_digest='0x'+'0'*64),
      dict(kind='ROUND_ENTER',view=dict(seq='2',round='0'),step=2,branch='INITIAL',cause='new_head',is_proposer=False,proposer=node,requested_round='0',valset_digest='0x'+'0'*64),
      dict(kind='NODE_STOP',reason='operator')]
raw=''.join(json.dumps(dict(common,seq=i,t_mono_ns=i,**r))+'\n' for i,r in enumerate(rows)).encode()
(work/'synthetic-votes.jsonl').write_bytes(raw)
genesis=json.loads((root/'internal/source/headers/testdata/0.json').read_text())['hash']
manifest=dict(format='wbft-analyzer-run/1',name='synthetic-vote-evidence',run='synthetic-votes',network=dict(chain_id='8283',genesis_hash=genesis,name='synthetic-headers'),clock='shared-host',inputs=[dict(id='votes',node=node,kind='events',path='synthetic-votes.jsonl',sha256=hashlib.sha256(raw).hexdigest())])
(work/'synthetic-votes.json').write_text(json.dumps(manifest)+'\n')
PYMISSING
"$bin" ingest run --db "$src" --manifest "$work/synthetic-votes.json" >"$out/missing-run.log"
missing_dataset_id=$(sed -n 's/^dataset=\([0-9][0-9]*\).*/\1/p' "$out/missing-run.log")
"$bin" reindex missing --db "$src" --dataset "$missing_dataset_id" --from 1 --to 2 >"$out/missing-index.log"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/g7/manifest.json" >"$out/run.log"
run_dataset_id=$(sed -n 's/^dataset=\([0-9][0-9]*\).*/\1/p' "$out/run.log")
"$bin" reindex messages --db "$src" --dataset "$run_dataset_id" >"$out/run-pair-index.log"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/baseline/manifest-1.json" >"$out/baseline-1.log"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/baseline/manifest-2.json" >"$out/baseline-2.log"
"$bin" ingest messages --db "$src" --manifest "$root/internal/source/messages/testdata/manifest.json" >"$out/messages.log"
message_dataset_id=$(jq -r .dataset_id "$out/messages.log")
"$bin" reindex messages --db "$src" --dataset "$message_dataset_id" >"$out/message-pair-index.log"
# A synthetic report points into the real sanitized G7 fixture. Its input
# namespace differs from the dataset, so resolution must use SHA/node.
python3 - "$root" "$work/log-report.json" <<'PYLOG'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);base=json.loads((root/'internal/reports/testdata/report.json').read_text());m=json.loads((root/'internal/source/logs/testdata/g7/manifest.json').read_text())
inp=next(i for i in m['inputs'] if i['node']=='node3')
rows=(root/'internal/source/logs/testdata/g7'/inp['path']).read_text().splitlines()
line=next(n for n,s in enumerate(rows,1) if (d:=json.loads(s))['msg']=='WBFT: start new round' and str(d['next.seq'])=='5542' and str(d['next.round'])=='1')
base['run']['id']='log-evidence-dump';base['run']['network']=m['network'];base['run']['inputs']=[dict(id='report-log-3',kind='log',node='node3',sha256=inp['sha256'],profile=inp['profile'])]
base['observations']=[dict(id='log-source',kind='round_change_f_plus_one',count=1,imp=[],checker='fixture',evidence=[dict(kind='log',input='report-log-3',node='node3',line=line,number='5542')])]
Path(sys.argv[2]).write_text(json.dumps(base)+'\n')
PYLOG
"$bin" ingest reports --db "$src" "$work/log-report.json" >"$out/log-report.log"
capture 18091 "$out/source"
stop

reports=$(jq '.reports | length' "$out/source/reports.json")
states=$(jq -r '[.alerts[].state] | join(",")' "$out/source/alerts.json")
if [ "$reports" != "$(( ${#counts[@]} + 1 ))" ] || [ "$states" != "resolved,firing" ]; then
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
