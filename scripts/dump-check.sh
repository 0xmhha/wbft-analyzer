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
	local base=http://127.0.0.1:$1/v1 dir=$2 header_net header_dataset run_net run_id log_report baseline_net baseline_ids message_net message_id missing_id observation_net observation_id timer_net timer_dataset timer_run
	mkdir -p "$dir"
	get() { curl -sf "$base$1" | jq -S . >"$dir/$2.json"; }
	get /networks networks
 local reconstruction_net reconstruction_dataset reconstruction_run
 reconstruction_net=$(jq -er '.networks[]|select(.name=="synthetic-reconstruction")|.id' "$dir/networks.json")
 get "/networks/$reconstruction_net/datasets" reconstruction-datasets
 reconstruction_dataset=$(jq -er '.datasets[]|select(.name=="synthetic-reconstruction")|.id' "$dir/reconstruction-datasets.json")
 get "/networks/$reconstruction_net/datasets/$reconstruction_dataset/reconstruction" reconstruction-runs
 jq -e '(.runs|length)==1 and .runs[0].heights==2 and .runs[0].complete_heights==0 and .runs[0].steps==0' "$dir/reconstruction-runs.json" >/dev/null
 reconstruction_run=$(jq -er '.runs[0].id' "$dir/reconstruction-runs.json")
 get "/networks/$reconstruction_net/datasets/$reconstruction_dataset/reconstruction/$reconstruction_run" reconstruction-summary
 jq -e '.summary.core_executed==false and (.summary.heights|length)==2 and all(.summary.heights[];.status=="not_possible")' "$dir/reconstruction-summary.json" >/dev/null
 get "/networks/$reconstruction_net/datasets/$reconstruction_dataset/reconstruction/$reconstruction_run/steps" reconstruction-steps
 jq -e '.steps==[] and .next==null' "$dir/reconstruction-steps.json" >/dev/null
 local scheduler_net scheduler_dataset
 scheduler_net=$(jq -er '.networks[]|select(.name=="synthetic-scheduler-source")|.id' "$dir/networks.json")
 get "/networks/$scheduler_net/datasets" scheduler-datasets
 scheduler_dataset=$(jq -er '.datasets[]|select(.name=="synthetic-scheduler-source")|.id' "$dir/scheduler-datasets.json")
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/records?type=scheduler_trace" scheduler-declarations
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/records?type=timer_operation" scheduler-operations
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/records?type=scheduler_step" scheduler-steps
 jq -e '(.records|length)==1 and .records[0].scheduler_trace.operations=="8" and .records[0].scheduler_trace.steps=="4" and .records[0].clock_source=="unavailable" and (.records[0]|has("t_wall")|not) and (.records[0]|has("t_mono_ns")|not)' "$dir/scheduler-declarations.json" >/dev/null
 jq -e '(.records|length)==8' "$dir/scheduler-operations.json" >/dev/null
 jq -e '(.records|length)==4' "$dir/scheduler-steps.json" >/dev/null
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/source?input=scheduler&file=frames-scheduler-fixture.jsonl&ordinal=1" scheduler-declaration-source
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/source?input=scheduler&file=frames-scheduler-fixture.jsonl&ordinal=6" scheduler-queue-source
 get "/networks/$scheduler_net/datasets/$scheduler_dataset/messages/source?input=scheduler&file=frames-scheduler-fixture.jsonl&ordinal=9" scheduler-step-source
 jq -e '.seq=="1" and .journal_position.offset=="0" and .clock_source=="unavailable"' "$dir/scheduler-declaration-source.json" >/dev/null
 jq -e '.seq=="6" and .timer_operation.sequence=="4" and .timer_operation.action=="queued" and .timer_operation.generation=="3"' "$dir/scheduler-queue-source.json" >/dev/null
 jq -e '.seq=="9" and .entry_t_mono_ns=="3000000000" and .entry_t_wall=="2026-01-01T00:00:03Z"' "$dir/scheduler-step-source.json" >/dev/null
 local cache_net cache_dataset
 cache_net=$(jq -er '.networks[]|select(.name=="synthetic-cache-source")|.id' "$dir/networks.json")
 get "/networks/$cache_net/datasets" cache-datasets
 cache_dataset=$(jq -er '.datasets[]|select(.name=="synthetic-cache-source")|.id' "$dir/cache-datasets.json")
 get "/networks/$cache_net/datasets/$cache_dataset/messages/records?type=cache_operation" cache-operations
 get "/networks/$cache_net/datasets/$cache_dataset/messages/records?type=cache_instance" cache-instances
 get "/networks/$cache_net/datasets/$cache_dataset/messages/source?input=cache&file=frames-cache-fixture.jsonl&ordinal=1" cache-declaration-source
 get "/networks/$cache_net/datasets/$cache_dataset/messages/source?input=cache&file=frames-cache-fixture.jsonl&ordinal=4" cache-operation-source
 get "/networks/$cache_net/datasets/$cache_dataset/messages/source?input=cache&file=frames-cache-fixture.jsonl&ordinal=6" cache-suppression-source
 get "/networks/$cache_net/datasets/$cache_dataset/messages/source?input=cache&file=frames-cache-fixture.jsonl&ordinal=7" cache-write-source
 jq -e '(.records|length)==2 and .records[0].cache_operation.sequence=="1" and .records[1].cache_operation.sequence=="2"' "$dir/cache-operations.json" >/dev/null
 jq -e '(.records|length)==1 and .records[0].cache_instance.initial_state=="empty" and .records[0].clock_source=="unavailable"' "$dir/cache-instances.json" >/dev/null
 jq -e '.cache_trace.complete==true and .cache_trace.operations=="2" and .scheduler_trace.operations=="0" and (.t_wall==null) and (.t_mono_ns==null)' "$dir/cache-declaration-source.json" >/dev/null
 jq -e '.seq=="4" and .cache_operation.sequence=="1" and .journal_position.offset=="342"' "$dir/cache-operation-source.json" >/dev/null
 jq -e '.cache_evidence.operation.ordinal==5 and .cache_decision.operation=="2" and .clock_source=="unavailable" and (.t_wall==null) and (.t_mono_ns==null)' "$dir/cache-suppression-source.json" >/dev/null
 jq -e '.seq=="7" and .send_attempt.sequence=="9" and .send_attempt.cache_decision.operation=="1" and .cache_evidence.operation.ordinal==4 and .cache_evidence.operation.seq=="4" and .write=="ok"' "$dir/cache-write-source.json" >/dev/null
 # Preserve complete and incomplete sync sources through independent restore.
 local sync_net sync_dataset sync_mode sync_kind sync_name sync_file
 for sync_mode in combined incomplete; do
  for sync_kind in frames journal; do
   sync_name="synthetic-sync-$sync_mode-$sync_kind"
   sync_net=$(jq -er '.networks[]|select(.name=="synthetic-sync-source")|.id' "$dir/networks.json")
   get "/networks/$sync_net/datasets" "$sync_name-datasets"
   sync_dataset=$(jq -er --arg name "$sync_name" '.datasets[]|select(.name==$name)|.id' "$dir/$sync_name-datasets.json")
   get "/networks/$sync_net/datasets/$sync_dataset/messages/records?type=sync_control" "$sync_name-controls"
   if [ "$sync_kind" = frames ]; then
    sync_file="frames-sync-control-$sync_mode.jsonl"
   else
    sync_file=00000000000000000000.wal
   fi
   get "/networks/$sync_net/datasets/$sync_dataset/messages/source?input=sync&file=$sync_file&ordinal=1" "$sync_name-declaration"
   get "/networks/$sync_net/datasets/$sync_dataset/messages/source?input=sync&file=$sync_file&ordinal=2" "$sync_name-processed"
   jq -e '.seq=="1" and .sync_trace.event_cursor=="next_sequence" and .clock_source=="unavailable" and (.t_wall==null) and (.t_mono_ns==null)' "$dir/$sync_name-declaration.json" >/dev/null
   jq -e '.seq=="2" and .sync_control.stage=="processed" and .sync_control.syncing==true and .sync_control.success==false and .sync_control.event_before=="9" and .sync_control.event_after=="11"' "$dir/$sync_name-processed.json" >/dev/null
   if [ "$sync_mode" = combined ]; then
    jq -e '(.records|length)==5 and all(.records[]; .sync_evidence.complete==true)' "$dir/$sync_name-controls.json" >/dev/null
    jq -e '.sync_trace.complete==true and .sync_trace.requests=="2" and .sync_trace.operations=="3"' "$dir/$sync_name-declaration.json" >/dev/null
    jq -e '.sync_control.request_source.source_seq=="3" and .sync_control.request_source.source_offset=="219" and .sync_evidence.request.ordinal==3 and .sync_evidence.request.seq=="3"' "$dir/$sync_name-processed.json" >/dev/null
    get "/networks/$sync_net/datasets/$sync_dataset/messages/source?input=sync&file=$sync_file&ordinal=3" "$sync_name-request"
    jq -e '.seq=="3" and .sync_control.stage=="requested" and .sync_control.request=="1" and .sync_control.operation=="0" and .sync_control.syncing==true and .sync_control.success==false and .journal_position.offset=="219"' "$dir/$sync_name-request.json" >/dev/null
   else
    jq -e '(.records|length)==1 and .records[0].sync_evidence.complete==false and (.records[0].sync_evidence.request==null)' "$dir/$sync_name-controls.json" >/dev/null
    jq -e '.sync_trace.complete==false and .sync_trace.requests=="0"' "$dir/$sync_name-declaration.json" >/dev/null
    jq -e '.sync_control.request_source.source_available==false and (.sync_evidence.request==null)' "$dir/$sync_name-processed.json" >/dev/null
   fi
  done
 done
 # Original typed headers/footers retain absent source sequences after restore.
 local typed_net typed_dataset typed_mode typed_name
 typed_net=$(jq -er '.networks[]|select(.name=="synthetic-typed-sync")|.id' "$dir/networks.json")
 for typed_mode in complete incomplete; do
  typed_name="synthetic-typed-sync-$typed_mode"
  get "/networks/$typed_net/datasets" "$typed_name-datasets"
  typed_dataset=$(jq -er --arg name "$typed_name" '.datasets[]|select(.name==$name)|.id' "$dir/$typed_name-datasets.json")
  get "/networks/$typed_net/datasets/$typed_dataset/messages/inputs" "$typed_name-inputs"
  get "/networks/$typed_net/datasets/$typed_dataset/messages/records?type=sync_notification" "$typed_name-notifications"
  get "/networks/$typed_net/datasets/$typed_dataset/messages/records?type=sync_notification_source" "$typed_name-sources"
  get "/networks/$typed_net/datasets/$typed_dataset/messages/source?input=typed&file=notifications.jsonl&ordinal=1" "$typed_name-header"
  jq -e '.seq=="" and .sync_notification_source.header.core_start_seq=="0" and (.t_wall==null) and (.t_mono_ns==null)' "$dir/$typed_name-header.json" >/dev/null
  jq -e '(.records|length)==6 and .records[3].seq=="4" and .records[3].sync_notification.number=="9007199254740993" and .records[1].clock_source=="unavailable" and (.records[1].t_wall==null)' "$dir/$typed_name-notifications.json" >/dev/null
  if [ "$typed_mode" = complete ]; then
   get "/networks/$typed_net/datasets/$typed_dataset/messages/source?input=typed&file=notifications.jsonl&ordinal=8" "$typed_name-footer"
   jq -e '.seq=="" and .sync_notification_source.footer.complete==true and .sync_notification_evidence.retained_complete==true' "$dir/$typed_name-footer.json" >/dev/null
   jq -e '(.records|length)==2 and all(.records[]; .seq=="")' "$dir/$typed_name-sources.json" >/dev/null
  else
   jq -e '(.records|length)==1 and .records[0].sync_notification_evidence.retained_complete==false and (.records[0].sync_notification_evidence.footer==null)' "$dir/$typed_name-sources.json" >/dev/null
  fi
 done
 local own_net own_dataset
 own_net=$(jq -r '.networks[]|select(.name=="synthetic-own-input")|.id' "$dir/networks.json")
 get "/networks/$own_net/datasets" own-input-datasets
 own_dataset=$(jq -er '.datasets[]|select(.name=="synthetic-own-input")|.id' "$dir/own-input-datasets.json")
 get "/networks/$own_net/datasets/$own_dataset/messages/records?limit=1000" own-input-records
 jq -e '[.records[]|select(.own_input_evidence!=null)]|length==3' "$dir/own-input-records.json" >/dev/null
 get "/networks/$own_net/datasets/$own_dataset/messages/source?input=native&file=frames-own-fixture.jsonl&ordinal=3" own-input-outcome-source
 get "/networks/$own_net/datasets/$own_dataset/messages/source?input=native&file=frames-own-fixture.jsonl&ordinal=4" own-input-internal-source
 jq -e '.seq=="4" and .input_of=="5" and .own_input_evidence.input.ordinal==4' "$dir/own-input-outcome-source.json" >/dev/null
 jq -e '.seq=="5" and .type=="own_input" and .own_input_evidence.outcome.ordinal==3 and .journal_position.offset=="469"' "$dir/own-input-internal-source.json" >/dev/null
 local runtime_net runtime_dataset
 runtime_net=$(jq -r '.networks[]|select(.chain_id=="10")|.id' "$dir/networks.json")
 get "/networks/$runtime_net/datasets" runtime-datasets
 runtime_dataset=$(jq -r '.datasets[]|select(.kind=="runtime")|.id' "$dir/runtime-datasets.json")
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime" runtime-summary
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime/calls" runtime-calls
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime/calls/18446744073709551615" runtime-call-source
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime/calls/42" runtime-core-start-source
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime/calls/43" runtime-core-stop-source
 get "/networks/$runtime_net/datasets/$runtime_dataset/runtime/calls/44" runtime-restarted-core-source
 local build_net build_dataset
 build_net=$(jq -r '.networks[]|select(.name=="synthetic-build")|.id' "$dir/networks.json")
 get "/networks/$build_net/datasets" build-datasets
 build_dataset=$(jq -r '.datasets[]|select(.name=="synthetic-build-lifecycle")|.id' "$dir/build-datasets.json")
 get "/networks/$build_net/datasets/$build_dataset/events/build/1/build" build-handover-source
 get "/networks/$build_net/datasets/$build_dataset/events/build/2/build" build-start-source
 get "/networks/$build_net/datasets/$build_dataset/events/build/3/build" build-finish-source

 local sealing_net sealing_dataset
 sealing_net=$(jq -r '.networks[]|select(.name=="synthetic-sealing")|.id' "$dir/networks.json")
 get "/networks/$sealing_net/datasets" sealing-datasets
 sealing_dataset=$(jq -r '.datasets[]|select(.name=="synthetic-sealing-policy")|.id' "$dir/sealing-datasets.json")
 get "/networks/$sealing_net/datasets/$sealing_dataset/inputs" sealing-inputs
 get "/networks/$sealing_net/datasets/$sealing_dataset/events?from_t=2026-01-01T00:00:00Z&to_t=2026-01-01T00:00:01Z&limit=1000" sealing-events
 jq -e '.. | objects | select(has("application_call_return_delay_ns")) | .application_call_return_delay_ns == ["0","9007199254740993","0"]' "$dir/sealing-events.json" >/dev/null
 jq -e '.. | objects | select(has("work_id")) | .work_id == "work-18446744073709551615" and .request_height == "18446744073709551617" and .request_round == "18446744073709551616"' "$dir/sealing-events.json" >/dev/null

 observation_net=$(jq -r '.networks[]|select(.chain_id=="8" and .genesis_hash=="0x1111111111111111111111111111111111111111111111111111111111111111")|.id' "$dir/networks.json")
 get "/networks/$observation_net/datasets" observation-datasets
 get "/networks/$observation_net/datasets?kind=observations" observation-only-datasets
 get "/networks/$observation_net/datasets?kind=follow" observation-no-follow-datasets
 jq -e --slurpfile all "$dir/observation-datasets.json" '.datasets == [$all[0].datasets[] | select(.kind=="observations")]' "$dir/observation-only-datasets.json" >/dev/null
 jq -e '.datasets==[]' "$dir/observation-no-follow-datasets.json" >/dev/null
 observation_id=$(jq -r '.datasets[]|select(.kind=="observations")|.id' "$dir/observation-datasets.json")
 get "/networks/$observation_net/datasets/$observation_id/observations" observation-capture
 get "/networks/$observation_net/datasets/$observation_id/observations/participation?from=1&to=2&limit=1000" observation-participation
 get "/networks/$observation_net/datasets/$observation_id/observations/calls/5" observation-copy-source
 get "/networks/$observation_net/datasets/$observation_id/observations/calls/6" observation-round-change-source
 jq -e '.round_changes.status=="match" and .round_changes.computed_count==0 and .round_changes.reported_count==0 and .round_changes.different_rows==0' "$dir/observation-capture.json" >/dev/null
 jq -e '.method=="wbft_roundChanges" and .status=="available" and .params==["1","2"] and .data==[]' "$dir/observation-round-change-source.json" >/dev/null
 get "/networks/$observation_net/datasets/$observation_id/observations/headers/index" observation-binding-index
 get "/networks/$observation_net/datasets/$observation_id/observations/headers?from=1&to=2&limit=1000" observation-bindings
	header_net=$(jq -r --arg genesis "$(jq -r .hash "$root/internal/source/headers/testdata/0.json")" '.networks[] | select(.chain_id == "8283" and .genesis_hash == $genesis) | .id' "$dir/networks.json")
	test -n "$header_net"
	get "/networks/$header_net/datasets" header-datasets
	get "/networks/$header_net/header-bounds" header-bounds
	header_dataset=$(jq -er '[.datasets[] | select(.kind=="range" and .name=="dump-headers")] | if length==1 then .[0].id else error("expected one dump-headers dataset") end' "$dir/header-datasets.json")
	get "/networks/$header_net/headers?from=0&to=3&dataset=$header_dataset&node=fixture" header-rows
	get "/networks/$header_net/headers/summary?from=0&to=3" header-summary
	get "/networks/$header_net/epochs?from=0&to=3" header-epochs
 missing_id=$(jq -r '.datasets[] | select(.kind=="run" and .name=="synthetic-vote-evidence") | .id' "$dir/header-datasets.json")
 get "/networks/$header_net/datasets/$missing_id/events?from_t=2020-01-01T00:00:00Z&to_t=2020-01-01T00:00:01Z&limit=1000" application-policy-events
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
 baseline_ids=$(jq -r '.datasets[] | select(.kind=="run") | .id' "$dir/baseline-datasets.json" | paste -sd, -)
 get "/networks/$baseline_net/rounds/baseline?datasets=$baseline_ids&from=31&to=32&node=n1" run-baseline
 get "/networks/$baseline_net/phases/comparison?datasets=$baseline_ids&from=31&to=32&metric=round_to_decision&node=n1" run-phase-comparison
 message_net=$(jq -r '.networks[]|select(.name=="synthetic-messages")|.id' "$dir/networks.json")
 get "/networks/$message_net/datasets" message-datasets
 message_id=$(jq -r '[.datasets[] | select(.kind=="messages" and .name=="synthetic-messages")] | if length==1 then .[0].id else error("expected one synthetic-messages dataset") end' "$dir/message-datasets.json")
 timer_net=$(jq -r '.networks[]|select(.name=="synthetic-timer")|.id' "$dir/networks.json")
 get "/networks/$timer_net/datasets" timer-datasets
 timer_dataset=$(jq -r '.datasets[]|select(.name=="synthetic-timer-experiment")|.id' "$dir/timer-datasets.json")
 get "/networks/$timer_net/datasets/$timer_dataset/whatif" timer-runs
 timer_run=$(jq -r '.runs[0].id' "$dir/timer-runs.json")
 get "/networks/$timer_net/datasets/$timer_dataset/whatif/$timer_run" timer-summary
 get "/networks/$timer_net/datasets/$timer_dataset/whatif/$timer_run/results?limit=1000" timer-results
 get "/networks/$timer_net/datasets/$timer_dataset/whatif/$timer_run/network-bindings?limit=1000" timer-network-bindings
 get "/networks/$timer_net/datasets/$timer_dataset/whatif/$timer_run/network-effects?limit=1000" timer-network-effects
 get "/networks/$timer_net/datasets/$timer_dataset/whatif-jobs" timer-jobs
 get "/networks/$timer_net/datasets/$timer_dataset/messages/source?input=journal&file=00000000000000000000.wal&ordinal=1" timer-original-source
 get "/networks/$message_net/datasets/$message_id/reexec-sources" message-reexec-sources
 get "/networks/$message_net/datasets/$message_id/reexec-jobs" message-reexec-jobs
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
rows=[dict(kind='NODE_START',impl='wbft',mode='standalone',validator=True,sign_floor=None,wal_recovery=dict(records=0,torn_bytes=0,corrupted=0),application_model=dict(build_queue='serial-latest',done_result='failed',assembly_return='sampled',selection='callbacks_then_done_then_pending')),
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
# Exact build identities exercise the lifecycle source endpoint after restore.
python3 - "$work" <<'PYBUILD'
import hashlib,json,sys
from pathlib import Path
work=Path(sys.argv[1]);node='0x'+'1'*40
common=dict(v=1,node=node,run='synthetic-build',t_wall='2026-01-01T00:00:00Z',view=dict(seq='18446744073709551616',round='0'),number='18446744073709551616',build_id='build-1')
rows=[dict(kind='BUILD_HANDOVER',wait_ns='9007199254740993',parent='0x'+'2'*64),dict(kind='BUILD_STARTED'),dict(kind='BUILD_FINISHED',status='submitted',hash='0x'+'3'*64)]
raw=''.join(json.dumps(dict(common,seq=i,t_mono_ns=i*1000000000,**row))+'\n' for i,row in enumerate(rows)).encode()
(work/'build.jsonl').write_bytes(raw)
manifest=dict(format='wbft-analyzer-run/1',name='synthetic-build-lifecycle',run='synthetic-build',network=dict(chain_id='9',genesis_hash='0x'+'4'*64,name='synthetic-build'),clock='shared-host',inputs=[dict(id='build',node=node,kind='events',path='build.jsonl',sha256=hashlib.sha256(raw).hexdigest())])
(work/'build.json').write_text(json.dumps(manifest)+'\n')
PYBUILD
"$bin" ingest run --db "$src" --manifest "$work/build.json" >"$out/build-ingest.log"
# Closed sealing declarations and actor IDs retain exact strings after restore.
python3 - "$work" <<'PYSEAL'
import hashlib,json,sys
from pathlib import Path
work=Path(sys.argv[1]);node='0x'+'1'*40
model=dict(build_queue='unbuffered-seal',assembly_return='sampled_empty_body',running_gate='at_selection',selection='actors_to_idle_then_deadline_callbacks_seeded',commit_capacity=1,result_capacity=10,head_capacity=10,pending_age=7,call_return_delay_ns=['0','9007199254740993','0'],post_delay_ns=['2'],assembly_delay_ns=['7','2','7'],import_delay_ns=['3'])
common=dict(v=1,node=node,run='synthetic-sealing',t_wall='2026-01-01T00:00:00Z')
rows=[dict(kind='NODE_START',impl='wbft',mode='standalone',wal_recovery=dict(records=0,torn_bytes=0,corrupted=0),sign_floor=None,application_model=model),dict(kind='SIM_SEALING_STAGE',src='app',actor='seal',stage='result_selected',work_id='work-18446744073709551615',commit_id='commit-9007199254740993',request_height='18446744073709551617',request_round='18446744073709551616',cancelled=True)]
raw=''.join(json.dumps(dict(common,seq=i,t_mono_ns=i,**row))+'\n' for i,row in enumerate(rows)).encode()
(work/'sealing.jsonl').write_bytes(raw)
manifest=dict(format='wbft-analyzer-run/1',name='synthetic-sealing-policy',run='synthetic-sealing',network=dict(chain_id='12',genesis_hash='0x'+'7'*64,name='synthetic-sealing'),clock='shared-host',inputs=[dict(id='sealing',node=node,kind='events',path='sealing.jsonl',sha256=hashlib.sha256(raw).hexdigest())])
(work/'sealing.json').write_text(json.dumps(manifest)+'\n')
PYSEAL
"$bin" ingest run --db "$src" --manifest "$work/sealing.json" >"$out/sealing-ingest.log"
"$bin" ingest runtime --db "$src" --file "$root/internal/source/runtimeobs/testdata/config-history-synthetic.jsonl" --name synthetic-runtime --chain-id 10 --genesis "0x5555555555555555555555555555555555555555555555555555555555555555" >"$out/runtime-ingest.json"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/g7/manifest.json" >"$out/run.log"
run_dataset_id=$(sed -n 's/^dataset=\([0-9][0-9]*\).*/\1/p' "$out/run.log")
"$bin" reindex messages --db "$src" --dataset "$run_dataset_id" >"$out/run-pair-index.log"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/baseline/manifest-1.json" >"$out/baseline-1.log"
"$bin" ingest run --db "$src" --manifest "$root/internal/source/logs/testdata/baseline/manifest-2.json" >"$out/baseline-2.log"
jq -n --arg path "$root/internal/source/messages/testdata/scheduler-source" '{format:"wbft-analyzer-messages/1",name:"synthetic-scheduler-source",network:{name:"synthetic-scheduler-source",chain_id:"17",genesis_hash:("0x"+"0"*64)},clock:{model:"unknown"},inputs:[{id:"scheduler",kind:"frames",node:"0xaa00000000000000000000000000000000000000",path:$path}]}' >"$work/scheduler-source.json"
"$bin" ingest messages --db "$src" --manifest "$work/scheduler-source.json" >"$out/scheduler-ingest.json"
jq -n --arg path "$root/internal/source/messages/testdata/cache-source-combined" '{format:"wbft-analyzer-messages/1",name:"synthetic-cache-source",network:{name:"synthetic-cache-source",chain_id:"18",genesis_hash:("0x"+"0"*64)},clock:{model:"unknown"},inputs:[{id:"cache",kind:"frames",node:"0xaa00000000000000000000000000000000000000",path:$path}]}' >"$work/cache-source.json"
"$bin" ingest messages --db "$src" --manifest "$work/cache-source.json" --inputs-dir "$out/cache-inputs" >"$out/cache-ingest.json"
jq -n --arg path "$root/internal/source/messages/testdata/own-input-frames" '{format:"wbft-analyzer-messages/1",name:"synthetic-own-input",network:{name:"synthetic-own-input",chain_id:"13",genesis_hash:("0x"+"0"*64)},clock:{model:"unknown"},inputs:[{id:"native",kind:"frames",node:"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",path:$path}]}' >"$work/own-input.json"
"$bin" ingest messages --db "$src" --manifest "$work/own-input.json" >"$out/own-input-ingest.json"
# Both frame projections and raw journals retain sync-control source links.
for sync_mode in combined incomplete; do
 for sync_kind in frames journal; do
  sync_name="synthetic-sync-$sync_mode-$sync_kind"
  jq -n --arg path "$root/internal/source/messages/testdata/sync-$sync_mode/$sync_kind" --arg name "$sync_name" --arg chain "9" --arg kind "$sync_kind" '{format:"wbft-analyzer-messages/1",name:$name,network:{name:"synthetic-sync-source",chain_id:$chain,genesis_hash:("0x"+"0"*64)},clock:{model:"unknown"},inputs:[{id:"sync",kind:$kind,node:"0xaa00000000000000000000000000000000000000",path:$path}]}' >"$work/$sync_name.json"
  "$bin" ingest messages --db "$src" --manifest "$work/$sync_name.json" --inputs-dir "$out/$sync_name-inputs" >"$out/$sync_name-ingest.json"
 done
done
# Typed metadata carries its original absence of header/footer sequences.
for typed_mode in complete incomplete; do
 typed_name="synthetic-typed-sync-$typed_mode"
 mkdir "$work/$typed_name"
 if [ "$typed_mode" = complete ]; then
  cp "$root/internal/source/messages/testdata/sync-notifications/complete.jsonl" "$work/$typed_name/notifications.jsonl"
 else
  sed '$d' "$root/internal/source/messages/testdata/sync-notifications/complete.jsonl" >"$work/$typed_name/notifications.jsonl"
 fi
 jq -n --arg path "$work/$typed_name" --arg name "$typed_name" '{format:"wbft-analyzer-messages/1",name:$name,network:{name:"synthetic-typed-sync",chain_id:"19",genesis_hash:("0x"+"0"*64)},clock:{model:"unknown"},inputs:[{id:"typed",kind:"sync_notifications",node:"0xaa00000000000000000000000000000000000000",path:$path}]}' >"$work/$typed_name.json"
 "$bin" ingest messages --db "$src" --manifest "$work/$typed_name.json" --inputs-dir "$out/$typed_name-inputs" >"$out/$typed_name-ingest.json"
done
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
"$bin" ingest observe --db "$src" --name synthetic-observation-dump --archive "$root/internal/source/observe/testdata/capture.json" >"$out/observation-ingest.log"
observation_dataset_id=$(jq -r .dataset_id "$out/observation-ingest.log")
"$bin" reindex observations --db "$src" --dataset "$observation_dataset_id" >"$out/observation-bindings.log"
# Full synthetic journals exercise non-empty counterfactual result tables.
cat >"$work/timer-fixture.go" <<'GOTIMER'
package main
import("context";"encoding/json";"fmt";"os";"path/filepath";"time";"github.com/0xmhha/wbft/codec";"github.com/0xmhha/wbft/conformance/sim";"github.com/0xmhha/wbft/crypto/keccak")
func main(){
 root:=os.Args[1];if err:=os.MkdirAll(root,0700);err!=nil{panic(err)}
 validators:=make([]sim.Validator,4)
 for i:=range validators{v,err:=sim.NewValidator(keccak.Sum256Bytes([]byte(fmt.Sprintf("synthetic-dump-timer-%d",i))));if err!=nil{panic(err)};validators[i]=v}
 var links []sim.Link
 for i,a:=range validators{for j,b:=range validators{if i!=j{links=append(links,sim.Link{From:a.Address(),To:b.Address(),Delay:[]time.Duration{10*time.Millisecond}})}}}
 result,err:=sim.Run(context.Background(),sim.Scenario{Name:"synthetic-dump-timer",Seed:4,Validators:validators,Links:links,Until:sim.Stop{Height:3,Duration:time.Minute}},sim.Output{JournalDir:root});if err!=nil || len(result.Violations)!=0{panic("synthetic timer scenario failed")}
 for _,validator:=range validators{files,ok:=result.Journals[validator.Address()];if !ok{continue};directory:=filepath.Join(root,"journal");if err=os.Mkdir(directory,0700);err!=nil{panic(err)};for name,raw:=range files{if err=os.WriteFile(filepath.Join(directory,name),raw,0600);err!=nil{panic(err)}}
 manifest:=map[string]any{"format":"wbft-analyzer-messages/1","name":"synthetic-timer-experiment","network":map[string]any{"name":"synthetic-timer","chain_id":"8282","genesis_hash":codec.BlockHash(result.Chain[0].Header).Hex()},"clock":map[string]any{"model":"shared-host"},"inputs":[]any{map[string]any{"id":"journal","kind":"journal","node":validator.Address().Hex(),"path":directory}}}
 raw,err:=json.Marshal(manifest);if err!=nil{panic(err)};if err=os.WriteFile(filepath.Join(root,"manifest.json"),raw,0600);err!=nil{panic(err)};return}
 panic("missing synthetic journal")
}
GOTIMER
(cd "$root" && go run "$work/timer-fixture.go" "$work/timer-fixture")
"$bin" ingest messages --db "$src" --manifest "$work/timer-fixture/manifest.json" --inputs-dir "$out/timer-inputs" >"$out/timer-ingest.json"
timer_dataset=$(jq -r .dataset_id "$out/timer-ingest.json")
printf '%s\n' '{"request_timeout_seconds":"2"}' >"$work/timer-policy.json"
"$bin" whatif --db "$src" --dataset "$timer_dataset" --input journal --chain "$work/timer-fixture/chain.rlp" --timer-policy "$work/timer-policy.json" >"$out/timer-experiment.json"
# Synthetic Info-only logs retain unavailable heights after dump/restore.
python3 - "$work" <<'PYRECONSTRUCTION'
from pathlib import Path
import json,hashlib,sys
work=Path(sys.argv[1]);node='0x'+'2'*40
raw=(json.dumps({'t':'2020-01-01T00:00:00Z','lvl':'info','msg':'WBFT: start new round','address':node,'next.seq':'1','next.round':'0'})+'\n').encode()
path=work/'reconstruction-log.jsonl';path.write_bytes(raw)
file={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
network={'chain_id':'17','genesis_hash':'0x'+'7'*64,'name':'synthetic-reconstruction'}
run={'format':'wbft-analyzer-run/1','name':'synthetic-reconstruction','run':'synthetic-reconstruction','network':network,'clock':'shared-host','inputs':[dict(file,id='log',kind='log',node=node,profile='gstable@740526d03')]}
manifest={'format':'wbft-reconstruction-input/1','node':node,'network':network,'log':file}
(work/'reconstruction-ingest.json').write_text(json.dumps(run)+'\n')
(work/'reconstruction-sources.json').write_text(json.dumps(manifest)+'\n')
PYRECONSTRUCTION
"$bin" ingest run --db "$src" --manifest "$work/reconstruction-ingest.json" >"$out/reconstruction-ingest.log"
reconstruction_dataset=$(sed -n 's/^dataset=\([0-9]*\).*/\1/p' "$out/reconstruction-ingest.log")
test -n "$reconstruction_dataset"
"$bin" reconstruct --execute --db "$src" --dataset "$reconstruction_dataset" --input log --manifest "$work/reconstruction-sources.json" --from 1 --to 2 >"$out/reconstruction-execution.json" 2>"$out/reconstruction-execution.log"
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
