import { useEffect, useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

type Sample = Schemas["LatencySample"];
type Stats = Schemas["LatencyStats"];
const metrics = ["preprepare", "prepare_quorum", "commit_quorum", "commit", "import", "round_to_decision", "round_to_import"];
export function seconds(n: number | null): string { return n === null ? "unknown" : `${(n * 1000).toFixed(3)} ms`; }

export function PhaseLatency({ net, dataset, times, node, height, round, onAuth, onPoint }: {
  net: number; dataset: number; times: { from_t: string; to_t: string }; node: string; height: string; round: string;
  onAuth: () => void; onPoint: (input: string, line: number) => void;
}) {
  const [metric, setMetric] = useState("round_to_decision");
  const [clock, setClock] = useState("");
  const [status, setStatus] = useState("");
  const [threshold, setThreshold] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const query = { ...times, ...(node ? { node } : {}), ...(height ? { height } : {}), ...(round ? { round } : {}), metric };
  const scope = JSON.stringify({ net, dataset, query, clock, status, threshold });
  useEffect(() => setCursors([]), [scope]);
  const summary = useLoad(() => get("/v1/networks/{net}/datasets/{dataset}/phases/summary", { path: { net, dataset }, query }), [net, dataset, JSON.stringify(query)]);
  const cursor = cursors.at(-1);
  const page = useLoad(() => get("/v1/networks/{net}/datasets/{dataset}/phases/samples", {
    path: { net, dataset }, query: { ...query, ...(clock ? { clock } : {}), ...(status ? { status } : {}), ...(threshold ? { threshold } : {}), ...(cursor ? { cursor } : {}), limit: 100 },
  }), [scope, cursor]);
  const groups = summary.state === "done" ? summary.data.groups : [];
  const rows = page.state === "done" ? page.data.samples : [];
  return <details><summary>WBFT phase latency and bottleneck samples</summary>
    <p>Measurements stay within one input, node, engine run, height and round. Available monotonic timestamps take precedence; logs use wall time. Missing or negative measurements are excluded from percentiles. Legacy decision logs do not establish import time. Overall percentiles use raw samples, so nodes with more samples have more weight. The event kind and message filters above apply to the event table; latency uses the time, node, height and round filters.</p>
    <div className="controls">
      <label>Latency metric <select value={metric} onChange={(e) => setMetric(e.target.value)}>{metrics.map((m) => <option key={m}>{m}</option>)}</select></label>
      <label>Latency clock <select value={clock} onChange={(e) => { setClock(e.target.value); setThreshold(""); }}><option value="">All clocks</option>{["wall", "monotonic", "unavailable"].map((c) => <option key={c}>{c}</option>)}</select></label>
      <label>Sample status <select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option>{["valid", "negative", "missing_start", "missing_end", "missing_both", "missing_clock", "invalid_clock"].map((s) => <option key={s}>{s}</option>)}</select></label>
      <label>At or above percentile <select value={threshold} disabled={!clock || clock === "unavailable"} onChange={(e) => setThreshold(e.target.value)}><option value="">All samples</option>{["p50", "p90", "p95", "p99"].map((p) => <option key={p}>{p}</option>)}</select></label>
    </div>
    <Pending load={summary} onAuth={onAuth} />
    {summary.state === "done" && <><p>{summary.data.samples} selected measurements · {summary.data.percentile_method}</p><PhaseStats groups={groups} />{groups.filter((g) => !g.node && (!clock || g.clock === clock)).map((g) => <PhaseHistogram key={g.clock} group={g} />)}<p>Bottleneck candidates ranked by node p95 (each clock ranked separately): {groups.filter((g) => g.node && g.p95_seconds !== null && (!clock || clock === g.clock)).sort((a, b) => a.clock.localeCompare(b.clock) || (b.p95_seconds ?? 0) - (a.p95_seconds ?? 0)).map((g) => `${g.node} ${g.clock}: ${seconds(g.p95_seconds)} (${g.valid} valid)`).join("; ") || "unknown"}. These are observed delays, not a diagnosis of their cause.</p></>}
    <Pending load={page} onAuth={onAuth} />
    {page.state === "done" && <><p>{rows.length} samples on this page / {page.data.total} matching samples. The series below shows this cursor page; use the table to inspect missing values and source context.</p>{[...new Set(rows.map((s) => s.clock))].filter((c) => c !== "unavailable").map((c) => <figure key={c}><figcaption>{c} clock · current cursor page</figcaption><PhaseSeries samples={rows.filter((s) => s.clock === c)} from={times.from_t} to={times.to_t} /></figure>)}
      <div className="controls"><button type="button" disabled={!cursors.length} onClick={() => setCursors(cursors.slice(0, -1))}>Previous samples</button><button type="button" disabled={!page.data.next} onClick={() => { if (page.data.next) setCursors([...cursors, page.data.next]); }}>Next samples</button></div>
      <div className="table-scroll"><table><thead><tr><th>Node / engine</th><th>Full height / round</th><th>Clock / status</th><th>Latency</th><th>Start / end evidence</th><th>Repeated markers</th></tr></thead><tbody>{rows.map((s) => <tr key={s.id}><td>{s.node} / {s.run}</td><td>{s.height} / {s.round}</td><td>{s.clock} / {s.status}</td><td>{seconds(s.seconds)}</td><td>{[s.start, s.end].map((p, i) => p ? <button key={i} type="button" title={`${p.t_wall}; ${p.view_inferred ? "inferred view" : "recorded view"}`} onClick={() => onPoint(p.input, p.line)}>{i === 0 ? "start" : "end"} {p.input}:{p.line}</button> : <span key={i}>{i === 0 ? "start" : "end"} missing </span>)}</td><td>{s.duplicate_markers}</td></tr>)}</tbody></table></div>
    </>}
  </details>;
}
export function PhaseStats({ groups }: { groups: Stats[] }) {
  return <div className="table-scroll"><table><thead><tr><th>Node / profile / clock</th><th>Total / valid</th><th>Missing / negative / invalid clock</th><th>p50</th><th>p90</th><th>p95</th><th>p99</th><th>Mean / stddev</th></tr></thead><tbody>{groups.map((g) => <tr key={`${g.node}:${g.profile}:${g.metric}:${g.clock}`}><td>{g.node || "Overall"} / {g.profile || "all profiles"} / {g.clock}</td><td>{g.total} / {g.valid}</td><td>{g.missing} / {g.negative} / {g.invalid_clock}</td><td>{seconds(g.p50_seconds)}</td><td>{seconds(g.p90_seconds)}</td><td>{seconds(g.p95_seconds)}</td><td>{seconds(g.p99_seconds)}</td><td>{seconds(g.mean_seconds)} / {seconds(g.stddev_seconds)}</td></tr>)}</tbody></table></div>;
}
export function PhaseHistogram({ group }: { group: Stats }) {
  const max = Math.max(1, ...group.histogram.map((b) => b.count));
  return <figure><figcaption>{group.metric} · {group.clock} · {group.valid} valid samples</figcaption><svg viewBox="0 0 800 150" role="img" aria-label={`Phase latency histogram ${group.clock}`}>
    {group.histogram.map((b, i) => <g key={i}><rect x={20 + i * 760 / group.histogram.length} y={110 - b.count / max * 95} width={Math.max(1, 760 / group.histogram.length - 3)} height={b.count / max * 95} fill="#7954c7"><title>{`${seconds(b.from_seconds)} – ${seconds(b.to_seconds)}: ${b.count}`}</title></rect><text x={20 + i * 760 / group.histogram.length} y={135} fontSize="11">{seconds(b.from_seconds)}</text></g>)}
  </svg></figure>;
}
export function PhaseSeries({ samples, from, to }: { samples: Sample[]; from: string; to: string }) {
  const valid = samples.filter((s) => s.seconds !== null && (s.status === "valid" || s.status === "negative"));
  const lo = Math.min(0, ...valid.map((s) => s.seconds ?? 0));
  const hi = Math.max(.001, ...valid.map((s) => s.seconds ?? 0));
  const start = Date.parse(from), span = Math.max(1, Date.parse(to) - start);
  return <svg viewBox="0 0 800 170" role="img" aria-label="Phase latency sample time series"><text x="5" y="15">{seconds(hi)}</text><text x="5" y="155">{seconds(lo)}</text>
    {valid.map((s) => <circle key={s.id} cx={100 + 670 * Math.max(0, Math.min(1, (Date.parse(s.at) - start) / span))} cy={145 - 120 * ((s.seconds ?? 0) - lo) / (hi - lo)} r="3" fill={s.status === "negative" ? "#b42d38" : "#7954c7"}><title>{`${s.node} h=${s.height} r=${s.round} ${s.clock} ${s.status}: ${seconds(s.seconds)}`}</title></circle>)}
  </svg>;
}
