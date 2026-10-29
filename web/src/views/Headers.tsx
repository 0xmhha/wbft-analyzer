import {EpochRegistry} from "./EpochRegistry";
import {HeaderGovernance} from "./HeaderGovernance";
import { useState } from "react";
import { get } from "../api/client";
import { evidenceMatches, included, pageEnd } from "../headers";
import type { HeaderRow, Evidence } from "../headers";
import { Pending, useLoad } from "../ui";

/** Immutable header participation with optional, explicitly scoped node copies. */
export function Headers({ net, onAuth, focus, sourceError }: { net: number; onAuth: () => void; focus?:{index:string;dataset:number;node:string}; sourceError?:string }) {
  const overview = useLoad(async () => {
    const [bounds, datasets] = await Promise.all([
      get("/v1/networks/{net}/header-bounds", { path: { net } }),
      get("/v1/networks/{net}/datasets", { path: { net } }),
    ]);
    return { bounds, datasets: datasets.datasets };
  }, [net]);
  const [start, setStart] = useState(focus?.index||"");
  const [draft, setDraft] = useState(focus?.index||"");
  const [dataset, setDataset] = useState(focus?.dataset||0);
  const [node, setNode] = useState(focus?.node||"");
  const [selected, setSelected] = useState<HeaderRow | null>(null);
  const [validator, setValidator] = useState<string | undefined>(undefined);
  const [view, setView] = useState<"participation" | "proposers" | "epochs">("participation");
  const bounds = overview.state === "done" ? overview.data.bounds : null;
  const from = start || bounds?.from || "0";
  const to = pageEnd(from, bounds?.to || from);
  const window = useLoad(async () => {
    if (!bounds?.from || BigInt(from) > BigInt(bounds.to || "0")) return null;
    const [rows, summary, epochs, reports] = await Promise.all([
      get("/v1/networks/{net}/headers", { path: { net }, query: { from, to, ...(dataset && node ? { dataset, node } : {}) } }),
      get("/v1/networks/{net}/headers/summary", { path: { net }, query: { from, to } }),
      get("/v1/networks/{net}/epochs", { path: { net }, query: { from, to } }),
      get("/v1/reports", { query: { net } }),
    ]);
    const obs = await Promise.all(reports.reports.map(async (r) => ({ report: r.id, observations: (await get("/v1/reports/{id}/observations", { path: { id: r.id } })).observations })));
    return { rows: rows.headers, summary, epochs: epochs.epochs, observations: obs.flatMap((r) => r.observations.map((o) => ({ ...o, report: r.report }))) };
  }, [net, from, to, bounds?.from, dataset, node]);
  const data = window.state === "done" ? window.data : null;
  const scopedObservations = data?.observations.filter((o)=>!dataset || !node || !o.node || o.node===node) || [];
  const choose = (r: HeaderRow, address?: string) => {setSelected(r);setValidator(address)};
  const move = (delta: bigint) => { const n = BigInt(from) + delta; setStart(String(n < BigInt(bounds?.from || "0") ? BigInt(bounds?.from || "0") : n)); setSelected(null); };
  return <section>
    <h1>What do the agreed headers show?</h1>{sourceError&&<p role="alert">{sourceError}</p>}
    <p className="muted">Participation at h uses the previous seals in h+1. Absent inclusion is normal for some validators. A linked successor establishes the decision round, without timeout or message causes. Without it, the decision and earlier proposer opportunities remain unknown; a selected node copy stays separate.</p>
    <Pending load={overview} onAuth={onAuth} />
    {bounds && <p>{bounds.count.toLocaleString()} stored headers · indices {bounds.from ?? "none"}–{bounds.to ?? "none"} · {(bounds.bytes / 1048576).toFixed(1)} MiB of header facts</p>}
    {overview.state === "done" && <details><summary>Import status and datasets</summary><table><thead><tr><th>Dataset</th><th>Status</th><th>Processed</th><th>Error</th></tr></thead><tbody>{overview.data.datasets.map((d) => <tr key={d.id}><td>{d.name}</td><td>{d.status}</td><td>{d.progress}</td><td>{d.error}</td></tr>)}</tbody></table></details>}
    <form className="controls" onSubmit={(e) => { e.preventDefault(); if (/^\d+$/.test(draft) && BigInt(draft) <= BigInt(bounds?.to || "0")) { setStart(String(BigInt(draft))); setSelected(null); } }}>
      <label>First index <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={from} inputMode="numeric" /></label> <button>Go</button>{" "}
      <button type="button" disabled={BigInt(from) <= BigInt(bounds?.from || "0")} onClick={() => move(-128n)}>Previous</button>{" "}
      <button type="button" disabled={BigInt(to) >= BigInt(bounds?.to || "0")} onClick={() => move(128n)}>Next</button>{" "}
      <label>Node copy <select value={dataset} onChange={(e) => { const id=Number(e.target.value); setDataset(id); setNode(overview.state === "done" ? overview.data.datasets.find((d) => d.id===id)?.copy_nodes[0] || "" : ""); }}><option value={0}>No copy</option>{overview.state === "done" && overview.data.datasets.filter((d)=>d.copy_nodes.length>0).map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select></label>{" "}
      {dataset !== 0 && <label>Node label <select value={node} onChange={(e) => setNode(e.target.value)}>{overview.state === "done" && overview.data.datasets.find((d) => d.id === dataset)?.copy_nodes.map((n) => <option key={n} value={n}>{n}</option>)}</select></label>}
    </form>
    <nav>{(["participation", "proposers", "epochs"] as const).map((v) => <button type="button" key={v} className={view === v ? "here" : ""} onClick={() => setView(v)}>{v}</button>)}</nav>
    <Pending load={window} onAuth={onAuth} />
    {data && <>
      <p>Window {from}–{to} · {data.summary.heights} heights · decision rounds: {data.summary.rounds.map((r) => `${r.round}: ${r.count}`).join(", ")} · {data.summary.unknown_round} unknown · {data.summary.missing_heights} missing heights</p>
      <div className="table-scroll">
        {view === "participation" && <ParticipationMatrix rows={data.rows} selected={selected?.fact.index} onSelect={choose} validator={validator} observations={scopedObservations.flatMap((o) => o.evidence)} />}
        {view === "proposers" && <table><thead><tr><th>Height</th><th>Round 0</th><th>Decision round / source</th><th>Expected proposer</th><th>Coinbase</th><th>Schedule / earlier opportunities</th></tr></thead><tbody>{data.rows.map((r) => <tr key={r.fact.index}><td><button type="button" onClick={() => choose(r)}>{r.fact.number}</button></td><td className="mono">{r.fact.round_zero}</td><td>{r.decision_round ?? "unknown"} / {r.round_source}</td><td className="mono">{r.expected_proposer ?? "unknown"}</td><td className="mono">{r.fact.coinbase}</td><td>{r.proposer_differs === null ? "unknown" : r.proposer_differs ? "differs (observation)" : "matches"} · {r.decision_round === null ? "unknown" : r.missed.map((m) => `${m.address}: ${m.count}`).join(", ") || "none"}</td></tr>)}</tbody></table>}
        {view === "epochs" && <>{data.epochs.length === 0 && <p>No epoch block in this window.</p>}{data.epochs.map((e) => <article key={e.index}><h2>Epoch block {e.index}: {e.check === "matched_header_inputs" ? "recalculation matches (header inputs)" : e.check === "mismatch" ? "recalculation differs" : "input unavailable"}</h2><p>{e.detail}</p>{e.changes_known ? <p>Validators added: {e.added.join(", ") || "none"}; removed: {e.removed.join(", ") || "none"}. Changes compare stored epoch headers.</p> : <p>Validator changes unknown: the preceding epoch header is not stored.</p>}<table><thead><tr><th>Candidate</th><th>Diligence (units of 10⁻⁶)</th><th>Next validator order</th><th>BLS public key</th></tr></thead><tbody>{e.candidates.map((c) => <tr key={c.index}><td className="mono">{c.address}</td><td>{c.diligence}</td><td>{c.validator_order ?? "not selected"}</td><td className="mono" title={c.bls_key ?? "key not in header"}>{c.bls_key ? `${c.bls_key.slice(0, 14)}…` : "key not in header"}</td></tr>)}</tbody></table><HeaderGovernance net={net} index={e.index} onAuth={onAuth}/><EpochRegistry key={`${net}:${e.index}`} net={net} index={e.index} onAuth={onAuth}/><details><summary>Encoded epoch fields</summary><pre>{JSON.stringify(e.info, null, 2)}</pre></details></article>)}</>}

      </div>
      <details><summary>Validator inclusion denominators and proposer totals</summary><table><thead><tr><th>Validator</th><th>Eligible</th><th>Known / unknown</th><th>Prepare / commit</th><th>Commit inclusion</th><th>Round 0 / actual / missed opportunities</th></tr></thead><tbody>{data.summary.validators.map((v) => <tr key={v.address}><td className="mono">{v.address}</td><td>{v.eligible}</td><td>{v.known} / {v.unknown}</td><td>{v.prepared} / {v.committed}</td><td>{v.inclusion_rate === null ? "unknown" : `${(v.inclusion_rate * 100).toFixed(1)}%`}</td><td>{v.round_zero} / {v.proposed} / {v.missed}</td></tr>)}</tbody></table></details>
      {selected && <aside><h2>Header {selected.fact.number}</h2><p className="mono">{selected.fact.hash}</p><p>Index {selected.fact.index}; epoch {selected.fact.epoch}; time {selected.fact.time}. Decision source: {selected.round_source}.</p>
        <h3>Validator cells</h3><table><thead><tr><th>Validator</th><th>Network prepare / commit</th><th>Own prepare / commit</th><th>Late prepare / commit</th></tr></thead><tbody>{selected.cells.map((c) => <tr key={c.address}><td className="mono">{c.address}</td><td>{included(c.prepared)} / {included(c.committed)}</td><td>{included(c.own_prepared)} / {included(c.own_committed)}</td><td>{c.late_prepared === null ? "unknown" : c.late_prepared ? "late" : "no"} / {c.late_committed === null ? "unknown" : c.late_committed ? "late" : "no"}</td></tr>)}</tbody></table><h3>Inspector evidence for this height{validator ? ` / validator ${validator}` : ""}</h3>{scopedObservations.filter((o) => o.evidence.some((e) => evidenceMatches(selected,e,validator))).map((o) => <article key={o.report + o.id}><p>{o.kind} · report {o.report} · node {o.node || "network"}</p><pre>{JSON.stringify(o.evidence.filter((e)=>evidenceMatches(selected,e,validator)), null, 2)}</pre></article>)}
        {selected.copy && <><h3>Node copy</h3><p>Node {selected.copy.node}; round {selected.copy.round}; source {selected.copy.source}. Own and late inclusion are shown in the validator cells.</p></>}
      </aside>}
    </>}
  </section>;
}

function Seal({ value }: { value: boolean | null }) { return <span className={`seal seal-${included(value)}`} title={included(value)} aria-label={included(value)}>{value === null ? "?" : value ? "●" : "○"}</span>; }

function ParticipationMatrix({ rows, selected, onSelect, observations,validator }: { rows: HeaderRow[]; selected?: string; onSelect: (r: HeaderRow, address?: string) => void; observations: Evidence[];validator?:string }) {
 const groups: { epoch: string; rows: HeaderRow[] }[] = [];
 for (const r of rows) {
  const last = groups[groups.length - 1];
  if (last?.epoch === r.fact.epoch) last.rows.push(r); else groups.push({ epoch: r.fact.epoch, rows: [r] });
 }
 return <><p>Each cell: prepare / commit. Select a cell for the node copy and late inclusion. Hollow marks mean absent; question marks mean unknown.</p>{groups.map((g) => <article key={g.epoch}>
 <h2>Governing epoch {g.epoch}</h2>
 <table className="participation"><thead><tr><th>Full height</th>{g.rows[0]?.cells.map((c) => <th key={c.address} className="mono" title={c.address}>{c.address.slice(0, 8)}…</th>)}<th>Network decision round</th><th>Evidence</th></tr></thead><tbody>{g.rows.map((r) => <tr key={r.fact.index} className={selected === r.fact.index ? "chosen" : ""}>
 <td><button type="button" onClick={() => onSelect(r)}>{r.fact.number}</button></td>{r.cells.map((c) => <td key={c.address} className={selected===r.fact.index && validator?.toLowerCase()===c.address.toLowerCase() ? "chosen-cell" : ""}><button type="button" onClick={() => onSelect(r,c.address)} aria-label={`height ${r.fact.number}, validator ${c.address}, prepare ${included(c.prepared)}, commit ${included(c.committed)}`}><Seal value={c.prepared} /> / <Seal value={c.committed} /></button>{observations.some((e)=>evidenceMatches(r,e,c.address) && Boolean(e.address)) && <button type="button" className="evidence-mark" aria-label={`inspector evidence at height ${r.fact.number} for validator ${c.address}`} onClick={()=>onSelect(r,c.address)}>e</button>}</td>)}<td>{r.decision_round ?? "?"}</td><td>{observations.some((e)=>evidenceMatches(r,e)) && <button type="button" onClick={() => onSelect(r)}>inspector</button>}</td>
 </tr>)}</tbody></table></article>)}</>;
}
