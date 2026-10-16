import type { EventFocus } from "../sourceLink";
import { useEffect, useState, useRef } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { eventClass, eventKey, eventLayout, field, timeWindow } from "../events";
import type { LogEvent } from "../events";
import { Pending, useLoad } from "../ui";
import { PhaseLatency } from "./PhaseLatency";
import { VisualReplay } from "./VisualReplay";
import { RoundBaselines } from "./RoundBaselines";
import { BuildLifecycleEvidence } from "./BuildLifecycleEvidence";

type Filter = { node: string; kind: string; phase: string; height: string; round: string };
const emptyFilter: Filter = { node: "", kind: "", phase: "", height: "", round: "" };

export function Events({ net, focus, sourceError, onAuth }: { net: number; focus?:EventFocus; sourceError?:string; onAuth: () => void }) {
  const datasets = useLoad(async () => (await get("/v1/networks/{net}/datasets", { path: { net } })).datasets.filter((d) => d.kind === "run"), [net]);
  const [chosen, choose] = useState(focus?.dataset || 0);
  const id = chosen || (datasets.state === "done" ? datasets.data.at(-1)?.id : 0) || 0;
  const run = datasets.state === "done" ? datasets.data.find((d) => d.id === id) : undefined;
  const info = useLoad(async () => {
    if (!id) return null;
    const [bounds, inputs] = await Promise.all([
      get("/v1/networks/{net}/datasets/{dataset}/event-bounds", { path: { net, dataset: id } }),
      get("/v1/networks/{net}/datasets/{dataset}/inputs", { path: { net, dataset: id } }),
    ]);
    return { bounds, inputs: inputs.inputs };
  }, [net, id]);
  const [anchor, setAnchor] = useState<number | null>(null);
  const [span, setSpan] = useState(30000);
  const [filter, setFilter] = useState<Filter>(emptyFilter);
  const [draft, setDraft] = useState<Filter>(emptyFilter);
  const [cursors, setCursors] = useState<string[]>([]);
  const [selected, setSelected] = useState<LogEvent | null>(null);
 const [pointer,setPointer]=useState<{input:string;line:number}|null>(focus ? {input:focus.input,line:focus.line}:null);
 const [replaySource,setReplaySource]=useState<LogEvent|null>(null);
 const select=(e:LogEvent|null)=>{setProof(null);setPointer(null);setSelected(e)};
 const detail=useLoad(async()=>pointer?get("/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}",{path:{net,dataset:id,...pointer}}):null,[net,id,pointer?.input,pointer?.line]);
 const [proof,setProof]=useState<{report:string;observation:string;index:number}|null>(null);
 const evidence=useLoad(async()=>proof?get("/v1/networks/{net}/datasets/{dataset}/evidence",{path:{net,dataset:id},query:proof}):null,[net,id,proof?.report,proof?.observation,proof?.index]);
 const chosenEvent=proof?(evidence.state==="done"?evidence.data?.event||null:null):pointer?(detail.state==="done"?detail.data:null):selected;
  const bounds = info.state === "done" ? info.data?.bounds : null;
  const times = bounds?.from_t && bounds.to_t ? timeWindow(anchor ?? Date.parse(bounds.from_t), span, bounds) : null;
  const cursor = cursors.at(-1);
  const scope = `${net}:${id}:${times?.from_t}:${times?.to_t}:${JSON.stringify(filter)}`;
  const windowScope=`${id}:${times?.from_t}:${times?.to_t}`;
 const retainProof=useRef(false), previousScope=useRef(scope), previousWindow=useRef(windowScope), initializingSource=useRef(Boolean(focus));
 useEffect(() => { if(previousScope.current===scope)return;previousScope.current=scope;const windowChanged=previousWindow.current!==windowScope;previousWindow.current=windowScope;setCursors([]); if(retainProof.current){retainProof.current=false}else if(!(pointer && (initializingSource.current || !windowChanged))){select(null);setReplaySource(null)} }, [scope]);
 useEffect(()=>{if(focus?.replay && detail.state==="done" && detail.data && pointer?.input===focus.input && pointer?.line===focus.line)setReplaySource(detail.data)},[focus,detail,pointer?.input,pointer?.line]);
 useEffect(()=>{if(proof&&evidence.state==="done"&&evidence.data?.event&&times){const t=Date.parse(evidence.data.event.t_wall);if(t<Date.parse(times.from_t)||t>Date.parse(times.to_t)){retainProof.current=true;setAnchor(t-span/2)}}},[proof,evidence,times?.from_t,times?.to_t,span]);
 useEffect(()=>{if(pointer&&detail.state==="done"&&detail.data&&times){const t=Date.parse(detail.data.t_wall);if(t<Date.parse(times.from_t)||t>Date.parse(times.to_t)){retainProof.current=true;setAnchor(t-span/2)}else{initializingSource.current=false}}},[pointer,detail,times?.from_t,times?.to_t,span]);

  const page = useLoad(async () => {
    if (!times) return null;
    const query = { ...times, ...Object.fromEntries(Object.entries(filter).filter(([, v]) => v)), limit: 500, ...(cursor ? { cursor } : {}) };
    return get("/v1/networks/{net}/datasets/{dataset}/events", { path: { net, dataset: id }, query });
  }, [scope, cursor]);
  const rounds = useLoad(async () => times ? get("/v1/networks/{net}/datasets/{dataset}/rounds/distribution", { path: { net, dataset: id }, query: times }) : null, [net, id, times?.from_t, times?.to_t]);
  const data = page.state === "done" ? page.data : null;
  const nodes = info.state === "done" && info.data ? [...new Set(info.data.inputs.map((i) => i.node))].sort().filter((n) => !filter.node || filter.node === n) : [];
  const resetDataset = (value: number) => { choose(value); setAnchor(null); setCursors([]); setReplaySource(null); select(null); };
  return <section>
    <h1>How did each WBFT node progress?</h1>
    {sourceError && <p className="error">{sourceError}</p>}
    <p className="muted">Points are metadata from node logs or schema-validated event streams. A send records an attempt; a handle records processing. Missing points do not prove a missing message. Time alignment uses wall timestamps; event intervals can retain a monotonic clock.</p>
    <Pending load={datasets} onAuth={onAuth} />
    {datasets.state === "done" && <>
      {datasets.data.length === 0 ? <p>No run dataset yet. Load a run manifest or a local chainbench workspace.</p> : <label>Run dataset <select value={id} onChange={(e) => resetDataset(Number(e.target.value))}>{datasets.data.map((d) => <option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label>}
      {run && <p>{run.status} · {run.progress.toLocaleString()} stored events {run.error && <span className="error">· {run.error}</span>}</p>}
    </>}
    {datasets.state==="done" && <RoundBaselines key={net} net={net} datasets={datasets.data} onAuth={onAuth}/>}
    <Pending load={info} onAuth={onAuth} />
    {info.state === "done" && info.data && <details><summary>Input hashes, profiles and diagnostics</summary><p>Clock model: {String((run?.metadata as Record<string, unknown> | null)?.clock || (run?.metadata as Record<string, unknown> | null)?.Clock || "unknown")}. Source timestamps can arrive out of order; the counts below do not establish clock skew. Logs have no monotonic clock and do not establish complete event coverage. Duplicate context outside the selected profile contributes no events; ambiguous relevant records remain malformed.</p><table><thead><tr><th>Input / node</th><th>Profile</th><th>Normalized source records</th><th>Unknown / malformed</th><th>Out-of-profile duplicate context</th><th>Wall / monotonic regressions / sequence gaps</th><th>SHA256</th></tr></thead><tbody>{info.data.inputs.map((i) => <tr key={i.id}><td>{i.id} / {i.node} · {i.kind}</td><td title={i.profile_sha256}>{i.profile}</td><td>{i.stats.events.toLocaleString()}</td><td>{i.stats.unknown} / {i.stats.malformed}</td><td>{i.kind === "events" ? "not applicable" : i.stats.out_of_profile_duplicate_context || 0}</td><td>{i.stats.clock_regressions} / {i.stats.monotonic_regressions || 0} / {i.stats.sequence_gaps || 0}</td><td className="mono" title={i.sha256}>{i.sha256.slice(0, 16)}…</td></tr>)}</tbody></table></details>}
    {times && <>
      <div className="controls"><button type="button" onClick={() => setAnchor(Date.parse(times.from_t) - span)}>Earlier</button><button type="button" onClick={() => setAnchor(Date.parse(times.from_t) + span)}>Later</button><button type="button" disabled={span <= 1000} onClick={() => setSpan(Math.max(1000, span / 2))}>Zoom in</button><button type="button" disabled={span >= 3600000} onClick={() => setSpan(Math.min(3600000, span * 2))}>Zoom out</button><label>Move through run <input aria-label="Move through run" type="range" min={Date.parse(bounds?.from_t || times.from_t)} max={Date.parse(bounds?.to_t || times.to_t)} step={1000} value={Date.parse(times.from_t)} onChange={(e) => setAnchor(Number(e.target.value))} /></label></div>
      <p className="mono">{times.from_t} – {times.to_t}</p>
      <form className="controls" onSubmit={(e) => { e.preventDefault(); setFilter(draft); }}>
        <label>Node <select value={draft.node} onChange={(e) => setDraft({ ...draft, node: e.target.value })}><option value="">All nodes</option>{run?.nodes.map((n) => <option key={n}>{n}</option>)}</select></label>
        <label>Kind <input list="event-kinds" value={draft.kind} onChange={(e)=>setDraft({...draft,kind:e.target.value})} placeholder="All kinds" /><datalist id="event-kinds">{["ROUND_ENTER","SEND","PREPREPARE_ACCEPT","MSG_OUTCOME","QUORUM","TIMER_ARM","TIMER_CANCEL","TIMER_FIRE","STATE","NEW_HEAD","ENGINE_START","ENGINE_STOP","BACKLOG","EXTRA_SEAL","BUILD_REQUEST","BUILD_HANDOVER","BUILD_STARTED","BUILD_FINISHED","PROPOSAL_SUBMITTED","FINALIZE_HANDOVER","COMMIT_RESULT","IMPORT_FAIL","EVIDENCE","LOG_CONFIG","HEALTH"].map((k)=><option key={k} value={k}/>)}</datalist></label>
        <label>Message <select value={draft.phase} onChange={(e) => setDraft({ ...draft, phase: e.target.value })}><option value="">All phases</option>{["PRE-PREPARE", "PREPARE", "COMMIT", "ROUND-CHANGE"].map((p) => <option key={p}>{p}</option>)}</select></label>
        <label>Full height <input value={draft.height} onChange={(e) => setDraft({ ...draft, height: e.target.value })} inputMode="numeric" /></label>
        <label>Full round <input value={draft.round} onChange={(e) => setDraft({ ...draft, round: e.target.value })} inputMode="numeric" /></label>
        <button>Apply filters</button><button type="button" onClick={() => { setDraft(emptyFilter); setFilter(emptyFilter); }}>Clear filters</button>
      </form>
      <Pending load={page} onAuth={onAuth} />
      {data && <>
        <p>{data.events.length} events on this cursor page · round entries (blue), send attempts (amber), quorum (purple), heads (green), timeout (red), application builds (teal), other (grey). Empty lanes mean no matching records on this page.</p>
        <div className="table-scroll"><Swimlanes events={data.events} nodes={nodes} from={times.from_t} to={times.to_t} selected={chosenEvent} onSelect={select} /></div>
        <div className="controls"><button type="button" disabled={cursors.length === 0} onClick={() => { setCursors(cursors.slice(0, -1)); select(null); }}>Previous page</button><button type="button" disabled={!data.next} onClick={() => { if (data.next) setCursors([...cursors, data.next]); select(null); }}>Next page</button></div>
        <div className="event-table table-scroll"><table><thead><tr><th>Source</th><th>Node</th><th>Wall time</th><th>Full height / round</th><th>Kind / message</th><th>View source</th></tr></thead><tbody>{data.events.map((e) => <tr key={eventKey(e)} className={chosenEvent && eventKey(chosenEvent) === eventKey(e) ? "selected" : ""}><td><button type="button" onClick={() => select(e)}>{e.input}:{e.line}</button></td><td>{e.node}</td><td className="mono">{e.t_wall}</td><td>{e.height || "unknown"} / {e.round || "unknown"}</td><td>{e.kind} / {field(e, "phase") || "—"}</td><td>{e.view_inferred ? "carried within engine run" : "recorded / unavailable"}</td></tr>)}</tbody></table></div>
      </>}
      {pointer && <Pending load={detail} onAuth={onAuth} />}
      {chosenEvent && <aside><h2>{chosenEvent.kind}: {chosenEvent.node}</h2>{data && !data.events.some((e)=>eventKey(e)===eventKey(chosenEvent)) && <p>This source event was fetched separately and is highlighted alongside the current filtered page.</p>}<p>Source {chosenEvent.input}:{chosenEvent.line} · {chosenEvent.run} · {chosenEvent.profile} · {chosenEvent.source || "log"}-{chosenEvent.level}</p><p className="mono">{chosenEvent.t_wall} · full height {chosenEvent.height || "unknown"} / round {chosenEvent.round || "unknown"}</p><p>{chosenEvent.view_inferred ? "View is inferred from this engine run's latest round." : "View is recorded in this line or unavailable."} {chosenEvent.t_mono_ns !== undefined ? `Monotonic time: ${chosenEvent.t_mono_ns} ns.` : "No monotonic timestamp is present."}</p><pre>{JSON.stringify(chosenEvent.fields, null, 2)}</pre><BuildLifecycleEvidence net={net} dataset={id} source={chosenEvent} onAuth={onAuth} onSelect={(input,line)=>{setProof(null);setSelected(null);setPointer({input,line})}}/><button type="button" onClick={()=>setReplaySource(chosenEvent)}>Show this source in replay</button><a href={`#/networks/${net}/headers`}>Compare header participation and missed proposer opportunities</a></aside>}
      {proof && <><Pending load={evidence} onAuth={onAuth}/>{evidence.state==="done"&&evidence.data&&<p>Inspector source: {evidence.data.status} · {evidence.data.report_input} → {evidence.data.dataset_input || "unavailable"}:{evidence.data.line} · SHA256 {evidence.data.sha256 || "unavailable"}</p>}</>}
      <VisualReplay key={`${id}:${replaySource?.input}:${replaySource?.line}`} focus={replaySource || undefined} net={net} dataset={id} times={times} node={filter.node} onAuth={onAuth} onPoint={(input,line)=>{setProof(null);setSelected(null);setPointer({input,line});}} />
      <PhaseLatency net={net} dataset={id} times={times} node={filter.node} height={filter.height} round={filter.round} onAuth={onAuth} onPoint={(input,line)=>{setProof(null);setSelected(null);setPointer({input,line});}} />
      <LogOverlay net={net} dataset={id} onAuth={onAuth} onEvidence={(p)=>{setSelected(null);setPointer(null);setProof(p)}}/>
      <Pending load={rounds} onAuth={onAuth} />
      {rounds.state === "done" && rounds.data && <RoundSummary data={rounds.data} onPoint={(input, line) => { const e = data?.events.find((e) => e.input === input && e.line === line); if (e) select(e); else {setSelected(null);setPointer({input,line});} }} />}
    </>}
  </section>;
}
export function Swimlanes({ events, nodes, from, to, selected, onSelect }: { events: LogEvent[]; nodes: string[]; from: string; to: string; selected: LogEvent | null; onSelect: (e: LogEvent) => void }) {
  const laneNodes=selected&&!nodes.includes(selected.node)?[...nodes,selected.node]:nodes;
 const visible=selected&&!events.some((e)=>eventKey(e)===eventKey(selected))?[...events,selected]:events;
 const points = eventLayout(visible, laneNodes, from, to);
  return <svg className="swimlanes" viewBox={`0 0 1000 ${Math.max(150, laneNodes.length * 58 + 70)}`} role="img" aria-label="WBFT node event swimlanes">
    {laneNodes.map((node, i) => <g key={node}><text x={10} y={56 + i * 58}>{node}</text><line className="lane" x1={140} x2={960} y1={52 + i * 58} y2={52 + i * 58} /></g>)}
    {[0, 0.25, 0.5, 0.75, 1].map((v) => <g key={v}><line className="tick" x1={140 + 820 * v} x2={140 + 820 * v} y1={20} y2={laneNodes.length * 58 + 20} /><text x={140 + 820 * v} y={laneNodes.length * 58 + 50} textAnchor="middle">{new Date(Date.parse(from) + v * (Date.parse(to) - Date.parse(from))).toISOString().slice(11, 23)}</text></g>)}
    {points.map(({ event: e, x, y }) => <circle key={eventKey(e)} className={`${eventClass(e)} ${selected && eventKey(selected) === eventKey(e) ? "event-selected" : ""}`} cx={x} cy={y} r={selected && eventKey(selected) === eventKey(e) ? 6 : 3} tabIndex={0} role="button" aria-label={`${e.node} ${e.kind} ${e.input}:${e.line}`} onClick={() => onSelect(e)} onKeyDown={(k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); onSelect(e); } }}><title>{e.kind} {e.node} h={e.height || "unknown"} r={e.round || "unknown"} {e.input}:{e.line}</title></circle>)}
  </svg>;
}
function RoundSummary({ data, onPoint }: { data: Schemas["RoundsSummary"]; onPoint: (input: string, line: number) => void }) {
  return <details><summary>Round distribution and cause evidence</summary><p>Decision claims are deduplicated per node and height, and remain separate by node/profile. They do not pool repeated observations of the same network height. Unknown decision rounds: {data.unknown_decisions}. Causes inferred from logs are marked log_correlated; unknown is preserved.</p><table><thead><tr><th>Node / profile</th><th>Round</th><th>Decision claims</th></tr></thead><tbody>{data.decisions.map((b) => <tr key={`${b.node}:${b.profile}:${b.round}`}><td>{b.node} / {b.profile}</td><td>{b.round}</td><td>{b.count}</td></tr>)}</tbody></table><table><thead><tr><th>Node</th><th>Height / round</th><th>Proposer</th><th>Cause / strength</th><th>Source</th></tr></thead><tbody>{data.transitions.map((t) => <tr key={`${t.input}:${t.line}`}><td>{t.node}</td><td>{t.height} / {t.round}</td><td className="mono">{t.proposer || "unknown"}</td><td>{t.cause} / {t.confidence}</td><td><button type="button" onClick={() => onPoint(t.input, t.line)}>{t.input}:{t.line}</button>{t.cause_line > 0 && ` ← ${t.cause_input}:${t.cause_line}`}</td></tr>)}</tbody></table>{data.transitions_omitted > 0 && <p>{data.transitions_omitted} additional transitions are counted but omitted. Narrow the window or use ROUND_ENTER event cursor pages.</p>}</details>;
}

function LogOverlay({net,dataset,onAuth,onEvidence}:{net:number;dataset:number;onAuth:()=>void;onEvidence:(p:{report:string;observation:string;index:number})=>void}){
 const observations=useLoad(async()=>{
  const reports=(await get("/v1/reports",{query:{net}})).reports;
  const groups=await Promise.all(reports.map(async(r)=>({report:r.id,rows:(await get("/v1/reports/{id}/observations",{path:{id:r.id}})).observations})));
  return groups.flatMap((g)=>g.rows.filter((o)=>o.evidence.some((e)=>e.kind==="log"||e.kind==="event")).map((o)=>({...o,report:g.report})));
 },[net,dataset]);
 return <details><summary>Inspector log evidence</summary><p>Source jumps require the same network, file SHA256, node and original line. Missing or ambiguous sources remain unavailable; an input name alone is insufficient.</p><Pending load={observations} onAuth={onAuth}/>{observations.state==="done"&&<table><thead><tr><th>Observation / node</th><th>Count</th><th>Original evidence</th></tr></thead><tbody>{observations.data.map((o)=><tr key={`${o.report}:${o.id}`}><td>{o.kind} / {o.node || "network"}</td><td>{o.count}</td><td>{o.evidence.map((e,index)=>(e.kind==="log"||e.kind==="event")?<button type="button" key={index} onClick={()=>onEvidence({report:o.report,observation:o.id,index})}>{e.input}:{e.line}</button>:null)}</td></tr>)}</tbody></table>}</details>;
}
