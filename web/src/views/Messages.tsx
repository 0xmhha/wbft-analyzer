import { useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { TimerEvidence } from "./TimerEvidence";
import { Pending, useLoad } from "../ui";

type Filter = { input: string; type: string; node: string; phase:string; height: string; round: string };
const empty: Filter = { input: "", type: "", node: "", phase:"", height: "", round: "" };

export function Messages({net,onAuth}:{net:number;onAuth:()=>void}) {
 const datasets=useLoad(async()=>(await get("/v1/networks/{net}/datasets",{path:{net}})).datasets.filter((d)=>d.kind==="messages"),[net]);
 const [chosen,choose]=useState(0);
 const id=chosen || (datasets.state==="done"?datasets.data.at(-1)?.id:0) || 0;
 const run=datasets.state==="done"?datasets.data.find((d)=>d.id===id):undefined;
 const [draft,setDraft]=useState<Filter>(empty);
 const [filter,setFilter]=useState<Filter>(empty);
 const [cursors,setCursors]=useState<string[]>([]);
 const [selected,select]=useState<Schemas["MessagesRecord"]|null>(null);
 const inputs=useLoad(async()=>id?get("/v1/networks/{net}/datasets/{dataset}/messages/inputs",{path:{net,dataset:id}}):null,[net,id]);
 const cursor=cursors.at(-1);
 const page=useLoad(async()=>id?get("/v1/networks/{net}/datasets/{dataset}/messages/records",{path:{net,dataset:id},query:{...Object.fromEntries(Object.entries(filter).filter(([,v])=>v)),limit:100,...(cursor?{cursor}:{})}}):null,[net,id,JSON.stringify(filter),cursor]);
 const data=page.state==="done"?page.data:null;
 const changeDataset=(n:number)=>{choose(n);setDraft(empty);setFilter(empty);setCursors([]);select(null)};
 const clock=(run?.metadata as {clock?:{model?:string;skew_ms?:number}}|null)?.clock;
 return <section>
  <h1>Which WBFT messages were recorded?</h1>
  <p>Journal and R-01 frame records retain their original source positions. Unknown peers, missing payloads, gaps and clock regressions stay visible. A recovered signer has not been checked for validator membership.</p>
  <Pending load={datasets} onAuth={onAuth}/>
  {datasets.state==="done" && (datasets.data.length ? <label>Message dataset <select value={id} onChange={(e)=>changeDataset(Number(e.target.value))}>{datasets.data.map((d)=><option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label> : <p>No message dataset yet.</p>)}
  {run && <p>{run.status} · {run.progress.toLocaleString()} stored records · clock {clock?.model||"unknown"}{clock?.skew_ms!==undefined?` ±${clock.skew_ms} ms`:""}{run.error && <span className="error"> · {run.error}</span>}</p>}
  <Pending load={inputs} onAuth={onAuth}/>
  {inputs.state==="done"&&inputs.data&&<details><summary>Source hashes and coverage diagnostics</summary><div className="table-scroll"><table><thead><tr><th>Input / recording node</th><th>Records / frames / decoded</th><th>Undecoded / unknown peer</th><th>Gap records / sequence gaps / partial runs / clock regressions</th><th>SHA256</th></tr></thead><tbody>{inputs.data.inputs.map((i)=><tr key={i.summary.id}><td>{i.summary.id} · {i.summary.kind}<br/>{i.summary.node}</td><td>{i.stats.records} / {i.stats.frames} / {i.stats.decoded}</td><td>{i.stats.undecoded} / {i.stats.unknown_peers}</td><td>{i.stats.gap_records} / {i.stats.sequence_gaps} / {i.summary.kind === "journal" ? i.stats.partial_runs : "unavailable"} / {i.stats.clock_diagnostics === "recorded_sequence" ? i.stats.clock_regressions : "unavailable (export order)"}</td><td className="mono">{i.summary.sha256}<details><summary>Original files</summary>{i.summary.files.map((f)=><p key={f.name}>{f.name} · {f.bytes} bytes · {f.sha256}</p>)}</details></td></tr>)}</tbody></table></div></details>}
  {id>0&&<form className="controls" onSubmit={(e)=>{e.preventDefault();setFilter(draft);setCursors([]);select(null)}}>
   <label>Input <select value={draft.input} onChange={(e)=>setDraft({...draft,input:e.target.value})}><option value="">All inputs</option>{inputs.state==="done"&&inputs.data?.inputs.map((i)=><option key={i.summary.id}>{i.summary.id}</option>)}</select></label>
   <label>Record type <select value={draft.type} onChange={(e)=>setDraft({...draft,type:e.target.value})}><option value="">All types</option>{["frame","outcome","conn","send_suppressed","segment","step","gap","timer_operation"].map((t)=><option key={t}>{t}</option>)}</select></label>
   <label>Phase <select value={draft.phase} onChange={(e)=>setDraft({...draft,phase:e.target.value})}><option value="">All phases</option>{["PRE-PREPARE","PREPARE","COMMIT","ROUND-CHANGE"].map((p)=><option key={p}>{p}</option>)}</select></label>
 <label>Node <select value={draft.node} onChange={(e)=>setDraft({...draft,node:e.target.value})}><option value="">All nodes</option>{run?.nodes.map((n)=><option key={n}>{n}</option>)}</select></label>
 <label>Full height <input value={draft.height} onChange={(e)=>setDraft({...draft,height:e.target.value})}/></label>
   <label>Full round <input value={draft.round} onChange={(e)=>setDraft({...draft,round:e.target.value})}/></label>
   <button>Apply filters</button><button type="button" onClick={()=>{setDraft(empty);setFilter(empty);setCursors([]);select(null)}}>Clear filters</button>
  </form>}
  <Pending load={page} onAuth={onAuth}/>
  {data&&<><p>{data.records.length} records on this page, ordered by original source position.</p><div className="table-scroll"><table><thead><tr><th>Source / original seq</th><th>Type / direction / phase</th><th>Node / peer</th><th>Full height / round</th><th>Decode / write / outcome</th><th>Clock source / wall / monotonic</th></tr></thead><tbody>{data.records.map((r)=><tr key={`${r.input}:${r.file}:${r.ordinal}`}><td><button type="button" onClick={()=>select(r)}>{r.input}:{r.file}:{r.ordinal}</button><br/>seq {r.seq}{r.offset!==undefined?` · byte ${r.offset}`:""}</td><td>{r.type} / {r.timer_operation?.action||r.dir||"—"} / {r.timer_operation?.timer||r.phase||"—"}</td><td>{r.node}<br/>{r.type==="timer_operation"?"local scheduler":r.peer||"unknown"}</td><td>{r.height||"unknown"} / {r.round||"unknown"}</td><td>{r.timer_operation?.decode||r.decode||"—"} / {r.write||"unknown"} / {r.outcome||"—"}</td><td>{r.clock_source||"unavailable"}<br/>{r.t_wall||"unknown"}<br/>{r.t_mono_ns??"unknown"}</td></tr>)}</tbody></table></div><div className="controls"><button type="button" disabled={!cursors.length} onClick={()=>{setCursors(cursors.slice(0,-1));select(null)}}>Previous page</button><button type="button" disabled={!data.next} onClick={()=>{if(data.next)setCursors([...cursors,data.next]);select(null)}}>Next page</button></div></>}
  {selected&&<aside><h2>Recorded message evidence</h2><p>{selected.input}:{selected.file}:{selected.ordinal} · original seq {selected.seq}</p><TimerEvidence operation={selected.timer_operation}/><pre>{JSON.stringify(selected,null,2)}</pre></aside>}
 </section>;
}
