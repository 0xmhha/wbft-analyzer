import {useState} from "react";
import {get,type Schemas} from "../api/client";
import {Pending,useLoad} from "../ui";
export function Runtime({net,onAuth}:{net:number;onAuth:()=>void}) {
 const [dataset,setDataset]=useState(0);
 const load=useLoad(()=>get("/v1/networks/{net}/datasets",{path:{net}}),[net]);
 return <section><h1>Runtime call evidence</h1><p>Recorded operation boundaries and startup claims remain separate from consensus events and a complete execution model.</p><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<label>Capture <select value={dataset} onChange={e=>setDataset(Number(e.target.value))}><option value={0}>Select a runtime capture</option>{load.data.datasets.filter(d=>d.kind==="runtime").map(d=><option value={d.id} key={d.id}>{d.name} · {d.status}</option>)}</select></label>}{dataset>0&&<Capture key={dataset} net={net} dataset={dataset} onAuth={onAuth}/>}</section>;
}
function Capture({net,dataset,onAuth}:{net:number;dataset:number;onAuth:()=>void}){
 const [after,setAfter]=useState(0),[call,setCall]=useState("");
 const summary=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/runtime",{path:{net,dataset}}),[net,dataset]);
 const page=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/runtime/calls",{path:{net,dataset},query:{after}}),[net,dataset,after]);
 return <article><Pending load={summary} onAuth={onAuth}/>{summary.state==="done"&&<><p>{summary.data.node} · writer {summary.data.run} · capture {summary.data.capture_complete?"complete":"incomplete"} · {summary.data.point_count} original lines</p><p>Full runtime model, remote delivery, and application request completion remain unproved. Network membership is declared at import.</p>{summary.data.startup?.config&&<p>Startup line {summary.data.startup.line} · height {summary.data.startup.config.height} · request timeout {summary.data.startup.config.request_timeout_ms} ms · block period {summary.data.startup.config.block_period_seconds} s · epoch {summary.data.startup.config.epoch}. These are claims at the recorded startup height.</p>}<p>Source SHA256: <code>{summary.data.source_sha256}</code></p>{summary.data.unavailable.length>0&&<p>{summary.data.unavailable.join(", ")}</p>}</>}<Pending load={page} onAuth={onAuth}/>{page.state==="done"&&<><table><thead><tr><th>Operation</th><th>Return</th><th>Interval (ns)</th><th>Source</th></tr></thead><tbody>{page.data.calls.map(c=><tr key={c.id}><td>{c.operation}</td><td>{c.result}</td><td>{c.nanoseconds}</td><td><button type="button" onClick={()=>setCall(c.id)}>Call {c.id}: {c.start_line}→{c.end_line}</button></td></tr>)}</tbody></table><button type="button" disabled={after===0} onClick={()=>setAfter(Math.max(0,after-100))}>Previous calls</button><button type="button" disabled={page.data.next===null} onClick={()=>{if(page.data.next!==null)setAfter(page.data.next)}}>Next calls</button></>}{call&&<Source key={call} net={net} dataset={dataset} call={call} onAuth={onAuth}/>}</article>;
}
function Source({net,dataset,call,onAuth}:{net:number;dataset:number;call:string;onAuth:()=>void}){
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/runtime/calls/{call}",{path:{net,dataset,call}}),[net,dataset,call]);
 return <section><h2>Exact operation source</h2><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<RuntimeSource evidence={load.data}/>}</section>;
}
export function RuntimeSource({evidence}:{evidence:Schemas["RuntimeCallSource"]}){
 return <div className="runtime-source"><p>Call {evidence.call.id} · {evidence.call.operation} · {evidence.call.result}</p><p>{evidence.node} · {evidence.run}</p><ol>{[evidence.start,evidence.end].map(p=><li key={p.line}>Line {p.line} · {p.type} · {p.t_mono_ns} ns · height {p.height||"unavailable"}</li>)}</ol><p>Observed call interval: {evidence.call.nanoseconds} ns. This is not a consensus acceptance result.</p></div>;
}
