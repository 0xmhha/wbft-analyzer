import {useEffect,useState} from "react";
import {ApiError,get,type Schemas} from "../api/client";
import {Pending,useLoad} from "../ui";

type Detail=Schemas["StoreReconstructionDetail"];
type Step=Schemas["StoreReconstructionStep"];
type Projection=Schemas["ReconstructProjection"];

export function Reconstruction({net,onAuth}:{net:number;onAuth:()=>void}) {
 const [dataset,setDataset]=useState(0),[refresh,setRefresh]=useState(0);
 const load=useLoad(async()=>(await get("/v1/networks/{net}/datasets",{path:{net}})).datasets.filter(d=>d.kind==="run"&&d.status==="complete"),[net,refresh]);
 return <section><h1>Reconstructed core comparison</h1><p>Compare observed processing inputs with the WBFT core, with all improvements disabled. Results are cross-implementation difference candidates. A completed comparison does not decide specification compliance.</p><button type="button" onClick={()=>setRefresh(n=>n+1)}>Refresh results</button><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<><label>Log dataset <select value={dataset} onChange={e=>setDataset(Number(e.target.value))}><option value={0}>Select a dataset</option>{load.data.map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select></label>{dataset>0&&<Runs key={dataset} net={net} dataset={dataset} refresh={refresh} onAuth={onAuth}/>}</>}</section>;
}
function Runs({net,dataset,refresh,onAuth}:{net:number;dataset:number;refresh:number;onAuth:()=>void}) {
 const [selected,setSelected]=useState(0);
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/reconstruction",{path:{net,dataset}}),[net,dataset,refresh]);
 return <><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&(load.data.runs.length?<><label>Comparison <select value={selected} onChange={e=>setSelected(Number(e.target.value))}><option value={0}>Select a comparison</option>{load.data.runs.map(r=><option key={r.id} value={r.id}>{r.id}: {r.input_id} · {r.from_height}–{r.to_height} · {r.complete_heights}/{r.heights} complete</option>)}</select></label>{selected>0&&<Run key={selected} net={net} dataset={dataset} id={selected} onAuth={onAuth}/>}</>:<p>No stored reconstruction. Import the original log dataset and store a closed execution with the reconstruct command.</p>)}</>;
}
function Run({net,dataset,id,onAuth}:{net:number;dataset:number;id:number;onAuth:()=>void}) {
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/reconstruction/{reconstruction}",{path:{net,dataset,reconstruction:id}}),[net,dataset,id]);
 return <><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<><ReconstructionSummary run={load.data}/><Execution key={id} net={net} dataset={dataset} run={load.data} onAuth={onAuth}/></>}</>;
}
export function ReconstructionSummary({run}:{run:Detail}) {
 const summary=run.summary;
 return <article><h2>Comparison {run.id}</h2><p>{run.complete_heights}/{run.heights} complete heights · {run.steps} compared inputs · {run.difference_candidates} difference candidates</p><p>Core {summary.core_version} · improvements {summary.all_improvements_off?"all disabled":"unverified"} · comparison model <code>{summary.comparison_model}</code></p><p>Processing-boundary clocks belong to this node. Reconstructed input positions and derived timer generations remain separate from original source sequence numbers and native journal identities.</p><details><summary>Completeness by height</summary><table><thead><tr><th>Active height</th><th>Completeness</th><th>Unavailable evidence</th></tr></thead><tbody>{summary.heights.map(h=><tr key={h.height}><td className="mono">{h.height}</td><td>{h.status}</td><td>{h.issues.join(", ")||"none"}</td></tr>)}</tbody></table></details><details><summary>Verified source identities</summary><dl><dt>Result</dt><dd className="mono">{run.result_sha256}</dd><dt>Log</dt><dd className="mono">{summary.sources.log_sha256}</dd><dt>Processing observations</dt><dd className="mono">{summary.sources.input_observations?.sha256??"unavailable"}</dd></dl></details></article>;
}
function Execution({net,dataset,run,onAuth}:{net:number;dataset:number;run:Detail;onAuth:()=>void}) {
 const [after,setAfter]=useState(0),[height,setHeight]=useState(""),[different,setDifferent]=useState(false),[index,setIndex]=useState(0),[playing,setPlaying]=useState(false);
 const [review,setReview]=useState({busy:false,message:""});
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/reconstruction/{reconstruction}/steps",{path:{net,dataset,reconstruction:run.id},query:{after,limit:50,...(height?{height}:{}),...(different?{different:"true"}:{})}}),[net,dataset,run.id,after,height,different]);
 const rows=load.state==="done"?load.data.steps:[];
 useEffect(()=>{setPlaying(false);setIndex(0)},[after,height,different]);
 useEffect(()=>{if(!playing||load.state!=="done")return;const timer=setInterval(()=>setIndex(i=>{if(i+1>=rows.length){setPlaying(false);return i}return i+1}),800);return()=>clearInterval(timer)},[playing,load.state,rows.length]);
 const step=rows[index];
 async function downloadReview(row:Step) {
  setReview({busy:true,message:""});
  try {
   const packet=await get("/v1/networks/{net}/datasets/{dataset}/reconstruction/{reconstruction}/steps/{position}/review",{path:{net,dataset,reconstruction:run.id,position:row.position}});
   const bytes=new TextEncoder().encode(JSON.stringify(packet,null,2)+"\n");
   const digest=globalThis.crypto?.subtle?Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),v=>v.toString(16).padStart(2,"0")).join(""):undefined;
   const url=URL.createObjectURL(new Blob([bytes],{type:"application/json"}));
   const link=document.createElement("a");link.href=url;link.download=`reconstruction-${run.id}-${row.position}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
   setReview({busy:false,message:`Step ${row.step.input.ordinal} (source ${row.step.input.source.sequence??"unknown"}) saved for independent inspection. ${digest?`File SHA-256: ${digest}`:"File checksum unavailable in this browser context."}`});
  } catch(error) {
   if(error instanceof ApiError&&error.status===401)onAuth();
   setReview({busy:false,message:error instanceof Error?error.message:"Step record unavailable"});
  }
 }
 return <article><h2>Input comparisons</h2><div className="controls"><label>Active height <select value={height} onChange={e=>{setHeight(e.target.value);setAfter(0)}}><option value="">All selected heights</option>{run.summary.heights.map(h=><option key={h.height} value={h.height}>{h.height} · {h.status}</option>)}</select></label><label><input type="checkbox" checked={different} onChange={e=>{setDifferent(e.target.checked);setAfter(0)}}/> Difference candidates only</label><button type="button" disabled={after===0} onClick={()=>setAfter(0)}>First page</button></div><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<>{rows.length?<><div className="controls"><button type="button" disabled={index===0} onClick={()=>{setPlaying(false);setIndex(i=>i-1)}}>Previous input</button><button type="button" disabled={index+1>=rows.length} onClick={()=>setPlaying(p=>!p)}>{playing?"Pause":"Play this page"}</button><button type="button" disabled={index+1>=rows.length} onClick={()=>{setPlaying(false);setIndex(i=>i+1)}}>Next input</button></div><div className="reconstruction-strip" aria-label="Reconstructed input order">{rows.map((row,i)=><button type="button" key={row.position} className={`reconstruction-tick ${row.step.difference_candidates.length?"different":row.step.core_applied?"applied":"unavailable"}${i===index?" selected":""}`} aria-label={`Select input ${row.step.input.ordinal}, source ${row.step.input.source.sequence??"unknown"}${row.step.difference_candidates.length?", difference candidate":""}`} aria-pressed={i===index} onClick={()=>{setPlaying(false);setIndex(i)}}>{row.step.input.ordinal}</button>)}</div>{step&&<><button type="button" disabled={review.busy} onClick={()=>void downloadReview(step)}>{review.busy?"Preparing step record…":"Download step for inspection"}</button>{review.message&&<p role="status" className="mono">{review.message}</p>}<ReconstructionStep row={step}/></>}</>:<p>No compared inputs for these filters. Missing evidence remains visible in the height assessment.</p>}{load.data.next!==null&&<button type="button" onClick={()=>setAfter(load.data.next!)}>Next page</button>}</>}</article>;
}
export function ReconstructionStep({row}:{row:Step}) {
 const step=row.step,input=step.input;
 return <section className="reconstruction-selected" key={row.position} aria-label={`Reconstructed input ${input.ordinal}`}><h3>Reconstructed input {input.ordinal}: {input.kind}</h3><p>Active height {row.height} · round {input.round} · {step.core_applied?"core applied":"core stopped before completing this input"}</p><p>Original source {input.source.file}, line {input.source.line??"unknown"}, sequence {input.source.sequence??"unknown"} · observation instance {input.observation_instance??"unavailable"} · log run {row.log_run}</p><p>Binding: {input.via} · processing boundary {input.processing_mono_ns??"unavailable"} ns{input.derived_timer_generation&&<> · derived timer generation {input.derived_timer_generation}</>}</p>{step.issues.length>0&&<p className="error">{step.issues.join(", ")}</p>}<table><caption>Observable state and actions</caption><thead><tr><th>Observed</th><th>Computed</th></tr></thead><tbody>{Array.from({length:Math.max(step.observed.length,step.computed.length)},(_,i)=><tr key={i}><td><Projection value={step.observed[i]}/></td><td><Projection value={step.computed[i]}/></td></tr>)}</tbody></table><p>Rows retain each side's order; difference candidates compare actions within their own classes. Packet delivery, signatures and application import success are outside this comparison model.</p><h4>Cross-implementation difference candidates ({step.difference_candidates.length})</h4>{step.difference_candidates.map((d,i)=><div className="reconstruction-difference" key={i}><strong>{d.kind}</strong><table><thead><tr><th>Expected observation</th><th>Computed</th></tr></thead><tbody><tr><td><Projection value={d.expected}/></td><td><Projection value={d.actual}/></td></tr></tbody></table></div>)}{step.difference_candidates.length===0&&<p>No difference candidate in the fields compared for this input.</p>}<details><summary>Step source pointers for review</summary><pre>{JSON.stringify(step,null,2)}</pre></details></section>;
}
function Projection({value}:{value?:Projection|null}) {
 if(!value)return <span className="muted">unavailable</span>;
 return <dl>{Object.entries(value).filter(([,v])=>v!==undefined).map(([k,v])=><div key={k}><dt>{k}</dt><dd className="mono">{typeof v==="object"?JSON.stringify(v):String(v)}</dd></div>)}</dl>;
}
