import { useState } from "react";
import { get,type Schemas } from "../api/client";
import { Pending,useLoad } from "../ui";

type Model=Schemas["ScenarioProcessingModel"];
type Timing=Schemas["ScenarioProcessingTimings"];
type Point=Schemas["ScenarioProcessingPoint"];
type Sample=Schemas["ScenarioProcessingSample"];
type Focus={input:string;point:Point;sample?:Sample};
const noAuth=()=>{};

function Samples({timing,onSource,enabled}:{timing:Timing;onSource:(s:Focus)=>void;enabled:boolean}){
 const [page,setPage]=useState(0);
 const [excludedPage,setExcludedPage]=useState(0);
 const counts=new Map<string,string[]>();
 for(const sample of timing.samples){const key=`${sample.kind} · code ${sample.code}`,values=counts.get(key);if(values)values.push(sample.nanoseconds);else counts.set(key,[sample.nanoseconds])}
 return <details><summary>{timing.source.id}: {timing.samples.length} measured intervals · {timing.excluded.length} exclusions · {timing.status}</summary>
  <p>{timing.source.node}<br/>Source SHA256 {timing.source.sha256}<br/>Scope: {timing.scope} · heights {timing.from}–{timing.to}</p>
  <table><thead><tr><th>Work class</th><th>Samples</th><th>Minimum / lower median / maximum ns</th></tr></thead><tbody>{[...counts].map(([kind,values])=>{const sorted=values.map(BigInt).sort((a,b)=>a<b?-1:a>b?1:0);return <tr key={kind}><td>{kind}</td><td>{sorted.length}</td><td>{String(sorted[0])} / {String(sorted[Math.floor((sorted.length-1)/2)])} / {String(sorted.at(-1))}</td></tr>})}</tbody></table>
  <p>Descriptive measured ranges; not confidence intervals or a physical processing guarantee.</p>
  <table><thead><tr><th>Original source</th><th>Writer / engine / step</th><th>Input class</th><th>Measured entry / completion ns</th><th>Interval ns</th></tr></thead><tbody>{timing.samples.slice(page*100,(page+1)*100).map((s,i)=><tr key={i}><td><button disabled={!enabled} onClick={()=>onSource({input:timing.source.id,point:s.point,sample:s})}>Open timing source {s.point.ordinal}</button><br/>{s.point.file}</td><td>{s.point.writer_run} / {s.point.engine_run} / {s.point.step}<br/>head + 1: {s.point.height}</td><td>{s.kind} · {s.code}</td><td>{s.entry_mono_ns} / {s.complete_mono_ns}</td><td>{s.nanoseconds}</td></tr>)}</tbody></table>
  <p>Measured intervals {timing.samples.length?page*100+1:0}–{Math.min((page+1)*100,timing.samples.length)} of {timing.samples.length}</p><button disabled={page===0} onClick={()=>setPage(p=>p-1)}>Previous timing page</button><button disabled={(page+1)*100>=timing.samples.length} onClick={()=>setPage(p=>p+1)}>Next timing page</button>
  <details><summary>Excluded timing sources ({timing.excluded.length})</summary><p>Source positions {timing.excluded.length?excludedPage*100+1:0}–{Math.min((excludedPage+1)*100,timing.excluded.length)} of {timing.excluded.length}; all exclusions remain in stored model evidence.</p>{timing.excluded.slice(excludedPage*100,(excludedPage+1)*100).map((s,i)=><p key={i}><button disabled={!enabled} onClick={()=>onSource({input:timing.source.id,point:s.point})}>Open excluded source {s.point.ordinal}</button> · {s.kind} · {s.reason}<br/>{s.point.writer_run}/{s.point.engine_run}/{s.point.step} · {s.point.file}</p>)}<button disabled={excludedPage===0} onClick={()=>setExcludedPage(p=>p-1)}>Previous exclusion page</button><button disabled={(excludedPage+1)*100>=timing.excluded.length} onClick={()=>setExcludedPage(p=>p+1)}>Next exclusion page</button></details>
  <details><summary>Measurement assumptions</summary><ul>{timing.assumptions.map(a=><li key={a}>{a.replaceAll("_"," ")}</li>)}</ul></details>
 </details>;
}

export function ProcessingEvidence({model,net,dataset,onAuth=noAuth}:{model?:Model|null;net?:number;dataset?:number;onAuth?:()=>void}){
 const [focus,setFocus]=useState<Focus|null>(null);
 const original=useLoad(async()=>!focus||!net||!dataset?null:get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:focus.input,file:focus.point.file,ordinal:focus.point.ordinal}}),[net,dataset,focus]);
 if(!model)return null;
 const matches=focus&&original.state==="done"&&original.data&&original.data.type==="step"&&original.data.run===focus.point.writer_run&&original.data.engine_run===focus.point.engine_run&&original.data.step===focus.point.step&&(!focus.sample||original.data.entry_t_mono_ns===focus.sample.entry_mono_ns&&original.data.t_mono_ns===focus.sample.complete_mono_ns);
 return <section aria-label="Processing service evidence"><h3>Recorded processing intervals and service policy</h3><p>Policy: {model.policy} · declared receive workers: {model.declared_receive_workers} (unmeasured).</p><p>Measured whole-step intervals charge service before atomic dispatch. Internal CPU, WAL, signing and output stages are not reconstructed. Unmeasured receive checks, frame-only substitutes and unlisted classes retain zero cost.</p><details><summary>Processing model assumptions</summary><ul>{model.assumptions.map(a=><li key={a}>{a.replaceAll("_"," ")}</li>)}</ul></details>{model.timings.map(t=><Samples key={t.source.id} timing={t} onSource={setFocus} enabled={!!net&&!!dataset}/>)}
  {focus&&<aside aria-label="Original processing timing record"><h4>Original timing record {focus.input}:{focus.point.file}:{focus.point.ordinal}</h4><Pending load={original} onAuth={onAuth}/>{original.state==="done"&&original.data&&<><p>{matches?"Original writer, engine, step and available timing coordinates match.":"Original record does not match the stored timing coordinates."}</p><pre>{JSON.stringify(original.data,null,2)}</pre></>}</aside>}
 </section>;
}
