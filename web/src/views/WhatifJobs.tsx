import { useEffect, useRef, useState } from "react";
import { ApiError, get, post, type Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";
type Job=Schemas["StoreWhatifJob"];
export function WhatifJobs({net,dataset,refresh,onAuth,onResult,onFinished}:{net:number;dataset:number;refresh:number;onAuth:()=>void;onResult:(id:number)=>void;onFinished:()=>void}) {
 const finished=useRef(new Set<number>());
 const sources=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/reexec-sources",{path:{net,dataset}}),[net,dataset,refresh]);
 const [source,setSource]=useState(""),[request,setRequest]=useState("2"),[maximum,setMaximum]=useState("");
 const [sending,setSending]=useState(false),[error,setError]=useState(""),[reload,setReload]=useState(0),[jobs,setJobs]=useState<Job[]>([]);
 useEffect(()=>{
  let live=true;let timer:ReturnType<typeof setTimeout>;
  const load=async()=>{try {
   const result=await get("/v1/networks/{net}/datasets/{dataset}/whatif-jobs",{path:{net,dataset}});
   if(!live)return;setJobs(result.jobs);
 const newlyFinished=result.jobs.filter(j=>j.status!=="queued"&&j.status!=="running"&&!finished.current.has(j.id));
 for(const job of newlyFinished)finished.current.add(job.id);
 if(newlyFinished.length)onFinished();
   if(result.jobs.some(j=>j.status==="queued"||j.status==="running"))timer=setTimeout(load,2000);
  }catch(e){if(!live)return;setError(e instanceof Error?e.message:"Unable to load experiment jobs.");if(e instanceof ApiError&&e.status===401)onAuth();}};
  void load();return ()=>{live=false;clearTimeout(timer)};
 },[net,dataset,refresh,reload,onAuth]);
 const available=sources.state==="done"?sources.data.sources.filter(s=>s.allow_timer):[];
 const chosen=available.find(s=>s.id===source)??available[0];
 async function submit(){
  if(!chosen||sending)return;setSending(true);setError("");
  try {
   const timer_policy={request_timeout_seconds:request,...(maximum!==""?{max_request_timeout_seconds:maximum}:{})};
   const job=await post("/v1/networks/{net}/datasets/{dataset}/whatif",{net,dataset},{source_id:chosen.id,timer_policy});
   setJobs(old=>[job,...old].slice(0,100));setReload(n=>n+1);
  }catch(e){setError(e instanceof Error?e.message:"Unable to queue experiment.");if(e instanceof ApiError&&e.status===401)onAuth();}
  finally{setSending(false)}
 }
 return <section aria-label="Timer experiment jobs"><h3>Start a timer experiment</h3><Pending load={sources} onAuth={onAuth}/>{sources.state==="done"&&(!sources.data.enabled||!chosen)?<p>No timer source is enabled for this dataset. Stored results remain available.</p>:chosen&&<form className="controls" onSubmit={e=>{e.preventDefault();void submit()}}>
 <label>Retained timer source <select value={chosen.id} onChange={e=>setSource(e.target.value)} disabled={sending}>{available.map(s=><option key={s.id} value={s.id}>{s.id} · {s.input_id}</option>)}</select></label>
 <label>Request timeout seconds <input required inputMode="numeric" pattern="[1-9][0-9]*" value={request} onChange={e=>setRequest(e.target.value)} disabled={sending}/></label>
 <label>Maximum timeout seconds <input inputMode="numeric" pattern="0|[1-9][0-9]*" placeholder="Preserve source policy" value={maximum} onChange={e=>setMaximum(e.target.value)} disabled={sending}/></label>
 <p>Counterfactual: the full recorded input is used, with fixed external slots, zero generated processing cost and recorded signing results. New network reactions are unknown.</p>
 <button type="submit" disabled={sending}>{sending?"Queueing experiment…":"Queue timer experiment"}</button></form>}
 {error&&<p role="alert" className="error">{error}</p>}
 <p role="status">{jobs.filter(j=>j.status==="queued").length} queued · {jobs.filter(j=>j.status==="running").length} running. Job success covers the recorded source horizon.</p>
 {jobs.length>0&&<table><thead><tr><th>Job</th><th>Input</th><th>Policy</th><th>Status</th><th>Result</th></tr></thead><tbody>{jobs.map(j=><tr key={j.id}><td>{j.id}</td><td>{j.input_id}</td><td>{j.timer_policy.request_timeout_seconds??"preserved"} / {j.timer_policy.max_request_timeout_seconds??"preserved"} seconds</td><td>{j.status}{j.issue&&<><br/>{j.issue}</>}</td><td>{j.whatif_id!=null&&<button type="button" onClick={()=>onResult(j.whatif_id!)}>Open experiment {j.whatif_id}</button>}</td></tr>)}</tbody></table>}
 </section>;
}
