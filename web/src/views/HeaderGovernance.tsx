import {useState} from "react";
import {get,type Schemas} from "../api/client";
import {governanceSourceLink} from "../governanceLink";
import {Pending,useLoad} from "../ui";
import {ExecutionKeyStatus} from "./GovernanceExecutionState";

export function HeaderGovernance({net,index,onAuth}:{net:number;index:string;onAuth:()=>void}){
 const [open,setOpen]=useState(false),[revision,refresh]=useState(0);
 const load=useLoad(()=>open?get("/v1/networks/{net}/headers/{index}/governance",{path:{net,index}}):Promise.resolve(null),[net,index,open,revision]);
 return <section aria-label={`Governance claims for header ${index}`} className="gov-detail"><h3>Governance source claims</h3>
  <button type="button" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?"Hide governance claims":"Inspect governance claims"}</button>
  {open&&<><button type="button" onClick={()=>refresh(revision+1)}>Refresh governance claims</button><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&load.data&&<HeaderGovernanceResult net={net} value={load.data}/>}</>}
 </section>;
}

export function HeaderGovernanceResult({net,value}:{net:number;value:Schemas["StoreHeaderGovernanceClaims"]}){
 return <><p>Claims match this network's exact canonical block index {value.index} and hash {value.hash}. Execution cause remains unestablished.</p>
  {!value.claims.length&&<p>No exact-hash governance claims are currently stored for this header. This does not establish that no operation occurred or that history is complete.</p>}
  {value.truncated&&<p>Only the first 20 source claims are shown; additional captures are not listed.</p>}
  {value.claims.length>0&&<ul>{value.claims.map(c=><li key={`${c.dataset_id}:${c.call_ordinal}:${c.entry_ordinal}`}><a href={governanceSourceLink(net,{dataset:c.dataset_id,call:c.call_ordinal,entry:c.entry_ordinal,collection:"changes",snapshot:c.snapshot})}>{c.dataset_name} · request {c.call_ordinal} · row {c.entry_ordinal}</a><p>Source node {c.node} · normalized pointer {c.normalized_pointer}.</p>{c.epoch&&<><p>Epoch candidates {c.epoch.candidates}; validators {c.epoch.validators}; added {c.epoch.added}; removed {c.epoch.removed}.</p><ExecutionKeyStatus epoch={c.epoch}/></>}</li>)}</ul>}
 </>;
}
