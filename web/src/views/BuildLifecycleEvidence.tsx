import { get } from "../api/client";
import type { Schemas } from "../api/client";
import type { LogEvent } from "../events";
import { Pending, useLoad } from "../ui";

const kinds = new Set(["BUILD_HANDOVER", "BUILD_STARTED", "BUILD_FINISHED"]);
export function BuildLifecycleEvidence({ net, dataset, source, onAuth, onSelect }: { net:number; dataset:number; source:LogEvent; onAuth:()=>void; onSelect:(input:string,line:number)=>void }) {
 const enabled=kinds.has(source.kind);
 const load=useLoad(async()=>enabled?get("/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}/build",{path:{net,dataset,input:source.input,line:source.line}}):null,[net,dataset,source.input,source.line,enabled]);
 if(!enabled)return null;
 return <section><h3>What happened to this build request?</h3><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&load.data&&<BuildLifecycleDetails evidence={load.data} onSelect={onSelect}/>}</section>;
}
export function BuildLifecycleDetails({ evidence, onSelect }: { evidence:Schemas["StoreBuildLifecycle"]; onSelect:(input:string,line:number)=>void }) {
 return <div className="build-lifecycle"><p>{evidence.build_id || "Build identity unavailable"} · observed lifecycle: {evidence.state} · return: {evidence.status || "unavailable"}</p><p>{evidence.assembly_ns!==null?`Assembly start to submission: ${evidence.assembly_ns} ns.`:"Assembly interval unavailable."} Submission records the application handover to consensus.</p>{evidence.state!=="complete"&&<p>Incomplete or duplicate source candidates remain visible. No unique assembly interval is inferred.</p>}<ol>{evidence.events.map(e=><li key={`${e.input}:${e.line}`}><button type="button" onClick={()=>onSelect(e.input,e.line)}>{e.input}:{e.line} · {e.kind}</button> · height {e.height} / round {e.round} · {e.t_mono_ns!==undefined?`${e.t_mono_ns} ns`:"monotonic clock unavailable"}</li>)}</ol></div>;
}
