import { useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

type Record = Schemas["MessagesRecord"];
type Point = Schemas["MessagesOwnSourcePoint"];
type Focus = "declaration"|"request";
const flag = (value:boolean|null|undefined) => value===true?"yes":value===false?"no":"unknown";

export function getSyncSource(net:number,dataset:number,point:Point) {
 return get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:point.input,file:point.file,ordinal:String(point.ordinal)}});
}

export function matchesSyncSource(parent:Record,source:Record,kind:Focus) {
 const proof=parent.sync_evidence;
 const point=kind==="declaration"?proof?.declaration:proof?.request;
 if(!proof||typeof proof.complete!=="boolean"||!point||!point.seq||point.seq==="0"||point.ordinal<=0||source.input!==point.input||source.file!==point.file||source.ordinal!==point.ordinal||source.seq!==point.seq||source.node!==parent.node||source.run!==parent.run)return false;
 if(kind==="declaration")return ["segment","scheduler_trace","cache_trace","sync_trace"].includes(source.type)&&source.sync_trace?.version==="1"&&source.sync_trace.event_cursor==="next_sequence"&&typeof source.sync_trace.complete==="boolean"&&source.sync_trace.complete===proof.complete;
 const control=parent.sync_control,original=source.sync_control,ref=control?.request_source;
 return proof.complete&&control?.stage==="processed"&&control.request!=="0"&&typeof control.syncing==="boolean"&&typeof control.success==="boolean"&&ref?.source_available===true&&source.type==="sync_control"&&original?.stage==="requested"&&original.request===control.request&&original.syncing===control.syncing&&original.success===control.success&&source.seq===ref.source_seq&&source.journal_position?.segment===ref.source_segment&&source.journal_position?.offset===ref.source_offset;
}

export function SyncControlEvidence({net,dataset,record,onAuth}:{net:number;dataset:number;record:Record;onAuth:()=>void}) {
 const [focus,setFocus]=useState<Focus|null>(null);
 const proof=record.sync_evidence,control=record.sync_control,trace=record.sync_trace;
 const point=focus==="declaration"?proof?.declaration:focus==="request"?proof?.request:null;
 const original=useLoad(async()=>point?getSyncSource(net,dataset,point):null,[net,dataset,point?.input,point?.file,point?.ordinal]);
 if(!control&&!trace)return null;
 const source=original.state==="done"?original.data:null;
 const matches=!!source&&!!focus&&matchesSyncSource(record,source,focus);
 const canOpenRequest=control?.stage==="processed"&&proof?.complete===true&&!!proof.request&&control.request_source?.source_available===true;
 return <section className="sync-evidence" aria-label="Recorded sync controls">
  <h3>Recorded sync controls</h3>
  <p>These are application notifications and recorded node actions. Source coverage does not decide consensus conformance or independently verify the downloader.</p>
  {trace&&<p>Snapshot version {trace.version}: {trace.requests} notifications · {trace.operations} handling records · {trace.complete===true?"complete recorded source":trace.complete===false?"incomplete recorded source":"source coverage unknown"}. The snapshot has no measured clock.</p>}
  {control&&<>
   <p>{control.stage==="requested"?"Submitted notification":"Actual node handling"} · request <code>{control.request==="0"?"unavailable (recorded 0)":control.request}</code>{control.stage==="processed"&&<> · handling <code>{control.operation==="0"?"unavailable (recorded 0)":control.operation}</code></>}.</p>
   <p>Sync in progress: {flag(control.syncing)} · completion marked successful: {flag(control.success)}.</p>
   {control.stage==="requested"&&<p>Engine and guard state are not measured on submitted notifications.</p>}
   {control.stage==="processed"&&<>
    <p>First successful sync seen (recorded guard): {flag(control.first_before)} → {flag(control.first_after)}. Engine running (recorded): {flag(control.running_before)} → {flag(control.running_after)}.</p>
    <p>{control.action==="none"?"No engine control call":`${control.action} attempted`} · call error recorded: {flag(control.failed)}.</p>
    {control.events_available===true?<p>Recorded event cursor range <code>[{control.event_before}, {control.event_after})</code>. These are next-sequence bounds around the control call, separate from journal seq {record.seq}. Matching the original event stream requires its own source validation.</p>:<p>{control.action==="none"?"No control call; no event cursor range was recorded.":"Event cursor range unavailable for this call."}</p>}
    <p>{canOpenRequest?"Exact submitted request metadata retained.":"Exact submitted request source unavailable; no coordinates were inferred."}</p>
   </>}
   {control.sequence_exhausted===true&&<p className="error">Control identity sequence exhausted; source relationship unavailable.</p>}
   <p>Observation clock: {record.t_mono_ns??"unavailable"} ns · {record.t_wall||"unavailable"}.</p>
   {proof&&<p>{proof.complete?"Complete recorded context":"Incomplete recorded context"}. A complete context can include superseded notifications or repeated handling of one request.</p>}
  </>}
  <div className="controls">{proof&&<button type="button" aria-pressed={focus==="declaration"} onClick={()=>setFocus("declaration")}>Open sync snapshot source</button>}{canOpenRequest&&<button type="button" aria-pressed={focus==="request"} onClick={()=>setFocus("request")}>Open original sync request</button>}</div>
  {point&&<aside key={`${focus}:${point.input}:${point.file}:${point.ordinal}`} className="sync-original" aria-label="Original sync source"><h4>{focus} source: {point.file}:{point.ordinal}</h4><Pending load={original} onAuth={onAuth}/>{source&&<><p className={matches?undefined:"error"}>{matches?"Original metadata matches the recorded source link.":"Original metadata does not match this sync source link."}</p><pre>{JSON.stringify(source,null,2)}</pre></>}</aside>}
 </section>;
}
