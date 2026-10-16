import { useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

type Record = Schemas["MessagesRecord"];
type Point = Schemas["MessagesOwnSourcePoint"];
type SourceKind = "declaration"|"instance"|"operation";
export function getCacheSource(net:number,dataset:number,point:Point) {
 return get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:point.input,file:point.file,ordinal:String(point.ordinal)}});
}
export function matchesCacheSource(parent:Record,source:Record,kind:SourceKind) {
 const proof=parent.cache_evidence,ref=parent.send_attempt?.cache_decision||parent.cache_decision;
 if(!proof||!ref)return false;
 const p=proof[kind];
 if(source.input!==p.input||source.file!==p.file||source.ordinal!==p.ordinal||source.seq!==p.seq||source.node!==parent.node||source.run!==parent.run)return false;
 if(kind==="declaration")return source.cache_trace?.version==="1"&&source.cache_trace.complete===true;
 if(kind==="instance")return source.cache_instance?.instance===ref.instance&&source.cache_instance.initial_state==="empty"&&source.cache_instance.self===parent.node;
 const op=source.cache_operation;
 return source.type==="cache_operation"&&op?.instance===ref.instance&&op.sequence===ref.operation&&source.seq===ref.source_seq&&source.journal_position?.segment===ref.source_segment&&source.journal_position?.offset===ref.source_offset&&op.dedup_key===parent.dedup_key&&op.cause===parent.cause&&(!parent.payload_sha256||op.payload_sha256===parent.payload_sha256);
}

export function CacheEvidence({net,dataset,record,onAuth}:{net:number;dataset:number;record:Record;onAuth:()=>void}) {
 const [focus,setFocus]=useState<SourceKind|null>(null);
 const proof=record.cache_evidence,ref=record.send_attempt?.cache_decision||record.cache_decision;
 const point=focus&&proof?.[focus];
 const original=useLoad(async()=>point?getCacheSource(net,dataset,point):null,[net,dataset,point?.input,point?.file,point?.ordinal]);
 const trace=record.cache_trace,instance=record.cache_instance,op=record.cache_operation,attempt=record.send_attempt;
 if(!trace&&!instance&&!op&&!attempt&&!ref)return null;
 const source=original.state==="done"?original.data:null;
 const matches=!!source&&!!focus&&matchesCacheSource(record,source,focus);
 return <section className="cache-evidence" aria-label="Cache decision and physical write">
  <h3>Cache decision and physical write</h3>
  <p>Cache operations are ordered within one cache mutex. Enqueue IDs belong to one recording lifetime. Journal sequence and physical write time describe separate observations; none proves delivery.</p>
  <p>Source links open retained metadata. Authenticating byte offsets requires the original journal. Cache behavior verdicts belong to inspector reports.</p>
  {trace&&<p>Snapshot version {trace.version}: {trace.instances} empty-cache declarations · {trace.operations} operations · {trace.complete?"complete recorded context":"incomplete context; cache behavior unavailable"}. A snapshot declaration has no measured clock.</p>}
  {instance&&<p>Cache instance <code>{instance.instance}</code> · initial state {instance.initial_state} · peer capacity {instance.peer_capacity} · message capacity {instance.message_capacity}. The empty-cache declaration has no measured clock.</p>}
  {op&&<><p>Cache instance <code>{op.instance}</code> · mutex operation <code>{op.sequence}</code> · {op.action} / {op.cause||"inbound"} · known hit {String(op.known_hit)} · peer recent hit {String(op.peer_recent_hit)}.</p>
   <p>Operation clock: {record.t_mono_ns??"unavailable"} ns · {record.t_wall||"unavailable"}.</p>
   <details><summary>{op.candidates_available?`${op.candidates.length} candidates: ${op.targets.length} targets, ${op.suppressed.length} suppressed`:"Candidate set unavailable"}</summary><p>Targets: {op.targets.join(", ")||"none"}</p><p>Suppressed: {op.suppressed.join(", ")||"none"}</p></details></>}
  {(attempt||ref)&&<ol className={`cache-source-chain${proof&&attempt?.available?"":" cache-unlinked"}`} aria-label={proof?"Observed source relationship":"Source relationship unavailable"}>
   <li><strong>Cache decision</strong><span>{ref?`instance ${ref.instance} / operation ${ref.operation}`:"Cache source unavailable"}</span>{proof?<button type="button" aria-pressed={focus==="operation"} onClick={()=>setFocus("operation")}>Open cache operation source</button>:<span>Exact operation source unavailable</span>}</li>
   <li><strong>Queue attempt</strong><code>{attempt?.available?attempt.sequence:"unavailable"}</code><span>{attempt?.available?"Exact enqueue identity; enqueue clock unavailable":"No exact queue identity recorded"}</span></li>
   <li><strong>{record.type==="send_suppressed"?"Suppression callback":"Physical write callback"}</strong><span>{record.type==="send_suppressed"?"Send omitted; callback clock unavailable":`write ${record.write||"unknown"} · ${record.t_mono_ns??"unavailable"} ns`}</span><span>Original journal seq {record.seq}</span></li>
  </ol>}
  {proof&&<p className="controls"><button type="button" aria-pressed={focus==="declaration"} onClick={()=>setFocus("declaration")}>Open snapshot declaration</button><button type="button" aria-pressed={focus==="instance"} onClick={()=>setFocus("instance")}>Open empty-cache source</button></p>}
  {point&&<aside key={`${focus}:${point.input}:${point.file}:${point.ordinal}`} className="cache-original" aria-label="Original cache source"><h4>{focus} source: {point.file}:{point.ordinal}</h4><Pending load={original} onAuth={onAuth}/>{source&&<><p className={matches?undefined:"error"}>{matches?"Original source identity and coordinates match.":"Original metadata does not match this cache source link."}</p>{matches&&focus==="operation"&&source.cache_operation&&<p>{source.cache_operation.targets.includes(record.peer||"")?"This peer was a target at the recorded decision.":source.cache_operation.suppressed.includes(record.peer||"")?"This peer was suppressed at the recorded decision.":"This peer has no target or suppression in the recorded decision."} A successful write remains a separate observation.</p>}<pre>{JSON.stringify(source,null,2)}</pre></>}</aside>}
 </section>;
}
