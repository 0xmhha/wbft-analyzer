import {useState} from "react";
import {get,type Schemas} from "../api/client";
import {governanceSourceLink} from "../governanceLink";
import {Pending,useLoad} from "../ui";

type Page=Schemas["EpochRegistryPage"];
type Row=Schemas["StoreEpochRegistryRow"];
type State=Schemas["ExecutionwitnessRegistryState"];

export function epochRegistryRowKey(row:Row):string{
 return `${row.dataset_id}:${row.witness_snapshot}:${row.kind}:${row.effect?.index||""}:${row.effect?.transaction_index??""}:${row.effect?.effect_ordinal??""}`;
}

export function EpochRegistry({net,index,onAuth}:{net:number;index:string;onAuth:()=>void}){
 const [open,setOpen]=useState(false),[cursors,setCursors]=useState<string[]>([]),[revision,refresh]=useState(0),[selected,select]=useState<string|null>(null),[motion,setMotion]=useState(true),[limit,setLimit]=useState(10);
 const cursor=cursors.at(-1);
 const page=useLoad(()=>open?get("/v1/networks/{net}/headers/{index}/registry-effects",{path:{net,index},query:{limit,...(cursor?{cursor}:{})}}):Promise.resolve(null),[net,index,open,cursor,revision,limit]);
 const first=()=>{setCursors([]);select(null)};
 return <section aria-label={`Registry effects at epoch ${index}`} className={motion?"gov-request":"gov-request no-motion"}><h3>Registry effects at this epoch</h3>
  <button type="button" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?"Hide replayed registry effects":"Inspect replayed registry effects"}</button>
  {open&&<><button type="button" onClick={()=>{first();refresh(revision+1)}}>Refresh registry effects</button><Pending load={page} onAuth={onAuth}/>
   {page.state==="done"&&page.data&&<>
    <label>Rows per registry page <select value={limit} onChange={event=>{first();setLimit(Number(event.target.value))}}>{[1,5,10,20].map(size=><option key={size} value={size}>{size}</option>)}</select></label>
    <label><input type="checkbox" checked={motion} onChange={event=>setMotion(event.target.checked)}/>Motion (respects reduced motion)</label>
    <EpochRegistryRows net={net} value={page.data} selected={selected} onSelect={select}/>
    <div className="controls"><button type="button" disabled={!cursors.length} onClick={first}>First registry page</button><button type="button" disabled={!cursors.length} onClick={()=>{setCursors(cursors.slice(0,-1));select(null)}}>Previous registry page</button><button type="button" disabled={!page.data.next} onClick={()=>{if(page.data?.next){setCursors([...cursors,page.data.next]);select(null)}}}>Next registry page</button></div>
   </>}
  </>}
 </section>;
}

export function EpochRegistryRows({net,value,selected=null,onSelect=()=>{}}:{net:number;value:Page;selected?:string|null;onSelect?:(key:string)=>void}){
 const row=value.rows.find(r=>epochRegistryRowKey(r)===selected);
 return <><p>Original block replay can establish that a transaction's registry effect survived through this epoch. Validator selection and diligence remain separate header comparisons.</p>
  {value.status==="not_epoch"?<p>This canonical header is not an epoch header.</p>:value.status==="genesis"?<p>Initial registry state at genesis. The initial validator set can predate the loaded registry; no preceding transaction cause is inferred.</p>:null}
  {!value.rows.length&&value.status!=="not_epoch"&&<p>No stored replay evidence on this page. This does not establish that no operation occurred or that history is complete.</p>}
  <p>{value.total.toLocaleString()} source-state and transaction-effect rows. Each row keeps its original capture; current source availability is checked on every read.</p>
  {value.rows.length>0&&<div className="table-scroll"><table aria-label="Epoch registry evidence"><thead><tr><th>Original capture</th><th>Observation</th><th>Result</th><th>Details</th></tr></thead><tbody>{value.rows.map(r=>{const key=epochRegistryRowKey(r);return <tr key={key} className={key===selected?"gov-selected":""}><td>{r.dataset_name}</td><td>{r.effect?`Block ${r.effect.index} · transaction ${r.effect.transaction_index} · ${r.effect.change.kind.replaceAll("_"," ")}`:"Epoch registry state"}</td><td>{registryRowResult(r)}</td><td><button type="button" aria-pressed={key===selected} onClick={()=>onSelect(key)}>Inspect {r.effect?`transaction ${r.effect.transaction_index} at ${r.effect.index}`:`state from ${r.dataset_name}`}</button></td></tr>})}</tbody></table></div>}
  {row&&<EpochRegistryDetail key={epochRegistryRowKey(row)} net={net} row={row}/>}
 </>;
}

export function registryRowResult(row:Row):string{
 if(row.status==="verified_retained_registry_effect")return "Registry effect retained to this epoch";
 if(row.status==="matched")return row.reason==="initial_registry_state"?"Initial registry state observed":"Registry and epoch header match";
 const reasons:Record<Row["reason"],string>={source_unbound:"Original sources remain unverified",header_state_only:"Header state only",initial_registry_state:"Initial registry state",registry_unavailable:"Registry state unavailable",epoch_header_mismatch:"Registry differs from epoch header",retention_unverified:"Registry effect retention unverified",operation_unavailable:"Original operation unavailable",operation_unverified:"Original operation remains unverified",operation_mismatch:"Original operation differs from replay",operation_ambiguous:"Conflicting or truncated operation evidence",verified_retained_registry_effect:"Registry effect retained to this epoch"};
 return reasons[row.reason];
}

export function EpochRegistryDetail({net,row}:{net:number;row:Row}){
 const effect=row.effect;
 const retention:Record<Schemas["ExecutionwitnessEpochEffectLineage"]["reason"],string>={invalid_scope:"Replay interval is incomplete or inconsistent",origin_effect_unverified:"The transaction's registry effect was not established",next_epoch_unavailable:"The requested epoch is not this effect's next observed epoch",epoch_header_mismatch:"Replay differs from the epoch header",registry_state_unavailable:"An intervening registry state is unavailable",registry_boundary_mismatch:"Registry state does not continue across the interval",system_phase_changed:"System processing changed the registry",effect_not_retained:"A later registry change replaced this effect",retained_write_overwritten:"A later transaction wrote this effect's state again",verified_retained_registry_effect:"The complete registry effect was retained through this epoch"};
 return <details open className="gov-state-evidence"><summary>{registryRowResult(row)}</summary><div className="gov-state-content">
  <p>Original capture: {row.dataset_name} · source node {row.node}.</p><p>Original header source {row.header_source_id}: {row.headers_dataset===null?"no longer available":`dataset ${row.headers_dataset}`}. Current comparison: {row.binding.replaceAll("_"," ")}.</p>
  <p>Epoch header comparison: {row.epoch_header_status.replaceAll("_"," ")}. A registry observation does not identify the cause of validator selection.</p>
  {effect&&<><h4>{effect.change.kind.replaceAll("_"," ")}</h4>{effect.change.candidate&&<p>Candidate {effect.change.candidate}</p>}
   {effect.change.kind==="candidate_order_changed"?<p>Candidate address order changed. Inspect the original operation for the before and after ordered registries.</p>:<dl className="gov-facts"><dt>Before</dt><dd>{candidateText(effect.change.before)}</dd><dt>After</dt><dd>{candidateText(effect.change.after)}</dd></dl>}
   <p>{row.status==="verified_retained_registry_effect"?"":"Historical replay comparison: "}{retention[effect.retention.reason]}. Examined {effect.retention.checked_blocks} blocks and {effect.retention.checked_transactions} transactions.</p>
   {row.status!=="verified_retained_registry_effect"&&<p>Current attribution remains unverified: {registryRowResult(row)}.</p>}
   <h4>Original operation references</h4>{!row.operations.length&&<p>No matching root operation is available in this original capture.</p>}
   {row.operations_truncated&&<p>Only the first 20 original operation references are shown. The incomplete comparison set cannot establish retention attribution.</p>}
   <ul>{row.operations.map(op=><li key={`${op.call_ordinal}:${op.entry_ordinal}`}><a href={governanceSourceLink(net,{dataset:row.dataset_id,call:op.call_ordinal,entry:op.entry_ordinal,collection:"operations",snapshot:row.capture_snapshot})}>Request {op.call_ordinal} · source row {op.entry_ordinal}</a> · {op.status}{op.comparisons_truncated?" · witness comparison truncated":""}<span> · {op.normalized_pointer}</span></li>)}</ul>
  </>}
  {row.registry&&(row.registry.status==="observed"&&row.registry.state?<RegistryCandidates state={row.registry.state}/>:<p>Registry unavailable: {row.registry.reason.replaceAll("_"," ")}. This does not establish an unchanged registry.</p>)}
  <details><summary>Evidence identity</summary><dl className="gov-facts"><dt>Capture snapshot</dt><dd>{row.capture_snapshot}</dd><dt>Transition witness</dt><dd>{row.witness_snapshot}</dd><dt>Execution witness</dt><dd>{row.execution_snapshot}</dd><dt>Helper digest</dt><dd>{row.verifier.sha256}</dd><dt>Configuration digest</dt><dd>{row.config_sha256}</dd></dl></details>
 </div></details>;
}

function candidateText(value:Schemas["ExecutionwitnessRegistryCandidate"]|null):string{
 return value?`${value.address} · operator ${value.operator} · ${value.key.bytes===0?"No public key":`${value.key.bytes}-byte public key`}`:"Not a registry candidate";
}

function RegistryCandidates({state}:{state:State}){
 const [offset,setOffset]=useState(0),size=100;
 return <section aria-label="Replayed epoch candidate registry"><h4>Replayed candidate registry</h4><p>{state.candidates.length} {state.candidates.length===1?"candidate":"candidates"}; {state.without_keys.length} without a public key.</p><p>These keys come from replayed execution state. Header selection and separately attached state proofs have their own comparisons.</p>
  <div className="table-scroll"><table aria-label="Replayed epoch registry candidates"><thead><tr><th>Order</th><th>Candidate</th><th>Operator</th><th>Public key</th></tr></thead><tbody>{state.candidates.slice(offset,offset+size).map((candidate,i)=><tr key={candidate.address}><td>{offset+i+1}</td><td>{candidate.address}</td><td>{candidate.operator}</td><td>{candidate.key.bytes===0?"No public key":`${candidate.key.bytes} bytes`}</td></tr>)}</tbody></table></div>
  {state.candidates.length>size&&<div className="controls"><p>Candidates {offset+1}–{Math.min(offset+size,state.candidates.length)} of {state.candidates.length}.</p><button type="button" disabled={!offset} onClick={()=>setOffset(0)}>First candidates</button><button type="button" disabled={!offset} onClick={()=>setOffset(Math.max(0,offset-size))}>Previous candidates</button><button type="button" disabled={offset+size>=state.candidates.length} onClick={()=>setOffset(offset+size)}>Next candidates</button></div>}
 </section>;
}
