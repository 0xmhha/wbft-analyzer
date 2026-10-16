import {useEffect,useRef,useState} from "react";
import {get,type Schemas} from "../api/client";
import {Pending,useLoad} from "../ui";
import {governanceCollections,governanceIndex,governanceOutcome,governancePhase,governancePointer,governancePositions,governanceProposalStatus,type Collection} from "../governance";

type Capture=Schemas["StoreGovernanceCapture"];
type Call=Schemas["StoreGovernanceCall"];
type Entry=Schemas["StoreGovernanceEntry"];
type SourceSelection={ordinal:number;pointer:string};
const quantity=(value:string)=>/^0x[0-9a-f]+$/.test(value)?`${BigInt(value)} (${value})`:value;
const count=(value:number|null)=>value===null?"unavailable":value.toLocaleString();

export function Governance({net,onAuth}:{net:number;onAuth:()=>void}){
 const datasets=useLoad(async()=>(await get("/v1/networks/{net}/datasets",{path:{net},query:{kind:"governance"}})).datasets,[net]);
 const [chosen,choose]=useState(0),[motion,setMotion]=useState(true);
 const id=chosen||(datasets.state==="done"?datasets.data.at(-1)?.id:0)||0;
 const capture=useLoad(async()=>id?get("/v1/networks/{net}/datasets/{dataset}/governance",{path:{net,dataset:id}}):null,[net,id]);
 return <section className="governance-history"><h1>Governance history</h1><p>Read-only governance claims, preserving each request's scope. Failed attempts remain visible. Mirror health, authority and verification labels describe the source; they do not verify canonical execution.</p>
  <Pending load={datasets} onAuth={onAuth}/>{datasets.state==="done"&&(datasets.data.length?<label>Governance capture <select value={id} onChange={e=>choose(Number(e.target.value))}>{datasets.data.map(d=><option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label>:<p>No governance captures. Import a bounded RPC capture or archive with ingest governance.</p>)}
  <Pending load={capture} onAuth={onAuth}/>{capture.state==="done"&&capture.data&&<GovernanceCapture key={`${id}:${capture.data.snapshot}`} net={net} capture={capture.data} onAuth={onAuth} motion={motion} onMotion={setMotion}/>}
 </section>;
}

function GovernanceCapture({net,capture,onAuth,motion,onMotion}:{net:number;capture:Capture;onAuth:()=>void;motion:boolean;onMotion:(value:boolean)=>void}){
 const [chosen,setChosen]=useState(capture.calls.find(c=>c.request.method==="wbft_govOps")?.ordinal||1);
 const call=capture.calls.find(c=>c.ordinal===chosen);
 return <>
  <h2>Capture provenance</h2><dl className="gov-facts"><dt>Source node</dt><dd>{capture.before.address}</dd><dt>Chain</dt><dd>{capture.before.chain_id}</dd><dt>Genesis</dt><dd>{capture.before.genesis_hash}</dd><dt>Identity bookend heads</dt><dd>{capture.before.head} → {capture.after.head}</dd><dt>Requested block indices</dt><dd>{governanceIndex(capture.from)} to {governanceIndex(capture.to)}</dd><dt>Bounded operation count</dt><dd>{count(capture.operations)}</dd><dt>Fault / gap records</dt><dd>{count(capture.faults)} / {count(capture.gaps)}</dd></dl>
  <p className="gov-caution">Collected independently; not an atomic snapshot. Canonical binding is not established by these RPC claims. Proposal history and current state have their own request scope.</p>
  <div className="gov-mirrors">{capture.calls.filter(c=>c.request.method==="wbft_mirror").map(c=><MirrorSnapshot key={c.ordinal} net={net} dataset={capture.dataset_id} call={c} onAuth={onAuth} onSelect={()=>setChosen(c.ordinal)}/>)}</div>
  <details><summary>Capture hashes and identity details</summary><p>Source {capture.source_kind} · envelope origin {capture.envelope_origin}. A reconstructed envelope digest does not identify original network packets.</p><p>Source digest {capture.source_sha256}</p><p>Normalized snapshot {capture.snapshot} · {capture.normalizer}</p><p>Before head hash {capture.before.head_hash}</p><p>After head hash {capture.after.head_hash}</p></details>
  <h2>Request history</h2><label>Original request <select value={chosen} onChange={e=>setChosen(Number(e.target.value))}>{capture.calls.map(c=><option key={c.ordinal} value={c.ordinal}>{c.ordinal} · {c.request.method} · {c.request.scope} · {c.status}</option>)}</select></label>
  {call&&<RequestHistory key={`${capture.snapshot}:${chosen}`} net={net} dataset={capture.dataset_id} call={call} onAuth={onAuth} motion={motion} onMotion={onMotion}/>}
 </>;
}

function MirrorSnapshot({net,dataset,call,onAuth,onSelect}:{net:number;dataset:number;call:Call;onAuth:()=>void;onSelect:()=>void}){
 const load=useLoad(async()=>call.status==="available"?get("/v1/networks/{net}/datasets/{dataset}/governance/calls/{ordinal}/entries",{path:{net,dataset,ordinal:call.ordinal},query:{collection:"mirrors"}}):null,[net,dataset,call.ordinal]);
 const mirror=load.state==="done"?load.data?.rows[0]?.mirror:null;
 return <article><h3>{call.request.scope}</h3><Pending load={load} onAuth={onAuth}/>{mirror?<><p>Authority: <strong>{mirror.authority}</strong> · source reports <strong>{mirror.healthy?"healthy":"unhealthy"}</strong></p><p>Mirror index {governanceIndex(mirror.number)}</p><p>{mirror.validators.length} reported validators · {Object.values(mirror.modes).filter(m=>m==="projection-only").length} projection-only instances</p></>:load.state==="done"?<p>{call.status==="available"?"Snapshot not available":"Request unavailable"}</p>:null}<button type="button" onClick={onSelect}>Inspect request {call.ordinal}</button></article>;
}

function RequestHistory({net,dataset,call,onAuth,motion,onMotion}:{net:number;dataset:number;call:Call;onAuth:()=>void;motion:boolean;onMotion:(value:boolean)=>void}){
 const choices=governanceCollections(call.request.method);
 const [collection,setCollection]=useState<Collection>(choices[0]||"operations"),[cursors,setCursors]=useState<string[]>([]),[selected,select]=useState<number|null>(null),[source,setSource]=useState<SourceSelection|null>(null);
 const page=useLoad(async()=>choices.length?get("/v1/networks/{net}/datasets/{dataset}/governance/calls/{ordinal}/entries",{path:{net,dataset,ordinal:call.ordinal},query:{collection,limit:100,...(cursors.at(-1)?{cursor:cursors.at(-1)!}:{})}}):null,[net,dataset,call.ordinal,collection,cursors.at(-1)]);
 const clear=()=>{select(null);setSource(null)};
 const selectedEntry=page.state==="done"?page.data?.rows.find(r=>r.ordinal===selected):null;
 return <section className={motion?"gov-request":"gov-request no-motion"}>
  <h3>Request {call.ordinal}: {call.request.method}</h3><p><strong>{call.request.scope}</strong> · {call.status}{call.error_code!=null?` · RPC code ${call.error_code}`:""}</p><p>Parameters: {call.request.params.join(" · ")||"none"}</p>
  <button type="button" onClick={()=>setSource({ordinal:call.ordinal,pointer:choices.length?"/request":"/data"})}>Open normalized request {call.ordinal}</button>
  {choices.length>1&&<div className="controls" aria-label="Request collections">{choices.map(kind=><button key={kind} type="button" aria-pressed={kind===collection} onClick={()=>{setCollection(kind);setCursors([]);clear()}}>{kind}</button>)}</div>}
  {call.request.scope==="proposal-full-history-current-state"&&<p>Full proposal history and current proposal state. Operations may lie outside the capture's bounded block range.</p>}
  {choices.length>0&&<><Pending load={page} onAuth={onAuth}/>{page.state==="done"&&page.data&&<>
   {page.data.call.status!=="available"?<p className="gov-caution">Request unavailable. This does not establish zero {collection}.</p>:<p>{page.data.total.toLocaleString()} {page.data.total===1?collection.slice(0,-1):collection} reported by this request.</p>}
   {collection==="operations"&&page.data.rows.length>0&&<><label><input type="checkbox" checked={motion} onChange={e=>onMotion(e.target.checked)}/>Selection motion (respects reduced motion)</label><GovernanceTimeline rows={page.data.rows} selected={selected} onSelect={n=>{select(n);setSource(null)}}/></>}
   {selectedEntry&&<EntryDetails entry={selectedEntry}/>}
   <div className="table-scroll"><table aria-label={`Governance ${collection}`}><thead><tr><th>Source row</th><th>Block index / proposal ID</th><th>Recorded item</th><th>Outcome / state</th><th>Details</th><th>Source</th></tr></thead><tbody>{page.data.rows.map(row=><tr key={row.ordinal} className={row.ordinal===selected?"gov-selected":""}><td>{row.ordinal}</td><td>{entryIndex(row)}</td><td>{entryTitle(row)}</td><td>{entryOutcome(row)}</td><td><button type="button" aria-pressed={row.ordinal===selected} onClick={()=>{select(row.ordinal);setSource(null)}}>Details {row.ordinal}</button></td><td><button type="button" onClick={()=>setSource({ordinal:row.call_ordinal,pointer:row.normalized_pointer})}>Source {row.ordinal}</button></td></tr>)}</tbody></table></div>
   <div className="controls"><button type="button" disabled={!cursors.length} onClick={()=>{setCursors(cursors.slice(0,-1));clear()}}>Previous entries</button><button type="button" disabled={!page.data.next} onClick={()=>{if(page.data?.next)setCursors([...cursors,page.data.next]);clear()}}>Next entries</button></div>
  </>}</>}
  {source&&<GovernanceSource key={`${source.ordinal}:${source.pointer}`} net={net} dataset={dataset} selection={source} onAuth={onAuth}/>}
 </section>;
}

function entryIndex(e:Entry):string{return quantity(e.operation?.number||e.fault?.number||e.state?.number||e.change?.number||e.mirror?.number||e.proposal?.id||"");}
function entryTitle(e:Entry):string{return e.operation?(e.operation.call.signature||`unknown call ${e.operation.selector}`):e.fault?e.fault.kind:e.state?e.state.instance:e.proposal?e.proposal.instance:e.change?"validator / epoch change":e.mirror?`${e.mirror.authority} mirror`:"unknown";}
function entryOutcome(e:Entry):string{return e.operation?governanceOutcome(e.operation).label:e.fault?e.fault.kind==="gap"?"unconfirmed history":"fault":e.state?`${e.state.mode}${e.state.inexact?" · inexact":""}`:e.proposal?e.proposal.proposal?`current state: ${governanceProposalStatus(e.proposal.proposal.status)}`:"proposal not available":e.change?"source change claim":e.mirror?e.mirror.healthy?"source reports healthy":"source reports unhealthy":"unknown";}

export function GovernanceTimeline({rows,selected,onSelect}:{rows:Entry[];selected:number|null;onSelect:(n:number)=>void}){
 const ops=rows.filter((r):r is Entry&{operation:Schemas["GovernanceOperation"]}=>!!r.operation),positions=governancePositions(ops.map(r=>r.operation.number));
 if(!ops.length||!positions)return <p>Block positions unavailable.</p>;
 const phase=(op:Schemas["GovernanceOperation"])=>governanceOutcome(op).kind==="failed"?"failed attempt":governancePhase(op.call.signature||"");
 const lanes=["creation","vote","execution","closure","configuration","unknown","failed attempt"].filter(lane=>ops.some(r=>phase(r.operation)===lane));
 const axisY=30+lanes.length*40,height=axisY+41;
 const indices=ops.map(r=>BigInt(r.operation.number));let low=indices[0]!,high=low;for(const n of indices){if(n<low)low=n;if(n>high)high=n;}
 return <figure className="gov-timeline"><figcaption>Operation positions on this request page. Filled marks report effective operations; outlines retain attempts, crosses retain reverted attempts, and dashed marks retain unknown outcomes. Select a mark for details.</figcaption><div className="table-scroll"><svg viewBox={`0 0 840 ${height}`} role="group" aria-label="Governance operation positions by source block index">
  {lanes.map((lane,i)=><g key={lane}><line x1="60" x2="780" y1={30+i*40} y2={30+i*40} className="gov-grid"/><text x="4" y={24+i*40}>{lane}</text></g>)}
  {ops.map((r,i)=>{const op=r.operation,outcome=governanceOutcome(op),lane=lanes.indexOf(phase(op)),x=positions[i]!,y=30+Math.max(0,lane)*40+(i%3-1)*5;return <g key={r.ordinal} className={`gov-mark gov-${outcome.kind}`} role="button" tabIndex={0} aria-pressed={selected===r.ordinal} aria-label={`Source row ${r.ordinal}, block ${BigInt(op.number)}, ${op.call.signature||"unknown call"}, ${outcome.label}`} onClick={()=>onSelect(r.ordinal)} onKeyDown={e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();onSelect(r.ordinal)}}}><title>{`Row ${r.ordinal} · ${op.number} · transaction ${op.tx} · ${outcome.label}`}</title>{selected===r.ordinal&&<circle cx={x} cy={y} r="12" className="gov-selection"/>}<circle cx={x} cy={y} r="5"/>{outcome.kind==="failed"&&<path d={`M${x-4} ${y-4}l8 8m0 -8l-8 8`}/>}</g>})}
  <text x="60" y={axisY}>{low.toString()}</text><text x="780" y={axisY} textAnchor="end">{high.toString()}</text><text x="420" y={axisY+25} textAnchor="middle">source block index (decimal); all source rows remain in the table</text>
 </svg></div></figure>;
}

export function EntryDetails({entry:e}:{entry:Entry}){
 const op=e.operation,st=e.state,p=e.proposal?.proposal,ch=e.change,m=e.mirror,f=e.fault;
 return <aside className="gov-detail"><h3>Source row {e.ordinal}: {entryTitle(e)}</h3><p>Request {e.call_ordinal} · normalized pointer {e.normalized_pointer}</p>
  {op&&<><p>{governanceOutcome(op).label} · source verified: {String(op.verified)} · source effective: {String(op.effective)} · view: {String(op.view)}.</p><p>Result {op.result}{op.error_name?` · ${op.error_name}`:""}. Call decoding: {op.call.status}.</p><dl className="gov-facts"><dt>Instance / sender</dt><dd>{op.instance} / {op.from}</dd><dt>Stored block hash (source)</dt><dd>{op.block_hash||"unknown · not reported"}</dd><dt>Transaction</dt><dd>{op.tx_hash} · index {op.tx} · path {op.path.length?op.path.join("."):"root"}</dd><dt>Executing proposal ID</dt><dd>{op.executing_proposal_id===null?"not reported":quantity(op.executing_proposal_id)}</dd><dt>Validator-change annotation</dt><dd>{op.validator_change.status==="not-reported"?"not reported":op.validator_change.status}</dd><dt>Input</dt><dd>{op.input.length} bytes · digest {op.input.sha256}</dd></dl><h4>Decoded arguments</h4>{op.call.arguments.length?<ul>{op.call.arguments.map((a,i)=><li key={i}>{a.type}: {a.value?(a.type==="address"?a.value:quantity(a.value)):a.values?a.values.join(" · "):a.bytes?`${a.bytes.length} bytes · digest ${a.bytes.sha256}`:"not reported"}</li>)}</ul>:<p>No decoded arguments.</p>}<p>{op.logs.length} recorded log metadata rows. Opaque input and log bytes are not retained.</p></>}
  {f&&<><p>{f.kind==="gap"?f.bounds_known?`Unconfirmed history: ${quantity(f.gap_from!)} through ${quantity(f.gap_to!)} (inclusive).`:"Unconfirmed history: gap bounds are unknown. The record index is not an inferred interval.":`Source reports ${f.kind} fault.`}</p><p>Instance {f.instance}. Description digest {f.description.sha256} · {f.description.length} bytes.</p></>}
  {st&&<><p>Historical state at {quantity(st.number)} · {st.mode} · {st.inexact?"inexact":"source did not mark inexact"}.</p><p>Reported optional fields: {st.reported_fields.join(", ")||"none"}. Missing fields are not zero values.</p><p>Member version {quantity(st.member_version)} · quorum {quantity(st.quorum)} · expiry {quantity(st.proposal_expiry)} · current proposal {quantity(st.current_proposal_id)} · maximum proposals {quantity(st.max_proposals)}.</p><AddressList label="Members" values={st.members}/><p>{st.proposals.length} current proposal snapshots in this historical state.</p></>}
  {e.proposal&&<><p>Proposal {quantity(e.proposal.id)} · current-state request.</p>{p?<><p>Status {governanceProposalStatus(p.status)} · approvals {p.approved}/{p.required_approvals} · rejections {p.rejected} · execution count {quantity(p.execution_count)}.</p><p>Proposer {p.proposer} · action type {p.action_type}.</p><p>Proposal calldata {p.call_data.length} bytes · digest {p.call_data.sha256}. Select operations to inspect this proposal's full history.</p></>:<p>Current proposal state unavailable. Recorded operations remain available separately.</p>}</>}
  {ch&&<><p>Stored block hash (source): {ch.block_hash||"unknown · not reported"}.</p><p>Validator and epoch data are source claims; a canonical cause is not inferred.</p>{ch.validators_reported?<AddressList label="Reported validators" values={ch.validators}/>:<p>Validator list not reported.</p>}{ch.epoch&&<><AddressList label="Epoch candidates" values={ch.epoch.candidates}/><AddressList label="Epoch validators" values={ch.epoch.validators}/><AddressList label="Added" values={ch.epoch.added}/><AddressList label="Removed" values={ch.epoch.removed}/><AddressList label="Candidates without keys reported" values={ch.epoch.no_key}/></>}</>}
  {m&&<><p>Authority {m.authority} · source healthy {String(m.healthy)} · mirror hash {m.hash}.</p><AddressList label="Validators" values={m.validators}/><div className="table-scroll"><table aria-label="Mirror instance modes"><thead><tr><th>Instance</th><th>Mode</th></tr></thead><tbody>{Object.entries(m.modes).map(([address,mode])=><tr key={address}><td>{address}</td><td>{mode}</td></tr>)}</tbody></table></div><p>Gas tip {m.gas_tip===null?"not reported":quantity(m.gas_tip)}.</p></>}
 </aside>;
}
function AddressList({label,values}:{label:string;values:string[]}){return <p>{label}: {values.length?values.slice(0,50).join(" · "):"no entries reported"}{values.length>50?` · showing 50 of ${values.length}; full list in normalized source`:""}</p>;}

function GovernanceSource({net,dataset,selection,onAuth}:{net:number;dataset:number;selection:SourceSelection;onAuth:()=>void}){
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/governance/calls/{ordinal}",{path:{net,dataset,ordinal:selection.ordinal}}),[net,dataset,selection.ordinal]);
 const ref=useRef<HTMLElement>(null);
 useEffect(()=>{if(load.state!=="done")return;ref.current?.focus({preventScroll:true});ref.current?.scrollIntoView({block:"nearest",behavior:window.matchMedia("(prefers-reduced-motion: reduce)").matches?"instant":"smooth"})},[load.state]);
 const value=load.state==="done"?governancePointer(load.data,selection.pointer):undefined;
 const json=value===undefined?"Selected normalized field unavailable.":JSON.stringify(value,null,2);
 return <aside ref={ref} tabIndex={-1} className="gov-source"><h3>Normalized source request {selection.ordinal}</h3><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<><p>{load.data.request.method} · {load.data.request.scope} · {load.data.status}. Captured envelope digest {load.data.sha256}.</p><p>Selected field {selection.pointer}. Raw opaque payloads and arbitrary error text are not retained.</p><pre>{json.slice(0,50000)}{json.length>50000?"\nDisplay truncated after 50,000 characters.":""}</pre></>}</aside>;
}
