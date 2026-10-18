import type {Schemas} from "../api/client";
import {governanceProposalStatus} from "../governance";

type Evidence=Schemas["StoreGovernanceTransitionEvidenceList"];
type Registry=Schemas["ExecutionwitnessRegistryRead"];

export function GovernanceTransitions({value}:{value:Evidence}){
 const source:Record<Evidence["status"],string>={matched:"Replay remains bound to canonical headers and configuration",mismatch:"Replay differs from the source operation",unverified:"Replay context remains unverified",ambiguous:"Conflicting or incomplete transition evidence"};
 const cause:Record<Evidence["cause_status"],string>={verified_transaction_effect:"Transaction caused the displayed registry changes",unestablished:"Registry-change cause remains unestablished",ambiguous:"Conflicting or truncated witnesses cannot establish a cause"};
 return <section className="gov-state-list" aria-label="Governance transition evidence"><h4>Registry transitions</h4><p><strong>{cause[value.cause_status]}</strong></p><p>{source[value.status]}. Source annotations are retained separately.</p><p>These registry states come from original block replay. State-proof key comparisons are shown separately.</p>
  {!value.evidence.length&&<p>No transition witness is attached at this block or transaction.</p>}
  {value.truncated&&<p>Showing the first 20 witnesses. The complete set is required to establish an unambiguous cause.</p>}
  {value.evidence.map(entry=>{const {witness,replay,point,block,next_epoch}=entry;const bound=entry.binding==="matched";const verified=bound&&entry.cause_status==="verified_transaction_effect";
   const phases=[{label:"Before system processing",values:block.before_system},{label:"Before transactions",values:block.before_transactions},{label:"After transactions",values:block.after_transactions},{label:"After finalization",values:block.finalized}];
   return <details className="gov-state-evidence" key={witness.snapshot}><summary>Block {block.index}{point?` · transaction ${point.transaction_index}`:" · header state"} · {entry.binding.replaceAll("_"," ")} · witness {witness.snapshot.slice(0,12)}</summary><div className="gov-state-content">
    <p>{verified?"This witness binds the effective root transaction's writes to the registry changes.":"This witness does not currently establish a transaction cause."} {entry.reason.replaceAll("_"," ")}.</p>
    <p>Canonical source {replay.headers_dataset===null?"no longer available":`dataset ${replay.headers_dataset}`} · original source ID {replay.header_source_id}. {witness.blocks} blocks replayed from genesis.</p>
    <ol className="gov-state-flow" aria-label="Governance state phases">{phases.map(phase=><li key={phase.label}><strong>{phase.label}</strong><span>{block.genesis&&phase.label!=="After finalization"?"Not applicable at genesis":`${phase.values.length} governance accounts observed`}</span></li>)}</ol>
    {point&&<><p>Method: {point.method||"not established"}. Observation: {point.reason.replaceAll("_"," ")}.</p>
     <RegistrySummary label="Registry before transaction" value={point.registry_before}/><RegistrySummary label="Registry after transaction" value={point.registry_after}/>
     <h5>Observed registry effects</h5>{point.effects.length?<ul>{point.effects.map((effect,i)=><li key={`${effect.candidate}:${i}`}>{effect.kind.replaceAll("_"," ")}{effect.candidate?": "+effect.candidate:""}</li>)}</ul>:<p>No candidate, order, key or operator effect was established for this transaction.</p>}
     {point.proposal_before&&point.proposal_after&&<p>Proposal {point.proposal_after.id}: status {governanceProposalStatus(Number(point.proposal_before.status))} → {governanceProposalStatus(Number(point.proposal_after.status))}; approvals {point.proposal_before.approved} → {point.proposal_after.approved}; execution count {point.proposal_before.execution_count} → {point.proposal_after.execution_count}.</p>}
     <details><summary>Observed storage writes ({point.writes.length})</summary><div className="table-scroll"><table aria-label="Replayed governance storage writes"><thead><tr><th>Storage owner</th><th>Observed path</th><th>Instruction</th><th>Retained effect</th></tr></thead><tbody>{point.writes.slice(0,50).map((write,i)=><tr key={i}><td>{write.address}</td><td>{write.path.length?write.path.join("/"):"root"}</td><td>{write.instruction?`SSTORE at ${write.instruction.pc}`:"Instruction unavailable"}</td><td>{write.reverted?"reverted":"retained"}</td></tr>)}</tbody></table></div>{point.writes.length>50&&<p>Showing 50 of {point.writes.length} writes; the API retains the complete bounded observation.</p>}<p>Storage slots, values and keys are represented by digests in the API.</p></details>
    </>}
    {block.epoch_registry&&<RegistrySummary label="Registry at this epoch header" value={block.epoch_registry}/>}
    {next_epoch&&<><h5>Next replayed epoch header: {next_epoch.index}</h5>{next_epoch.epoch_registry&&<RegistrySummary label="Registry at the next epoch header" value={next_epoch.epoch_registry}/>}<p>This is a separate header state. A transaction's registry effect does not establish the cause of validator selection or the complete epoch change.</p></>}
    {block.genesis&&<p>The initial validator set at genesis can differ from the loaded candidate registry.</p>}
    <details><summary>System phase roots and source digests</summary>{phases.map(phase=><div key={phase.label}><h5>{phase.label}</h5>{phase.values.map(account=><p key={account.address}>{account.address} · storage root {account.storage_root} · code {account.code_hash}</p>)}</div>)}<dl className="gov-facts"><dt>Helper digest</dt><dd>{witness.source.verifier.sha256}</dd><dt>Configuration digest</dt><dd>{witness.source.report.execution.source.config_sha256}</dd><dt>Manifest digest</dt><dd>{witness.source.report.execution.source.manifest.sha256}</dd></dl></details>
   </div></details>
  })}
 </section>;
}

function RegistrySummary({label,value}:{label:string;value:Registry}){
 if(value.status!=="observed"||!value.state)return <section aria-label={label}><h5>{label}</h5><p>Registry state unavailable: {value.reason.replaceAll("_"," ")}. An unavailable registry does not establish that it was unchanged.</p></section>;
 const state=value.state;
 return <section aria-label={label}><h5>{label}</h5><p>{state.candidates.length} candidates; {state.without_keys.length} without a public key.</p><details><summary>Candidate order and keys</summary><div className="table-scroll"><table aria-label={label+" candidates"}><thead><tr><th>Candidate</th><th>Operator</th><th>Public key</th></tr></thead><tbody>{state.candidates.slice(0,50).map(candidate=><tr key={candidate.address}><td>{candidate.address}</td><td>{candidate.operator}</td><td>{candidate.key.bytes===0?"No public key":`${candidate.key.bytes} bytes`}</td></tr>)}</tbody></table></div>{state.candidates.length>50&&<p>Showing 50 of {state.candidates.length} candidates. The API retains the full ordered list.</p>}</details></section>;
}
