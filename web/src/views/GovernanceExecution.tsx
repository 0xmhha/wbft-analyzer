import type {Schemas} from "../api/client";

type Evidence = Schemas["StoreGovernanceExecutionEvidenceList"];

export function GovernanceExecution({value}:{value:Evidence}) {
 const labels:Record<Evidence["status"],string>={matched:"Source operation matches independently replayed VM execution",mismatch:"Source operation differs from replayed VM execution",unverified:"Operation execution remains unverified",ambiguous:"Conflicting or truncated execution evidence"};
 const binding:Record<Schemas["StoreGovernanceExecutionEvidence"]["binding"],string>={matched:"Canonical headers and configuration match",header_unavailable:"Canonical header unavailable",header_mismatch:"Canonical header differs",config_mismatch:"Configuration differs",network_mismatch:"Network identity differs",source_unavailable:"Canonical source unavailable"};
 const reason:Record<Schemas["StoreGovernanceExecutionEvidence"]["reason"],string>={source_unavailable:"Source capture unavailable",source_unbound:"Execution source is no longer bound",nested_path_unmapped:"Nested source paths have no independently established VM path mapping",source_hash_unavailable:"Source block hash was not reported",identity_mismatch:"Block, transaction or call identity differs",outcome_mismatch:"Reported outcome differs",outcome_unavailable:"Reported outcome cannot be independently classified",logs_mismatch:"Receipt logs differ",matched:"Call identity, outcome and receipt logs match"};
 return <section className="gov-state-list" aria-label="VM execution evidence"><h4>VM execution evidence</h4><p><strong>{labels[value.status]}</strong></p>
  <p>Error comparison: {value.error_status.replaceAll("_"," ")}. Proposal execution cause remains unestablished.</p>
  {value.truncated&&<p>Showing the first 20 witnesses. An incomplete list cannot establish an unambiguous result.</p>}
  {!value.evidence.length&&<p>No execution witness is attached to this transaction.</p>}
  {value.evidence.map(({witness,point,binding:state,status,error_status,reason:why})=><details className="gov-state-evidence" key={witness.snapshot}>
   <summary>{binding[state]} · transaction {point.transaction_index} · witness {witness.snapshot.slice(0,12)}</summary>
   <div className="gov-state-content"><ol className="gov-state-flow" aria-label="VM evidence checks">
    <li><strong>Original blocks</strong><span>{witness.blocks} blocks replayed from genesis</span></li>
    <li data-state={state}><strong>Current canonical context</strong><span>{binding[state]}</span></li>
    <li data-state={status}><strong>Source claim comparison</strong><span>{reason[why]}</span></li>
   </ol><p>Canonical source {witness.headers_dataset===null?"no longer available":`dataset ${witness.headers_dataset}`} · original source ID {witness.header_source_id}. Error comparison: {error_status.replaceAll("_"," ")}.</p>
    <dl className="gov-facts"><dt>Replayed receipt</dt><dd>{point.receipt_status}</dd><dt>Transaction gas used</dt><dd>{point.gas_used}</dd><dt>Receipt logs</dt><dd>{point.logs.length}</dd></dl>
    <div className="table-scroll"><table aria-label="Observed VM calls"><thead><tr><th>Observed path</th><th>Call</th><th>VM outcome</th><th>Return classification</th><th>Retained effect</th></tr></thead><tbody>{point.frames.slice(0,50).map(frame=><tr key={frame.path.join("/")}><td>{frame.path.length?frame.path.join("/"):"root"}</td><td>{frame.kind}<br/>{frame.to}</td><td>{frame.status}<br/>{frame.vm_error!=="none"?frame.vm_error.replaceAll("_"," "):"No VM error"}</td><td>{frame.error_name||frame.abi_status.replaceAll("_"," ")}{frame.observation==="execution_result"&&<><br/>Call hook details unavailable</>}</td><td>{frame.effective?"yes":"no"}</td></tr>)}</tbody></table></div>
    {point.frames.length>50&&<p>Showing the first 50 of {point.frames.length} observed calls. The API retains the complete bounded call list.</p>}
    <details><summary>Execution source digests</summary><dl className="gov-facts"><dt>Helper digest</dt><dd>{witness.source.verifier.sha256}</dd><dt>Execution implementation</dt><dd>{witness.source.verifier.origin.path} · {witness.source.verifier.origin.version}</dd><dt>Configuration digest</dt><dd>{witness.source.report.source.config_sha256}</dd><dt>Manifest digest</dt><dd>{witness.source.report.source.manifest.sha256}</dd><dt>Receipt digest</dt><dd>{point.receipt.sha256}</dd><dt>Transaction hash</dt><dd>{point.hash}</dd></dl></details>
    <p>VM paths describe observed calls. They do not establish SDK source paths, the original throwing call or the transaction that caused an epoch change. Successful children of reverted ancestors have no retained effect.</p>
   </div>
  </details>)}
 </section>;
}
