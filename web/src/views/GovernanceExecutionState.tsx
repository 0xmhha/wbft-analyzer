import type {Schemas} from "../api/client";

type Epoch=Schemas["StoreGovernanceEpochEvidence"];

export function ExecutionKeyStatus({epoch}:{epoch:Epoch}){
 const labels:Record<Epoch["no_key_status"],string>={
  unverified_execution_keys:"Candidates without keys remain unverified: bound execution-state evidence is unavailable or incomplete.",
  verified_execution_keys:"Candidates without keys match authenticated execution state.",
  mismatch_execution_keys:"Reported candidates without keys differ from authenticated execution state.",
  ambiguous_execution_keys:"Conflicting or truncated execution-state sources: candidates without keys remain unverified."
 };
 return <section aria-label="Execution key evidence"><p><strong>{labels[epoch.no_key_status]}</strong></p>
  {epoch.execution_state&&<ExecutionStateEvidence value={epoch.execution_state}/>}
 </section>;
}

export function ExecutionStateEvidence({value}:{value:Schemas["StoreGovernanceStateEvidenceList"]}){
 const binding:Record<Schemas["StoreGovernanceStateEvidence"]["status"],string>={matched:"Canonical header and configuration match",header_unavailable:"Canonical header unavailable",header_mismatch:"Canonical header differs",config_mismatch:"Configuration differs",network_mismatch:"Network identity differs",source_unavailable:"Source dataset unavailable"};
 return <div className="gov-state-list"><p>Execution-state evidence at block {value.index}. Proofs were authenticated during import; header and configuration bindings are checked again on each read.</p>
  {value.truncated&&<p>More than 20 witnesses are available. The incomplete source list cannot establish an unambiguous key result.</p>}
  {!value.evidence.length&&<p>No execution-state witness is currently attached at this block.</p>}
  {value.evidence.map(entry=>{const {witness,point}=entry;return <details className="gov-state-evidence" key={witness.snapshot}>
   <summary>{binding[entry.status]} · source {witness.source.node} · witness {witness.snapshot.slice(0,12)}</summary>
   <div className="gov-state-content"><ol className="gov-state-flow" aria-label="Execution-state evidence checks">
    <li><strong>Original state proof</strong><span>Authenticated at import</span></li>
    <li data-state={entry.status}><strong>Canonical context</strong><span>{binding[entry.status]}</span></li>
    <li data-state={point.epoch.keys}><strong>Epoch candidate keys</strong><span>{point.epoch.keys==="matched"?"Match the source header":point.epoch.keys==="not_epoch"?"No epoch data in this header":"Differ from the source header"}</span></li>
   </ol><p>Header source {witness.headers_dataset===null?"no longer available":`dataset ${witness.headers_dataset}`} · original source ID {witness.header_source_id}. {point.state.candidates.length} proven candidates; {point.state.without_keys.length} without a public key.</p>
    <div className="table-scroll"><table aria-label={`Proven candidate keys for witness ${witness.snapshot.slice(0,12)}`}><thead><tr><th>Candidate</th><th>Public key at this block</th></tr></thead><tbody>{point.state.candidates.slice(0,50).map(candidate=><tr key={candidate.address}><td>{candidate.address}</td><td>{candidate.key_bytes===0?"No public key":`${candidate.key_bytes} bytes`}</td></tr>)}</tbody></table></div>
    {point.state.candidates.length===0&&<p>The proven candidate set is empty. This does not establish a valid epoch.</p>}
    {point.state.candidates.length>50&&<p>Showing the first 50 of {point.state.candidates.length} candidates; the API retains the complete proven set.</p>}
    <details><summary>Source digests and state roots</summary><dl className="gov-facts"><dt>Block hash</dt><dd>{point.block_hash}</dd><dt>State root</dt><dd>{point.state.state_root}</dd><dt>Contract</dt><dd>{point.state.contract}</dd><dt>Code hash</dt><dd>{point.state.code_hash}</dd><dt>Storage root</dt><dd>{point.state.storage_root}</dd><dt>Configuration digest</dt><dd>{witness.source.config_sha256}</dd><dt>Manifest digest</dt><dd>{witness.source.manifest.sha256}</dd><dt>Response digest</dt><dd>{point.response.sha256}</dd><dt>Storage slots proved</dt><dd>{point.state.slots}</dd></dl></details>
    <p>Key comparisons do not establish diligence, validator selection, aggregate signatures or the transaction that caused a state change.</p>
   </div>
  </details>})}
 </div>;
}
