import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {ExecutionKeyStatus,ExecutionStateEvidence} from "./views/GovernanceExecutionState";

const address="0x"+"1".repeat(40),hash="a".repeat(64),file={sha256:hash,bytes:12};
function evidence():Schemas["StoreGovernanceStateEvidenceList"]{
 return {index:"10",truncated:false,evidence:[{status:"matched",witness:{dataset_id:1,snapshot:hash,headers_dataset:2,header_source_id:2,points:1,source:{format:"wbft-execution-state-witness-input/1",manifest:file,node:address,chain_id:"7",config_sha256:hash,config_file:file,genesis_hash:"0x"+hash,genesis_file:file,points:[]}},point:{index:"10",block_hash:"0x"+hash,block_file:file,request:file,response:file,epoch:{sha256:hash,keys:"matched"},state:{layout:"wbft-validator-keys/1",contract:address,code_hash:"0x"+hash,state_root:"0x"+hash,storage_root:"0x"+hash,slots:4,candidates:[{address,key_bytes:0,key_sha256:hash}],without_keys:[address]}}}]};
}
const epoch:Schemas["StoreGovernanceEpochEvidence"]={status:"available",candidates:"matched",validators:"matched",added:"matched",removed:"matched",header_candidates:[],header_validators:[],header_added:[],header_removed:[],no_key_status:"verified_execution_keys",execution_state:null};

it("shows the actual key proof and canonical binding without a transaction verdict",()=>{
 const html=renderToStaticMarkup(<ExecutionKeyStatus epoch={{...epoch,execution_state:evidence()}}/>);
 for(const text of ["match authenticated execution state","Authenticated at import","Canonical header and configuration match","Match the source header","1 proven candidates; 1 without a public key","No public key","do not establish diligence","transaction that caused a state change"])expect(html).toContain(text);
 expect(html).not.toContain("Consensus PASS");expect(html).not.toContain("/private/tmp/");
});

it("keeps deleted or changed header sources visibly unavailable",()=>{
 const value=evidence();value.evidence[0]!.status="source_unavailable";value.evidence[0]!.witness.headers_dataset=null;
 const html=renderToStaticMarkup(<ExecutionKeyStatus epoch={{...epoch,no_key_status:"unverified_execution_keys",execution_state:value}}/>);
 expect(html).toContain("remain unverified");expect(html).toContain("Source dataset unavailable");expect(html).toContain("no longer available");expect(html).not.toContain("Candidates without keys match authenticated");
});

it("does not present conflicting or truncated witness lists as complete",()=>{
 const value=evidence();value.truncated=true;
 const html=renderToStaticMarkup(<ExecutionKeyStatus epoch={{...epoch,no_key_status:"ambiguous_execution_keys",execution_state:value}}/>);
 expect(html).toContain("Conflicting or truncated execution-state sources");expect(html).toContain("cannot establish an unambiguous key result");
 const mismatch=renderToStaticMarkup(<ExecutionKeyStatus epoch={{...epoch,no_key_status:"mismatch_execution_keys"}}/>);
 expect(mismatch).toContain("differ from authenticated execution state");
});

it("distinguishes an empty proven candidate set from a valid epoch",()=>{
 const value=evidence();value.evidence[0]!.point.state.candidates=[];value.evidence[0]!.point.state.without_keys=[];value.evidence[0]!.point.epoch.keys="not_epoch";
 const html=renderToStaticMarkup(<ExecutionStateEvidence value={value}/>);
 expect(html).toContain("The proven candidate set is empty");expect(html).toContain("does not establish a valid epoch");expect(html).toContain("No epoch data in this header");
});
