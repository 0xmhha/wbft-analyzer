import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {GovernanceExecution} from "./views/GovernanceExecution";

const address="0x"+"1".repeat(40),hash="a".repeat(64),file={sha256:hash,bytes:4};
function example():Schemas["StoreGovernanceExecutionEvidenceList"] {
 const origin={path:"github.com/stable-net/go-stablenet",version:"v0.0.0-20260915070707-740526d0375a",sum:"synthetic-module-checksum"};
 return {status:"matched",error_status:"matched",truncated:false,evidence:[{binding:"matched",status:"matched",error_status:"matched",reason:"matched",witness:{dataset_id:1,snapshot:hash,headers_dataset:2,header_source_id:2,blocks:3,transactions:1,source:{verifier:{sha256:hash,origin},report:{protocol:"wbft-execution-witness/1",origin,source:{format:"wbft-execution-witness-input/1",node:address,chain_id:"7",genesis_hash:"0x"+hash,config_sha256:hash,manifest:file,genesis:file,blocks:[]},transactions:[]}}},point:{index:"2",transaction_index:0,hash:"0x"+hash,block_hash:"0x"+hash,from:address,to:address,input:file,selector:"0x12345678",gas_used:"50000",receipt_status:"failed",receipt:file,logs:[],frames:[{path:[],kind:"CALL",from:address,to:address,input:file,selector:"0x12345678",return:file,gas:"100000",gas_used:"29000",status:"reverted",vm_error:"execution_reverted",effective:false,account_code_hash:"0x"+hash,account_code_bytes:100,observation:"call_hook",authority:"gov_validator",authority_config_index:"1",abi_status:"decoded_revert",error_name:"InvalidProposal"}]}}]};
}
it("shows canonical binding, actual VM error, logs and source comparison separately from cause",()=>{
 const html=renderToStaticMarkup(<GovernanceExecution value={example()}/>);
 for(const text of ["Source operation matches independently replayed VM execution","Original blocks","Canonical headers and configuration match","Call identity, outcome and receipt logs match","InvalidProposal","Receipt logs","Proposal execution cause remains unestablished","Successful children of reverted ancestors have no retained effect"]) expect(html).toContain(text);
 expect(html).not.toContain("raw calldata");
});
it("keeps missing canonical dependencies unverified",()=>{
 const value=example();value.status="unverified";value.error_status="unverified";const entry=value.evidence[0]!;entry.binding="source_unavailable";entry.status="unverified";entry.error_status="unverified";entry.reason="source_unbound";entry.witness.headers_dataset=null;
 const html=renderToStaticMarkup(<GovernanceExecution value={value}/>);
 expect(html).toContain("Operation execution remains unverified");expect(html).toContain("Canonical source unavailable");expect(html).toContain("no longer available");expect(html).not.toContain("Source operation matches independently");
});
it("does not name unknown runtime errors or infer a nested source path",()=>{
 const value=example();value.status="unverified";value.error_status="unverified";const entry=value.evidence[0]!;entry.status="unverified";entry.error_status="unverified";entry.reason="nested_path_unmapped";entry.point.frames[0]!.abi_status="unknown_runtime";entry.point.frames[0]!.error_name="";
 const html=renderToStaticMarkup(<GovernanceExecution value={value}/>);
 expect(html).toContain("unknown runtime");expect(html).toContain("no independently established VM path mapping");expect(html).not.toContain("InvalidProposal");
});
it("keeps truncated or conflicting evidence ambiguous",()=>{
 const value=example();value.truncated=true;value.status="ambiguous";value.error_status="ambiguous";
 const html=renderToStaticMarkup(<GovernanceExecution value={value}/>);
 expect(html).toContain("Conflicting or truncated execution evidence");expect(html).toContain("cannot establish an unambiguous result");
});
it("retains unavailable pre-hook details and empty evidence",()=>{
 const value=example();value.evidence[0]!.point.frames[0]!.observation="execution_result";
 expect(renderToStaticMarkup(<GovernanceExecution value={value}/>)).toContain("Call hook details unavailable");
 value.evidence=[];value.status="unverified";value.error_status="unverified";
 expect(renderToStaticMarkup(<GovernanceExecution value={value}/>)).toContain("No execution witness is attached");
});
