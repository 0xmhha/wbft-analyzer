import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {EntryDetails,GovernanceHeaderResult,GovernanceTimeline} from "./views/Governance";
import type {Schemas} from "./api/client";
import {parseRoute} from "./App";

const addr="0x"+"1".repeat(40),hash="a".repeat(64);
const operation:Schemas["GovernanceOperation"]={number:"0xffffffffffffffff",tx:0,tx_hash:"0x"+hash,path:[],from:addr,instance:addr,input:{sha256:hash,length:4},selector:"0x12345678",call:{status:"decoded",signature:"approveProposal(uint256)",arguments:[{type:"uint256",value:"0xffffffffffffffff"}]},effective:false,view:false,result:"revert",result_value:{sha256:hash,length:3},error_name:"InvalidProposal",logs:[],verified:false,executing_proposal_id:null,validator_change:{status:"not-reported"}};
const entry:Schemas["StoreGovernanceEntry"]={call_ordinal:3,ordinal:1,normalized_pointer:"/data/0",operation};

it("shows failed attempts, exact quantities and unreported annotations",()=>{
 const html=renderToStaticMarkup(<EntryDetails entry={entry}/>);
 for(const text of ["failed attempt","InvalidProposal","source verified: false","18446744073709551615","not reported","/data/0"])expect(html).toContain(text);
 expect(html).not.toContain("18446744073709552000");
});
it("distinguishes a known zero interval from a legacy gap without inferring bounds",()=>{
 const fault:Schemas["GovernanceFault"]={number:"0xffffffffffffffff",kind:"gap",instance:addr,description:{sha256:hash,length:4},bounds_known:true,gap_from:"0x0",gap_to:"0x0"};
 const known=renderToStaticMarkup(<EntryDetails entry={{call_ordinal:4,ordinal:1,normalized_pointer:"/data/0",fault}}/>);
 expect(known).toContain("0 (0x0) through 0 (0x0)");
 const unknown=renderToStaticMarkup(<EntryDetails entry={{call_ordinal:4,ordinal:2,normalized_pointer:"/data/1",fault:{...fault,bounds_known:false,gap_from:null,gap_to:null}}}/>);
 expect(unknown).toContain("gap bounds are unknown");expect(unknown).not.toContain("through");
});
it("keeps adjacent large indices and keyboard-addressable source marks",()=>{
 const earlier={...entry,ordinal:2,operation:{...operation,number:"0xfffffffffffffffe",result:"unknown"}};
 const html=renderToStaticMarkup(<GovernanceTimeline rows={[earlier,entry]} selected={1} onSelect={()=>{}}/>);
 expect(html).toContain('cx="60"');expect(html).toContain('cx="780"');
 expect(html).toContain("18446744073709551614");expect(html).toContain("18446744073709551615");
 expect(html).toContain('tabindex="0"');expect(html).toContain('aria-pressed="true"');expect(html).toContain("outcome unknown");
 expect(parseRoute("#/networks/1/governance")).toEqual({view:"governance",net:1});
});

it("shows stored block hashes separately from transaction hashes and unknown legacy context",()=>{
 const blockHash="0x"+"b".repeat(64);
 const known=renderToStaticMarkup(<EntryDetails entry={{...entry,operation:{...operation,block_hash:blockHash}}}/>);
 expect(known).toContain("Stored block hash (source)");expect(known).toContain(blockHash);expect(known).toContain(operation.tx_hash);
 const legacy=renderToStaticMarkup(<EntryDetails entry={entry}/>);
 expect(legacy).toContain("unknown · not reported");
 const change=renderToStaticMarkup(<EntryDetails entry={{call_ordinal:5,ordinal:1,normalized_pointer:"/data/0",change:{number:"0x1",block_hash:blockHash,validators:[],validators_reported:false,epoch:null}}}/>);
 expect(change).toContain(blockHash);expect(change).toContain("canonical cause is not inferred");
});

const context:Schemas["StoreGovernanceHeaderContext"]={snapshot:hash,call_ordinal:3,entry_ordinal:1,collection:"operations",normalized_pointer:"/data/0",source_number:"0xffffffffffffffff",index:"18446744073709551615",source_block_hash:"0x"+hash,canonical_hash:"0x"+hash,header_status:"matched",header:{index:"18446744073709551615",number:"36893488147419103231",hash:"0x"+hash,governing_epoch:"100"},sources:[{dataset_id:7,node:"node a&b",dataset_status:"complete"}],sources_truncated:false,epoch:null,cause_status:"unestablished"};

it("links the exact header source without converting large indices to floating point",()=>{
 const html=renderToStaticMarkup(<GovernanceHeaderResult net={2} value={context}/>);
 expect(html).toContain("Exact canonical header match");expect(html).toContain("36893488147419103231");expect(html).toContain("index=18446744073709551615&amp;dataset=7&amp;node=node%20a%26b");
 expect(html).toContain("Execution cause remains unestablished");expect(html).not.toContain("18446744073709552000");
});
it("does not link unknown, missing or mismatched canonical context",()=>{
 for(const status of ["unknown_hash","header_unavailable","hash_mismatch"] as const){
  const html=renderToStaticMarkup(<GovernanceHeaderResult net={2} value={{...context,header_status:status,header:null,sources:[]}}/>);
  expect(html).not.toContain("href=");expect(html).not.toContain("Header full height");expect(html).toContain("Execution cause remains unestablished");
 }
});
it("separates epoch agreement from unverified execution keys and missing inputs",()=>{
 const epoch:Schemas["StoreGovernanceEpochEvidence"]={status:"available",candidates:"matched",validators:"mismatch",added:"unavailable",removed:"unavailable",header_candidates:[addr],header_validators:[addr],header_added:[],header_removed:[],no_key_status:"unverified_execution_keys"};
 const html=renderToStaticMarkup(<GovernanceHeaderResult net={2} value={{...context,epoch}}/>);
 expect(html).toContain("Epoch claim comparison");expect(html).toContain("mismatch");expect(html).toContain("Candidates without keys remain unverified");
 const missing=renderToStaticMarkup(<GovernanceHeaderResult net={2} value={{...context,epoch:{...epoch,status:"not_epoch"}}}/>);
 expect(missing).toContain("Header has no epoch data");expect(missing).not.toContain("Epoch claim comparison");
});
