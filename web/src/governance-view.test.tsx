import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {EntryDetails,GovernanceTimeline} from "./views/Governance";
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
