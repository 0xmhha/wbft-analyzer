import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {governanceFocus,governanceSourceLink} from "./governanceLink";
import {parseRoute} from "./App";
import {HeaderGovernanceResult} from "./views/HeaderGovernance";
import type {Schemas} from "./api/client";

const snapshot="a".repeat(64),focus={dataset:7,call:5,entry:501,collection:"changes" as const,snapshot};
it("round-trips an exact source beyond the first page",()=>{
 const link=governanceSourceLink(2,focus);
 expect(governanceFocus(link.split("?")[1]!)).toEqual({governanceFocus:focus});
 expect(parseRoute(link)).toEqual({view:"governance",net:2,governanceFocus:focus});
});
it("rejects partial, duplicate, unsafe or noncanonical source coordinates",()=>{
 const valid=governanceSourceLink(2,focus).split("?")[1]!;
 for(const q of ["dataset=7",valid+"&dataset=8",valid+"&unknown=1",valid.replace("entry=501","entry=0"),valid.replace("entry=501","entry=0501"),valid.replace("call=5","call=9007199254740993"),valid.replace("collection=changes","collection=states"),valid.replace(snapshot,"../secret"),valid.replace(snapshot,"a".repeat(63))]){
  expect(governanceFocus(q)).toEqual({sourceError:"Invalid governance source link."});
 }
 expect(governanceFocus("")).toEqual({});
});
const value:Schemas["StoreHeaderGovernanceClaims"]={index:"18446744073709551615",number:"36893488147419103231",hash:"0x"+snapshot,claims:[],truncated:false,cause_status:"unestablished"};
it("does not infer absence or complete history from zero exact-hash claims",()=>{
 const html=renderToStaticMarkup(<HeaderGovernanceResult net={2} value={value}/>);
 expect(html).toContain("18446744073709551615");expect(html).toContain("Execution cause remains unestablished");expect(html).toContain("does not establish that no operation occurred");
});
it("links immutable source coordinates and exposes truncation",()=>{
 const html=renderToStaticMarkup(<HeaderGovernanceResult net={2} value={{...value,truncated:true,claims:[{dataset_id:7,dataset_name:"source",node:"node-a",snapshot,call_ordinal:5,entry_ordinal:501,normalized_pointer:"/data/500",epoch:null}]}}/>);
 expect(html).toContain("Only the first 20");expect(html).toContain("entry=501&amp;collection=changes&amp;snapshot="+snapshot);expect(html).toContain("/data/500");expect(html).not.toContain("verified cause");
});

it("links an original operation without substituting a change claim",()=>{
 const operation={...focus,collection:"operations" as const};
 const link=governanceSourceLink(2,operation);
 expect(link).toContain("collection=operations");
 expect(governanceFocus(link.split("?")[1]!)).toEqual({governanceFocus:operation});
 expect(parseRoute(link)).toEqual({view:"governance",net:2,governanceFocus:operation});
});
