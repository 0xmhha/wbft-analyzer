import {describe,it,expect} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {RuntimeSource,ConfigurationPoint} from "./views/Runtime";
import type {Schemas} from "./api/client";
import {parseRoute} from "./App";
describe("runtime source identity",()=>{
 it("retains large call and height strings with exact original lines",()=>{
 const evidence:Schemas["RuntimeCallSource"]={engines:[],task:null,node:"node",run:"writer",source_sha256:"a".repeat(64),call:{id:"18446744073709551615",operation:"worker_commit_work",result:"returned",start_line:2,end_line:3,nanoseconds:"9007199254740993",height:"18446744073709551616",hash:""},start:{line:2,type:"operation_start",seq:"1",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"1"},end:{line:3,type:"operation_end",seq:"2",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"9007199254740994",height:"18446744073709551616"}};
 const html=renderToStaticMarkup(<RuntimeSource evidence={evidence}/>);
 expect(html).toContain("18446744073709551615");expect(html).toContain("18446744073709551616");expect(html).toContain("9007199254740993");expect(html).toContain("Line 2");expect(html).toContain("Line 3");expect(html).toContain("not a consensus acceptance");
 });
 it("resolves the runtime route",()=>{expect(parseRoute("#/networks/1/runtime")).toEqual({view:"runtime",net:1})});
});

describe("asynchronous task source",()=>{
 it("keeps return and result stages separate with original coordinates",()=>{
  const evidence:Schemas["RuntimeCallSource"]={engines:[],node:"node",run:"writer",source_sha256:"a".repeat(64),call:{id:"1",operation:"worker_commit_work",result:"returned",start_line:1,end_line:2,nanoseconds:"10",height:"1",hash:""},start:{line:1,type:"operation_start",seq:"0",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"0"},end:{line:2,type:"operation_end",seq:"1",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"10"},task:{id:"1",state:"observed_result",start_line:1,end_line:2,stages:[{line:3,type:"operation_stage",stage:"seal_return",id:"1",seq:"2",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"20",height:"1"},{line:4,type:"operation_stage",stage:"seal_result",id:"1",seq:"3",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"30",height:"1"}],intervals:[{definition:"seal_entry_to_seal_result",from_line:3,to_line:4,nanoseconds:"9007199254740993"}]}};
  const html=renderToStaticMarkup(<RuntimeSource evidence={evidence}/>);expect(html).toContain("seal_return");expect(html).toContain("seal_result");expect(html).toContain("Line 3");expect(html).toContain("Line 4");expect(html).toContain("9007199254740993");expect(html).toContain("not a total execution order");
 });
});

describe("core lifecycle source",()=>{
 it("keeps full instance identities and independent stage parents",()=>{
  const point=(line:number,stage:string,parent:string)=>({line,type:"engine_stage",stage,id:"18446744073709551614",parent_id:parent,seq:String(line),t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"9007199254740993"});
  const evidence:Schemas["RuntimeCallSource"]={engines:[{id:"18446744073709551614",parent_id:"42",created_line:3,state:"observed_stopped",configuration:"unavailable",configs:[],created:{...point(3,"","42"),type:"engine_created"},stages:[point(4,"handler_exit","42"),point(5,"handler_joined","43")]}],task:null,node:"node",run:"writer",source_sha256:"a".repeat(64),call:{id:"43",operation:"backend_stop",result:"ok",start_line:1,end_line:6,nanoseconds:"30",height:"",hash:""},start:point(1,"","43"),end:point(6,"","43")};
  const html=renderToStaticMarkup(<RuntimeSource evidence={evidence}/>);
  for(const text of ["18446744073709551614","parent call 42","parent call 43","handler_exit","handler_joined","Line 3","9007199254740993","does not establish a complete execution model"])expect(html).toContain(text);
 });
});

describe("configuration candidates",()=>{
 it("shows full heights and independent original parent identities",()=>{
  const point={line:8,type:"engine_config",seq:"7",id:"18446744073709551614",parent_id:"18446744073709551613",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"9007199254740993",config:{address:"node",height:"18446744073709551617",request_timeout_ms:"2000",block_period_seconds:"1",epoch:"10",allowed_future_block_seconds:"2",max_request_timeout_seconds:"0",proposer_policy:"0",transitions:"1",system_contract_upgrades:"0"}};
  const html=renderToStaticMarkup(<ConfigurationPoint point={point}/>);
  for(const text of ["18446744073709551617","18446744073709551614","18446744073709551613","9007199254740993","2000","only to this recorded height"])expect(html).toContain(text);
 });
});
