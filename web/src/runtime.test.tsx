import {describe,it,expect} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {RuntimeSource} from "./views/Runtime";
import type {Schemas} from "./api/client";
import {parseRoute} from "./App";
describe("runtime source identity",()=>{
 it("retains large call and height strings with exact original lines",()=>{
 const evidence:Schemas["RuntimeCallSource"]={task:null,node:"node",run:"writer",source_sha256:"a".repeat(64),call:{id:"18446744073709551615",operation:"worker_commit_work",result:"returned",start_line:2,end_line:3,nanoseconds:"9007199254740993",height:"18446744073709551616",hash:""},start:{line:2,type:"operation_start",seq:"1",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"1"},end:{line:3,type:"operation_end",seq:"2",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"9007199254740994",height:"18446744073709551616"}};
 const html=renderToStaticMarkup(<RuntimeSource evidence={evidence}/>);
 expect(html).toContain("18446744073709551615");expect(html).toContain("18446744073709551616");expect(html).toContain("9007199254740993");expect(html).toContain("Line 2");expect(html).toContain("Line 3");expect(html).toContain("not a consensus acceptance");
 });
 it("resolves the runtime route",()=>{expect(parseRoute("#/networks/1/runtime")).toEqual({view:"runtime",net:1})});
});

describe("asynchronous task source",()=>{
 it("keeps return and result stages separate with original coordinates",()=>{
  const evidence:Schemas["RuntimeCallSource"]={node:"node",run:"writer",source_sha256:"a".repeat(64),call:{id:"1",operation:"worker_commit_work",result:"returned",start_line:1,end_line:2,nanoseconds:"10",height:"1",hash:""},start:{line:1,type:"operation_start",seq:"0",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"0"},end:{line:2,type:"operation_end",seq:"1",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"10"},task:{id:"1",state:"observed_result",start_line:1,end_line:2,stages:[{line:3,type:"operation_stage",stage:"seal_return",id:"1",seq:"2",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"20",height:"1"},{line:4,type:"operation_stage",stage:"seal_result",id:"1",seq:"3",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"30",height:"1"}],intervals:[{definition:"seal_entry_to_seal_result",from_line:3,to_line:4,nanoseconds:"9007199254740993"}]}};
  const html=renderToStaticMarkup(<RuntimeSource evidence={evidence}/>);expect(html).toContain("seal_return");expect(html).toContain("seal_result");expect(html).toContain("Line 3");expect(html).toContain("Line 4");expect(html).toContain("9007199254740993");expect(html).toContain("not a total execution order");
 });
});
