import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BuildLifecycleDetails } from "./views/BuildLifecycleEvidence";
import type { Schemas } from "./api/client";

const event: Schemas["StoreLogEvent"]={input:"i",line:1,node:"n",run:"r",t_wall:"2026-01-01T00:00:00Z",t_mono_ns:"9007199254740993",kind:"BUILD_STARTED",height:"18446744073709551616",round:"0",level:"event",profile:"wbft@events-v1",view_inferred:false,fields:{build_id:"build-1"}};
describe("application build source evidence",()=>{
 it("keeps exact source and large values visible without claiming acceptance",()=>{
  const evidence:Schemas["StoreBuildLifecycle"]={state:"complete",build_id:"build-1",status:"submitted",origin:event,events:[event],assembly_ns:"9007199254740993"};
  const html=renderToStaticMarkup(<BuildLifecycleDetails evidence={evidence} onSelect={()=>{}}/>);
  expect(html).toContain("9007199254740993 ns");expect(html).toContain("i:1");expect(html).toContain("18446744073709551616");expect(html).toContain("application handover");expect(html).not.toContain("accepted");
 });
 it("retains ambiguous candidates and unavailable clock",()=>{
  const evidence:Schemas["StoreBuildLifecycle"]={state:"ambiguous",build_id:"build-1",status:"",origin:event,events:[event,{...event,line:2}],assembly_ns:null};
  const html=renderToStaticMarkup(<BuildLifecycleDetails evidence={evidence} onSelect={()=>{}}/>);
  expect(html).toContain("Assembly interval unavailable");expect(html).toContain("i:1");expect(html).toContain("i:2");expect(html).toContain("No unique assembly interval is inferred");
 });
});
