import {renderToStaticMarkup} from "react-dom/server";
import {describe,expect,it} from "vitest";
import {parseRoute} from "./App";
import type {Schemas} from "./api/client";
import {ReconstructionStep} from "./views/Reconstruction";

const row:Schemas["StoreReconstructionStep"]={position:1,height:"18446744073709551617",log_run:"synthetic",step:{core_applied:false,issues:["recorded_application_answer_missing"],input:{ordinal:"3",via:"direct",observation_instance:"2",kind:"message",height:"18446744073709551617",round:"9007199254740993",source:{kind:"processing_boundary",file:"input_observations",line:42,sequence:"91"},processing_mono_ns:"9007199254740999",derived_timer_generation:"7"},observed:[{kind:"state_before",height:"18446744073709551617",round:"9007199254740993"}],computed:[],difference_candidates:[{kind:"application_call_mismatch",expected:{kind:"application_binding",method:"verify",argument_sha256:"a".repeat(64)},actual:{kind:"application_binding",method:"verify",argument_sha256:"b".repeat(64)}}]}};

describe("reconstructed source comparison",()=>{
 it("retains full views and separates reconstructed and physical source positions",()=>{
  const html=renderToStaticMarkup(<ReconstructionStep row={row}/>);
  for(const text of ["Reconstructed input 3","sequence 91","line 42","observation instance 2","18446744073709551617","9007199254740993","9007199254740999","derived timer generation 7"])expect(html).toContain(text);
  expect(html).toContain("core stopped before completing this input");expect(html).toContain("recorded_application_answer_missing");expect(html).toContain("Cross-implementation difference candidates (1)");expect(html).toContain("unavailable");expect(html).not.toContain("specification violation");
 });
 it("does not turn an empty candidate list into a whole-run reproduction claim",()=>{
  const html=renderToStaticMarkup(<ReconstructionStep row={{...row,step:{...row.step,core_applied:true,issues:[],difference_candidates:[]}}}/>);
  expect(html).toContain("No difference candidate in the fields compared for this input");expect(html).not.toContain("reproduced");
 });
 it("routes reconstruction independently of journal replay",()=>{
  expect(parseRoute("#/networks/7/reconstruction")).toEqual({view:"reconstruction",net:7});expect(parseRoute("#/networks/7/reexec").view).toBe("reexec");
 });
});
