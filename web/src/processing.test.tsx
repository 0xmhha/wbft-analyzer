import {describe,expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {ProcessingEvidence} from "./views/ProcessingEvidence";

function fixture():Schemas["ScenarioProcessingModel"]{
 const point={ordinal:1,file:"00000000000000000001.wal",writer_run:"recording-1",engine_run:"18446744073709551615",step:"9007199254740993",height:"9007199254740994"};
 return {policy:"native-pre-dispatch/1",declared_receive_workers:2,assumptions:["receive_worker_count_is_declared_not_measured"],timings:[{source:{id:"journal-a",kind:"journal",node:"node-a",sha256:"a".repeat(64)},status:"partial",scope:"recorded_core_head_plus_one",from:point.height,to:point.height,samples:[{point,kind:"message",code:"20",entry_mono_ns:"9007199254740993",complete_mono_ns:"9007199254740993",nanoseconds:"0"},{point:{...point,ordinal:2,step:"9007199254740994"},kind:"message",code:"20",entry_mono_ns:"9007199254740993",complete_mono_ns:"9007199254741003",nanoseconds:"10"}],excluded:[{point:{...point,ordinal:3},kind:"timeout",reason:"measured_entry_unavailable"}],assumptions:["measured_core_step_envelope_not_internal_execution_milestones"]}]};
}

describe("recorded processing evidence",()=>{
 it("keeps known zero, missing entry and exact source coordinates distinct",()=>{
  const html=renderToStaticMarkup(<ProcessingEvidence model={fixture()} net={1} dataset={2}/>);
  for(const text of ["native-pre-dispatch/1","declared receive workers: 2 (unmeasured)","0 / 0 / 10","9007199254740993","9007199254741003","18446744073709551615","2 measured intervals · 1 exclusions · partial","measured_entry_unavailable","Open timing source 1","Open excluded source 3","Source SHA256 "+"a".repeat(64),"Unmeasured receive checks","not reconstructed"])expect(html).toContain(text);
  expect(html).not.toContain("NaN");expect(html).not.toContain("undefined");
 });
 it("bounds rendered rows while retaining independent sample and exclusion pagination",()=>{
  const model=fixture(),timing=model.timings[0]!;
  timing.samples=Array.from({length:101},(_,i)=>({...timing.samples[0]!,point:{...timing.samples[0]!.point,ordinal:i+1}}));
  timing.excluded=Array.from({length:102},(_,i)=>({...timing.excluded[0]!,point:{...timing.excluded[0]!.point,ordinal:i+201}}));
  const html=renderToStaticMarkup(<ProcessingEvidence model={model} net={1} dataset={2}/>);
  expect(html.match(/Open timing source /g)).toHaveLength(100);expect(html.match(/Open excluded source /g)).toHaveLength(100);
  expect(html).toContain("Measured intervals 1–100 of 101");expect(html).toContain("Source positions 1–100 of 102");
  expect(html).toContain("<button>Next timing page</button>");expect(html).toContain("<button>Next exclusion page</button>");
 });
 it("keeps historical models absent and empty evidence explicit",()=>{
  expect(renderToStaticMarkup(<ProcessingEvidence/>)).toBe("");
  const model=fixture();model.timings[0]!.samples=[];
  const html=renderToStaticMarkup(<ProcessingEvidence model={model}/>);
  expect(html).toContain("Measured intervals 0–0 of 0");expect(html).toContain('disabled="">Open excluded source');expect(html).not.toContain("undefined");
 });
});
