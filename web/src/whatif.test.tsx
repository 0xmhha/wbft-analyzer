import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { WhatifEvidence, WhatifSummary } from "./views/Whatif";
import { parseRoute } from "./App";
import type { Schemas } from "./api/client";

describe("timer experiment evidence",()=>{
 it("keeps generated inputs separate from source positions and preserves large views",()=>{
 const source={writer_run:"synthetic",engine_run:"9007199254740993",step:"2",ordinal:"3"};
 const step:Schemas["WhatifStep"]={output_actions:[],recorded_output_actions:[],parent_output:"1",execution_step:"4",t_mono_ns:"5",execution_state:{running:true,height:"9007199254740994",round:"9007199254740995",state:"Prepared"},source_input:null,cause:source,parent_execution_step:"1",timer_arm:source,timer_arm_execution_step:"1",timer_deadline_mono_ns:"5",signing_evidence:null,application_question_sources:[],answer_sources:[],generated:true,suppression_reason:"",input:"timeout",out_digest:"0x"+"a".repeat(64),outputs:1,comparable:false,match:false,counterfactual:true,execution_model:"recorded-external-slots/zero-generated-processing/recorded-signing-results/1"};
 const html=renderToStaticMarkup(<WhatifEvidence step={step}/>);
 expect(html).toContain("no original source ordinal");expect(html).toContain("9007199254740993");expect(html).toContain("Original input: none");expect(html).not.toContain("payload");
 });
 it("labels the finite counterfactual horizon and an explicit partial failure",()=>{
 const run:Schemas["StoreWhatifRun"]={id:1,dataset_id:2,input_id:"journal",chain_sha256:"a".repeat(64),source_sha256:"b".repeat(64),helper_sha256:"c".repeat(64),policy_sha256:"d".repeat(64),timer_policy:{request_timeout_seconds:"2"},created_at:"2026-10-14T00:00:00Z",finished_at:null,status:"partial",summary:{replaced_original_timers:null,version:"wbft-timer-experiment/1",execution_model:"recorded-external-slots/zero-generated-processing/recorded-signing-results/1",status:"partial",issue:"signing_unavailable",failure_execution_step:"659",baseline_validated:true,timer_trace_validated:true,helper_version:"unknown",source_versions:[],steps:658,generated_steps:20,source_steps:638,scopes:[],horizon:"",future_tail_generated:false}};
 const html=renderToStaticMarkup(<WhatifSummary run={run}/>);
 expect(html).toContain("Counterfactual");expect(html).toContain("recorded signing results");expect(html).toContain("execution 659");expect(html).toContain("Remaining effects are unknown");expect(html).toContain("cannot prove the network");
 expect(parseRoute("#/networks/7/whatif")).toEqual({view:"whatif",net:7});
 });
});
