import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { parseRoute } from "./App";
import { ReexecSummary, WarmupSummary, ApplicationAnswerSummary, ScheduleComparison } from "./views/Reexec";

describe("closed replay evidence",()=>{
 it("keeps partial inputs and unknown versions visible without numeric truncation",()=>{
 const run:Schemas["StoreReexecRun"]={id:1,dataset_id:2,input_id:"journal",from_height:"1",to_height:"2",created_at:"2026-01-01T00:00:00Z",finished_at:null,status:"partial",summary:{warmup_suspect:0,version:"wbft-closed-reexec/1",status:"partial",helper_version:"unknown",binary_version:"unknown",helper_sha256:"a".repeat(64),version_status:"unknown",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:["unknown"],heights:[{height:"18446744073709551616",status:"partial",issues:["wire_association"],steps:1}],steps:1,matches:0,mismatches:0,not_comparable:1}};
 const html=renderToStaticMarkup(<ReexecSummary run={run}/>);
 expect(html).toContain("Regression comparison");expect(html).toContain("18446744073709551616");expect(html).toContain("wire_association");expect(html).toContain("not comparable");expect(html).not.toContain("reproduced");
 });
 it("labels intentional input loss independently of version identity",()=>{
 const run:Schemas["StoreReexecRun"]={id:3,dataset_id:2,input_id:"journal",from_height:"1",to_height:"1",created_at:"2026-01-01T00:00:00Z",finished_at:null,status:"counterfactual",summary:{warmup_suspect:0,mode:"counterfactual",version:"wbft-closed-reexec/1",status:"counterfactual",helper_version:"same",binary_version:"same",helper_sha256:"a".repeat(64),version_status:"matched",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:["same"],heights:[],steps:1,matches:0,mismatches:1,not_comparable:0}};
 const html=renderToStaticMarkup(<ReexecSummary run={run}/>);
 expect(html).toContain("Counterfactual input loss");expect(html).toContain("cannot establish reproduction");expect(html).toContain("recorded application answers");
 });
 it("keeps prefix failures separate from selected matches",()=>{
 const run:Schemas["StoreReexecRun"]={id:4,dataset_id:2,input_id:"journal",from_height:"2",to_height:"2",created_at:"2026-01-01T00:00:00Z",finished_at:null,status:"diverged",summary:{warmup_suspect:0,version:"wbft-closed-reexec/1",status:"diverged",helper_version:"unknown",binary_version:"unknown",helper_sha256:"a".repeat(64),version_status:"unknown",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:[],heights:[],steps:1,matches:1,mismatches:0,not_comparable:0,warmup:{policy:"recorded_start",status:"diverged",steps:1,matches:0,mismatches:1,not_comparable:0,first_source_ordinal:12,last_source_ordinal:12,first_difference:{ordinal:12,file:"00000000000000000000.wal",writer_run:"synthetic-source",engine_run:"18446744073709551615",step:"1",height:"1",input:"start",recorded_digest:"0x"+"b".repeat(64),class:"output_diverged",completeness:"complete",issues:[]}}}};
 const html=renderToStaticMarkup(<WarmupSummary run={run} onSource={()=>{}}/>);
 expect(html).toContain("Selected matches cannot establish reproduction");expect(html).toContain("Open prefix source 12");expect(html).toContain("18446744073709551615");expect(html).toContain("separate from the selected comparison");
 });
 it("separates approximate differences from exact mismatches and names unknown state",()=>{
 const run:Schemas["StoreReexecRun"]={id:5,dataset_id:2,input_id:"journal",from_height:"25",to_height:"30",created_at:"2020-01-01T00:00:00Z",finished_at:null,status:"partial",summary:{warmup_suspect:1,version:"wbft-closed-reexec/1",status:"partial",helper_version:"unknown",binary_version:"unknown",helper_sha256:"a".repeat(64),version_status:"different",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:[],heights:[],steps:2,matches:1,mismatches:0,not_comparable:0,warmup:{policy:"bounded",status:"approximate",from_height:"23",compare_from_height:"25",steps:4,matches:3,mismatches:0,suspects:1,not_comparable:0}}};
 const html=renderToStaticMarkup(<ReexecSummary run={run}/>);
 expect(html).toContain("1 approximate differences");expect(html).toContain("0 different");expect(html).toContain("Prior backlog, view and timer state are unknown");expect(html).toContain("recorded engine start restores exact state");expect(html).toContain("Selected matches cannot establish reproduction");
 });
 it("labels context lookup without claiming intentional input loss",()=>{
 const run:Schemas["StoreReexecRun"]={id:6,dataset_id:2,input_id:"journal",from_height:"1",to_height:"1",created_at:"2020-01-01T00:00:00Z",finished_at:null,status:"counterfactual",summary:{answer_scope:"context",warmup_suspect:0,mode:"counterfactual",version:"wbft-closed-reexec/1",status:"counterfactual",helper_version:"same",binary_version:"same",helper_sha256:"a".repeat(64),version_status:"matched",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:["same"],heights:[],steps:1,matches:1,mismatches:0,not_comparable:0}};
 const html=renderToStaticMarkup(<ReexecSummary run={run}/>);
 expect(html).toContain("Context application lookup: counterfactual");expect(html).toContain("Matching outputs cannot establish original reproduction");expect(html).toContain("original call position");expect(html).not.toContain("missing captured inputs were intentionally omitted");
 const old={...run,summary:{...run.summary,answer_scope:undefined}};
 expect(renderToStaticMarkup(<ApplicationAnswerSummary run={old}/>)).toContain("no recorded application answer policy");
 });
 it("routes core replay separately from recorded event playback",()=>{expect(parseRoute("#/networks/7/reexec")).toEqual({view:"reexec",net:7});expect(parseRoute("#/networks/7/events").view).toBe("events")});
});

describe("input schedule evidence",()=>{
 it("shows original and execution order separately with original source links",()=>{
  const row=(ordinal:number,execution:number,step:string):Schemas["ReexecStep"]=>({ordinal,execution_ordinal:execution,file:"00000000000000000000.wal",writer_run:"synthetic",engine_run:"18446744073709551615",step,height:"1",execution_height:"1",input:"captured_message",recorded_digest:"0x"+"a".repeat(64),class:"output_diverged",completeness:"complete",issues:[],scheduled_input:{writer_run:"synthetic",engine_run:"18446744073709551615",step,reader_ordinal:ordinal,source_seq:step,execution_step:String(execution),slot_step:String(execution),slot_reader_ordinal:execution,slot_source_seq:String(execution)}});
  const html=renderToStaticMarkup(<ScheduleComparison steps={[row(20,10,"2"),row(10,20,"1")]} onSource={()=>{}}/>);
  const recorded=html.slice(html.indexOf("<h4>Recorded"),html.indexOf("<h4>Experiment"));const experiment=html.slice(html.indexOf("<h4>Experiment"));
  expect(recorded.indexOf("Source 10")).toBeLessThan(recorded.indexOf("Source 20"));expect(experiment.indexOf("Source 20")).toBeLessThan(experiment.indexOf("Source 10"));expect(html).toContain("inspect the original source");
 });
});
