import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { ScenarioComparison } from "./views/ScenarioComparison";
import { EmpiricalModel,EngineHistories,TransportScopeEvidence } from "./views/Scenarios";
import { pixel,extent,ecdfPath,bandPath } from "./scenario-chart";
import { parseRoute } from "./App";
function group():Schemas["ScenarioDistribution"]{
 return {status:"complete",saved_runs:2,expected_runs:2,complete_runs:2,samples:4,issue:"",rounds:[{value:"0",cumulative:.75,count:3},{value:"9007199254740993",cumulative:1,count:1}],period_seconds:[{value:"1",cumulative:.5,count:2},{value:"4",cumulative:1,count:2}],elapsed_seconds:[{height:"1",minimum:"0",median:"0",maximum:"0",seeds:2},{height:"2",minimum:"1",median:"1",maximum:"4",seeds:2}]};
}
describe("network scenario comparison",()=>{
 it("keeps closed transport observations separate from physical delivery and baseline credibility",()=>{
  const certificate={id:"certificate",kind:"transport-certificate",node:"node-a",sha256:"a".repeat(64)};
  const scope:Schemas["ScenarioTransportScope"]={status:"closed_observer_scope",controller:{...certificate,id:"controller",kind:"transport-controller",node:"network"},sources:[certificate],cutoff:"2026-01-01T00:00:03Z",through_height:"9007199254740993",physical_delivery_proven:false,assumptions:["peer_info_lists_all_other_live_nodes"],windows:[{input:"wire-a",certificate,node:"node-a",run:"writer",from:"2026-01-01T00:00:00Z",to:"2026-01-01T00:00:04Z",settled_through:"2026-01-01T00:00:03Z",frame_sha256:"b".repeat(64)}],sessions:[{input:"wire-a",node:"node-a",peer:"node-b",run:"writer",from:"2026-01-01T00:00:00Z",to:"2026-01-01T00:00:04Z",from_line:1,to_line:40}]};
  const html=renderToStaticMarkup(<TransportScopeEvidence scope={scope}/>);
  expect(html).toContain("9007199254740993");expect(html).toContain("Receiver windows (1)");expect(html).toContain("Local peer sessions (1)");expect(html).toContain("lines 1–40");expect(html).toContain("do not prove physical network delivery");expect(html).toContain("controller attestations");expect(html).toContain("Baseline round and time validation remain separate");expect(html).toContain("peer info lists all other live nodes");expect(html).not.toContain("/private/");
  expect(html).not.toContain("Verified header prefix and reported tips");
  scope.header_checkpoint={at:"2026-01-01T00:00:02Z",heads:[{node:"node-a",reported_head:"18446744073709551615"},{node:"node-b",reported_head:"9007199254740993"}]};
  const checkpoint=renderToStaticMarkup(<TransportScopeEvidence scope={scope}/>);
  for(const text of ["Verified header prefix and reported tips","2026-01-01T00:00:02Z","18446744073709551615","Controller-reported tip","Verified through","Later reported tip heights remain controller attestations"])expect(checkpoint).toContain(text);
 });
 it("distinguishes engine pauses, node shutdown and unavailable lifecycle evidence",()=>{
  const runtime:Schemas["ScenarioRuntime"]={node:"native",input:"events",starts:1,start_ns:0,sign_floor_state:"none",sign_floor:null,engine_stop_observed:true,wal_replay:true,events:[],wal_policies:[{run:"writer",engine_run:"9007199254740993",line:2,enabled:true,available:true,replayed:false,status:"complete"}],engine_history:{status:"partial",actions:[],issues:[{code:"engine_history_not_closed",run:"writer",line:12}],instances:[{run:"writer",engine_run:"1",start_ns:0,stop_ns:1,start_line:2,stop_line:4,initial:true,node_shutdown:false},{run:"writer",engine_run:"2",start_ns:2,stop_ns:3,start_line:5,stop_line:8,initial:false,node_shutdown:true},{run:"writer",engine_run:"9007199254740993",start_ns:4,stop_ns:null,start_line:9,stop_line:0,initial:false,node_shutdown:false}]}};
  const html=renderToStaticMarkup(<EngineHistories runtimes={[runtime]}/>);
  expect(html).toContain("1 node starts");expect(html).toContain("3 engine instances");expect(html).toContain("partial");expect(html).toContain("engine pause");expect(html).toContain("node shutdown");expect(html).toContain("unclosed");expect(html).toContain("engine_history_not_closed");expect(html).toContain("line 12");expect(html).toContain("9007199254740993");expect(html).toContain("enabled true");expect(html).toContain("Closed observations do not establish baseline credibility");
  expect(renderToStaticMarkup(<EngineHistories runtimes={[{...runtime,engine_history:null}]}/>)).not.toContain("3 engine instances");
 });
 it("labels substitute assumptions and keeps excluded measurements visible",()=>{
  const source={id:"wire",kind:"frames",node:"synthetic-node",sha256:"a".repeat(64)};
  const model:Schemas["ScenarioEmpiricalProjection"]={assumptions:["fresh_test_keys_genesis_no_replay"],nodes:[{node:"synthetic-node",substituted:true,source,improvements:"0",backlog_limit:0,profile:"compat",wal_replay:false,option_evidence:"modeled_core_substitution",runtime_evidence:"modeled_core_substitution",signing_state:"fresh_test_keys_genesis_no_replay",parameter_evidence:"static_wbft_parameters_verified",application_policy:"independent_request_sampled_empty_body"}],runtime_timings:[{source:{...source,id:"runtime",kind:"runtime"},build:[],import:[],excluded:[{kind:"import",id:"9007199254740993",reason:"not_single_block",from_line:1,to_line:2}],task_states:{observed_cancellation:3},import_results:{ok:1}}],application:{policies:[],outcomes:[],unsupported:0,unproved:0,build:[],import:[]},native_excluded:[],runtimes:[]};
  const html=renderToStaticMarkup(<EmpiricalModel model={model}/>);
  expect(html).toContain("static wbft parameters verified");expect(html).toContain("Substituted WBFT core");expect(html).toContain("WAL replay disabled");expect(html).toContain("fresh test keys genesis no replay");expect(html).toContain("9007199254740993");expect(html).toContain("not_single_block");expect(html).toContain("observed_cancellation=3");expect(html).toContain("Baseline validation is required");expect(html).toContain("scenario-unproved");
 });
 it("keeps full integers exact before the final pixel ratio",()=>{
  const domain=extent(["9007199254740994","9007199254740992","9007199254740993"]);
  expect(domain).toEqual(["9007199254740992","9007199254740994"]);
  expect(pixel("9007199254740993",domain,700)).toBe(350);
  expect(ecdfPath([{value:"9007199254740993",cumulative:.5,count:1}],domain)).toContain("H350V95");
  const bands=group().elapsed_seconds,before=JSON.stringify(bands);
  expect(bandPath(bands,["1","2"],["0","4"])).toContain("700,0");expect(JSON.stringify(bands)).toBe(before);
 });
 it("uses the API baseline credibility without promoting unknown states",()=>{
  const plot:Schemas["ScenarioComparisonPlot"]={from:"1",to:"2",credibility:"baseline_reproduced",recorded_sha256:"a".repeat(64),recorded:group(),baseline:group(),counterfactual:group()};
  const html=renderToStaticMarkup(<ScenarioComparison plot={plot}/>);
  expect(html).not.toContain("Baseline not established");expect(html).not.toContain("scenario-unproved");expect(html).toContain("does not establish physical equivalence");
  for(const credibility of ["reproduced","execution_incomplete","baseline_rounds_failed","baseline_time_unproved","unknown"]){
   const other=renderToStaticMarkup(<ScenarioComparison plot={{...plot,credibility}}/>);
   expect(other).toContain("Baseline not established");expect(other).toContain("scenario-unproved");
  }
 });
 it("labels failed credibility and preserves exact ECDF values",()=>{
  const incomplete={...group(),status:"incomplete",samples:0,rounds:[],period_seconds:[],elapsed_seconds:[],saved_runs:1,complete_runs:1,issue:"seed_executions_incomplete"};
  const plot:Schemas["ScenarioComparisonPlot"]={from:"1",to:"2",credibility:"time_unproved",recorded_sha256:"a".repeat(64),recorded:group(),baseline:group(),counterfactual:incomplete};
  const html=renderToStaticMarkup(<ScenarioComparison plot={plot}/>);
  expect(html).toContain("Baseline not established");expect(html).toContain("scenario-unproved");expect(html).toContain("9007199254740993");expect(html).toContain("Counterfactual seeds");expect(html).toContain("seed_executions_incomplete");expect(html).toContain("not confidence intervals");expect(html).not.toContain("NaN");
  expect(parseRoute("#/networks/7/scenarios")).toEqual({view:"scenarios",net:7});
 });
});
