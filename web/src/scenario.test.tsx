import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { ScenarioComparison } from "./views/ScenarioComparison";
import { EmpiricalModel } from "./views/Scenarios";
import { pixel,extent,ecdfPath,bandPath } from "./scenario-chart";
import { parseRoute } from "./App";
function group():Schemas["ScenarioDistribution"]{
 return {status:"complete",saved_runs:2,expected_runs:2,complete_runs:2,samples:4,issue:"",rounds:[{value:"0",cumulative:.75,count:3},{value:"9007199254740993",cumulative:1,count:1}],period_seconds:[{value:"1",cumulative:.5,count:2},{value:"4",cumulative:1,count:2}],elapsed_seconds:[{height:"1",minimum:"0",median:"0",maximum:"0",seeds:2},{height:"2",minimum:"1",median:"1",maximum:"4",seeds:2}]};
}
describe("network scenario comparison",()=>{
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
 it("labels failed credibility and preserves exact ECDF values",()=>{
  const incomplete={...group(),status:"incomplete",samples:0,rounds:[],period_seconds:[],elapsed_seconds:[],saved_runs:1,complete_runs:1,issue:"seed_executions_incomplete"};
  const plot:Schemas["ScenarioComparisonPlot"]={from:"1",to:"2",credibility:"time_unproved",recorded_sha256:"a".repeat(64),recorded:group(),baseline:group(),counterfactual:incomplete};
  const html=renderToStaticMarkup(<ScenarioComparison plot={plot}/>);
  expect(html).toContain("Baseline not established");expect(html).toContain("scenario-unproved");expect(html).toContain("9007199254740993");expect(html).toContain("Counterfactual seeds");expect(html).toContain("seed_executions_incomplete");expect(html).toContain("not confidence intervals");expect(html).not.toContain("NaN");
  expect(parseRoute("#/networks/7/scenarios")).toEqual({view:"scenarios",net:7});
 });
});
