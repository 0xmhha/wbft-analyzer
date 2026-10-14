import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { ScenarioComparison } from "./views/ScenarioComparison";
import { pixel,extent,ecdfPath,bandPath } from "./scenario-chart";
import { parseRoute } from "./App";
function group():Schemas["ScenarioDistribution"]{
 return {status:"complete",saved_runs:2,expected_runs:2,complete_runs:2,samples:4,issue:"",rounds:[{value:"0",cumulative:.75,count:3},{value:"9007199254740993",cumulative:1,count:1}],period_seconds:[{value:"1",cumulative:.5,count:2},{value:"4",cumulative:1,count:2}],elapsed_seconds:[{height:"1",minimum:"0",median:"0",maximum:"0",seeds:2},{height:"2",minimum:"1",median:"1",maximum:"4",seeds:2}]};
}
describe("network scenario comparison",()=>{
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
