import {describe,expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {SeedDiagnostics} from "./views/SeedDiagnostics";

function seed():Schemas["ScenarioSeedResult"]{
 return {seed:1,status:"violations",heights:[],simulation_ns:120000000000,violations:2,execution:{configured_stop_height:"18446744073709551615",configured_duration_ns:"120000000000",nodes:[{index:0,simulated_address:"simulated-node-a",head:"9007199254740993"}],violations:[{kind:"progress",simulated_node:"simulated-node-a",detail:"head below configured target"},{kind:"agreement",simulated_node:"simulated-node-b",detail:"conflicting block hashes"}]}};
}
describe("seed execution diagnostics",()=>{
 it("shows official progress and safety outcomes independently with exact heads",()=>{
  const html=renderToStaticMarkup(<SeedDiagnostics mode="Counterfactual" rows={[seed()]} expected={32}/>);
  for(const text of ["Counterfactual seed diagnostics (1/32 saved)","18446744073709551615","9007199254740993","120000000000","2 violations","progress","agreement","head below configured target","conflicting block hashes","Addresses below belong to simulated test keys"])expect(html).toContain(text);
  expect(html).not.toContain("No simulator violations");
 });
 it("does not infer historical violation kinds or heads from counts",()=>{
  const r=seed();delete r.execution;
  const html=renderToStaticMarkup(<SeedDiagnostics mode="Counterfactual" rows={[r]} expected={32}/>);
  expect(html).toContain("2 violations");expect(html).toContain("Execution details were not retained");expect(html).toContain("counts do not establish a cause");expect(html).not.toContain("progress");expect(html).not.toContain("Last head");
 });
 it("keeps a saved prefix separate from expected completion and detects conflicting details",()=>{
  expect(renderToStaticMarkup(<SeedDiagnostics mode="Baseline" rows={[]} expected={32}/>)).toContain("No seed outcomes retained yet");
  const r=seed();r.execution!.violations=[];
  const html=renderToStaticMarkup(<SeedDiagnostics mode="Counterfactual" rows={[r]} expected={32}/>);
  expect(html).toContain("Stored violation count and details disagree");expect(html).not.toContain("No simulator violations reported");
 });
});
