import {describe,expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {StaticChainSettings,SeedStaticChainSettings} from "./views/StaticChainSettings";

describe("static chain configuration evidence",()=>{
 it("keeps full activation heights and future allowance exact and separates source digests",()=>{
  const html=renderToStaticMarkup(<StaticChainSettings origin="Recorded" configuration={{source_rules_digest:"source-digest",rule_activations:{rejectNumberJump:"340282366920938463463374607431768211456"},allowed_future_block_time_seconds:"18446744073709551615"}}/>);
  for(const text of ["Recorded static chain settings","340282366920938463463374607431768211456","18446744073709551615","Source rules digest: source-digest","Chain rules apply to every node"])expect(html).toContain(text);
  expect(html).not.toContain("Generated rules digest");
 });
 it("displays observed writer and engine configurations without asserting source equality",()=>{
  const html=renderToStaticMarkup(<SeedStaticChainSettings observations={{source:"simulator_journal_chain_configuration/1",unobserved_nodes:[3],journal_configurations:[{node:0,run:"simulated-run",engine_run:"0",journal_segments:2,chain_config_sha256:"config-sha",generated_rules_digest:"generated-digest",configuration:{rule_activations:{rejectNumberJump:"0"},allowed_future_block_time_seconds:"3"}}]}}/>);
  for(const text of ["Read from this seed’s generated journals","may differ from the source configuration digest","Nodes without configuration observations: 3","engine 0","Observed static chain settings","Generated rules digest: generated-digest","Chain configuration SHA256: config-sha"])expect(html).toContain(text);
  expect(html).not.toContain("Source rules digest:");
 });
 it("keeps missing historical settings distinct from an observed empty rule set",()=>{
  const missing=renderToStaticMarkup(<StaticChainSettings origin="Modeled"/>);
  expect(missing).toContain("not retained separately");expect(missing).not.toContain("No active chain rules");
  expect(renderToStaticMarkup(<SeedStaticChainSettings/>)).toContain("not retained for this seed");
  expect(renderToStaticMarkup(<StaticChainSettings origin="Observed" configuration={{rule_activations:{},allowed_future_block_time_seconds:"0"}}/>)).toContain("No active chain rules in this configuration");
 });
});
