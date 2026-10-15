import type { Schemas } from "../api/client";

type Configuration = Schemas["ScenarioStaticChainConfiguration"];
type Observations = Schemas["ScenarioSeedStaticConfigurationObservations"];

export function StaticChainSettings({configuration,origin}:{configuration?:Configuration|null;origin:"Recorded"|"Modeled"|"Observed"}){
 if(!configuration)return <p>{origin} static chain settings were not retained separately for this record.</p>;
 const rules=Object.entries(configuration.rule_activations).sort(([a],[b])=>a.localeCompare(b));
 return <details><summary>{origin} static chain settings</summary><p>Future block time allowance: {configuration.allowed_future_block_time_seconds} seconds. Chain rules apply to every node; node timing overrides do not replace them.</p>
 {rules.length?<table><thead><tr><th>Chain rule</th><th>Activation height</th></tr></thead><tbody>{rules.map(([name,height])=><tr key={name}><td>{name}</td><td>{height}</td></tr>)}</tbody></table>:<p>No active chain rules in this configuration.</p>}
 {configuration.source_rules_digest&&<p className="mono">Source rules digest: {configuration.source_rules_digest}</p>}
 </details>;
}

export function SeedStaticChainSettings({observations}:{observations?:Observations|null}){
 if(!observations)return <p>Static chain settings observations were not retained for this seed.</p>;
 return <section aria-label="Observed seed chain settings"><h4>Observed seed chain settings</h4><p>Read from this seed’s generated journals. Generated digests include simulator parameters and may differ from the source configuration digest.</p>
 {observations.unobserved_nodes.length>0&&<p>Nodes without configuration observations: {observations.unobserved_nodes.join(", ")}</p>}
 {observations.journal_configurations.map(row=><details key={`${row.node}:${row.run}:${row.engine_run}`}><summary>Node {row.node} · writer {row.run} · engine {row.engine_run} · {row.journal_segments} segments</summary><StaticChainSettings origin="Observed" configuration={row.configuration}/><p className="mono">Generated rules digest: {row.generated_rules_digest}<br/>Chain configuration SHA256: {row.chain_config_sha256}</p></details>)}
 {observations.journal_configurations.length===0&&<p>No generated configuration was observed.</p>}
 </section>;
}
