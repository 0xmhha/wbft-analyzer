import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {membershipChange,type SyntheticNodeFields} from "./membership-change";
import {MembershipChangeForm} from "./views/MembershipChangeForm";
import {NetworkChangeEvidence} from "./views/NetworkChangeEvidence";
import {SeedMembershipEvidence,MembershipEvidence} from "./views/MembershipEvidence";
import type {Schemas} from "./api/client";

const node=():SyntheticNodeFields=>({alias:"new-test",start:"2000000000",timeout:"2",period:"1",cap:"0",build:"0,1000000",imports:"1000000"});
const links=Array.from({length:4},(_,i)=>`${i} -> 4 | 1000000,2000000 | 0\n4 -> ${i} | 3000000 | 123`).join("\n");

it("supports removal without fabricating node or link models",()=>{
 const c=membershipChange(4,60000000000,"replace_from_first_epoch",[],"","8: 3,0,2\n4: 0,1,2,3");
 expect(c).toEqual({kind:"synthetic_membership",from_ns:0,to_ns:60000000000,membership:{policy:"replace_from_first_epoch",nodes:[],links:[],epochs:[{block:"4",candidates:[0,1,2,3]},{block:"8",candidates:[3,0,2]}]}});
 const html=renderToStaticMarkup(<NetworkChangeEvidence change={c}/>);
 expect(html).toContain("Requested candidates do not prove actual validator selection");expect(html).toContain("Synthetic nodes (0)");expect(html).not.toContain("Reverse links");
});

it("keeps explicit synthetic timing, app and link samples as integer strings",()=>{
 const c=membershipChange(4,60000000000,"merge",[node()],links,"4: 0,1,2,3,4");
 if(c.kind!=="synthetic_membership")throw new Error("wrong kind");
 expect(c.membership.nodes[0]).toEqual({alias:"new-test",model:"unmeasured_compat",start_ns:"2000000000",timing:{request_timeout_seconds:"2",block_period_seconds:"1",max_request_timeout_seconds:"0"},build_delay:[{ns:"0"},{ns:"1000000"}],import_delay:[{ns:"1000000"}]});
 expect(c.membership.links).toHaveLength(8);expect(c.membership.links[4]).toEqual({from:4,to:0,delays:[{ns:"3000000"}],loss_ppm:"123"});
 const html=renderToStaticMarkup(<MembershipChangeForm nodes={["a","b","c","d"]} duration={60000000000} disabled={false} busy={false} onSubmit={async()=>{}}/>);
 expect(html).toContain("New nodes append after the recorded indices");expect(html).toContain("Synthetic membership request");expect(html).toContain("Synthetic node and link values have no measured provenance");expect(html).toContain("can reverse an earlier synthetic change");
});

it("refuses missing directions and undeclared runtime values before queueing",()=>{
 for(const text of ["",links.split("\n").slice(1).join("\n"),`${links}\n0 -> 4 | 0 | 0`,links.replace("0 -> 4","0 -> 1"),links.replace("0 -> 4","5 -> 4"),links.replace("| 123","| 1000000"),links.replace("| 123","| 1.5"),links.replace("3000000","-1")])expect(()=>membershipChange(4,60000000000,"merge",[node()],text,"4: 0,1,2,3,4")).toThrow();
 for(const n of [{...node(),timeout:"0"},{...node(),cap:""},{...node(),start:"60000000000"},{...node(),build:""},{...node(),imports:"3600000000001"},{...node(),alias:"../key"}])expect(()=>membershipChange(4,60000000000,"merge",[n],links,"4: 0,1,2,3,4")).toThrow();
 for(const text of ["","4: 0,1,2,3","4: 0,1,2,3,4,4","4: 0,1,2,3,5","4: 0,1,2,3,4\n4: 0,1,2,3,4","04: 0,1,2,3,4"])expect(()=>membershipChange(4,60000000000,"merge",[node()],links,text)).toThrow();
 expect(()=>membershipChange(4,60000000000,"unknown",[node()],links,"4: 0,1,2,3,4")).toThrow();
});

it("paginates the full bounded synthetic directed graph",()=>{
 const all=Array.from({length:256},(_,from)=>Array.from({length:256},(_,to)=>({from,to,delays:[{ns:"1"}],loss_ppm:"0"}))).flat().filter(l=>l.from!==l.to&&(l.from>=2||l.to>=2));
 const c={kind:"synthetic_membership" as const,from_ns:0,to_ns:1000,membership:{policy:"merge" as const,nodes:[],links:all,epochs:[{block:"4",candidates:[0,1]}]}};
 const html=renderToStaticMarkup(<NetworkChangeEvidence change={c}/>);
 expect(html).toContain("Showing 1–100 of 65278 synthetic directions");expect(html).toContain("Last synthetic links");expect(html).not.toContain('<td>255</td><td>254</td>');
});

it("distinguishes actual canonical header membership from per-node agreement",()=>{
 const html=renderToStaticMarkup(<SeedMembershipEvidence observations={{source:"official_simulator_epoch_headers/1",scope:"longest_result_chain_not_each_node",unobserved_requests:[{block:"8",candidates:[0,2]}],epochs:[{block:"4",block_hash:"synthetic-hash",governs_from:"5",next_block_observed:false,candidates:[{node:4,simulated_address:"test-new",diligence:"18446744073709551615"}],validators:[{node:4,candidate_index:0,simulated_address:"test-new"}]}]}}/>);
 expect(html).toContain("does not establish what each node imported");expect(html).toContain("Requested epochs without an observed header (1)");expect(html).toContain("18446744073709551615");expect(html).toContain("4 (candidate 0)");expect(html).toContain("not observed");expect(html).not.toContain("all nodes agree on");
});

it("shows candidate state inputs separately from the requested selection epoch",()=>{
 const change=membershipChange(4,60000000000,"merge",[],"","4: 0,1,2");
 if(change.kind!=="synthetic_membership")throw new Error("membership fixture has another kind");
 const effect:Schemas["ScenarioMembershipEffect"]={source:"declared_synthetic_membership/1",baseline_execution_sha256:"baseline",counterfactual_execution_sha256:"counterfactual",original_nodes:4,genesis_validators:4,synthetic_nodes:[],original_epochs:[],retained_epochs:[],removed_epochs:[],effective_epochs:[{block:"4",candidates:[0,1,2]}],assumptions:[],candidate_inputs:[{phase:"effective",index:0,epoch:"18446744073709551615",candidate_state_block:"18446744073709551614"}]};
 const html=renderToStaticMarkup(<MembershipEvidence change={change} effect={effect}/>);
 for(const text of ["Candidate input heights","not observed governance execution times","Selected epoch","Candidate state block","18446744073709551615","18446744073709551614"])expect(html).toContain(text);
 delete effect.candidate_inputs;
 expect(renderToStaticMarkup(<MembershipEvidence change={change} effect={effect}/>)).not.toContain("Candidate input heights");
});
