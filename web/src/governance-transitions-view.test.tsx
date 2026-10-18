import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {GovernanceTransitions} from "./views/GovernanceTransitions";

const address="0x"+"1".repeat(40),hash="a".repeat(64),digest={sha256:hash,bytes:32};
function example():Schemas["StoreGovernanceTransitionEvidenceList"]{
 const origin={path:"synthetic-implementation",version:"synthetic-version",sum:"synthetic-sum"},verifier={sha256:hash,origin};
 const execution:Schemas["ExecutionwitnessReport"]={protocol:"wbft-execution-witness/1",origin,source:{format:"wbft-execution-witness-input/1",node:address,chain_id:"7",genesis_hash:"0x"+hash,config_sha256:hash,manifest:digest,genesis:digest,blocks:[]},transactions:[]};
 const account={address,code_hash:"0x"+hash,storage_root:"0x"+hash,exists:true};
 const candidate={address,operator:address,key:{sha256:hash,bytes:0}};
 const registry:Schemas["ExecutionwitnessRegistryRead"]={status:"observed",reason:"reviewed_runtime",state:{layout:"wbft-validator-registry/1",address,code_hash:"0x"+hash,storage_root:"0x"+hash,candidates:[candidate],without_keys:[address]}};
 const block:Schemas["ExecutionwitnessBlockTransition"]={index:"2",genesis:false,before_system:[account],before_transactions:[account],after_transactions:[account],finalized:[account],epoch_registry:null};
 const proposal={id:"9",status:"1",action:"0x"+hash,call_data:digest,member_version:"1",created_at:"1",executed_at:"0",proposer:address,required_approvals:3,approved:2,rejected:0,execution_count:"0"};
 const point:Schemas["ExecutionwitnessTransactionTransition"]={index:"2",transaction_index:0,hash:"0x"+hash,block_hash:"0x"+hash,status:"observed",reason:"reviewed_runtime_writes",method:"configureValidator",accounts_before:[account],accounts_after:[account],writes:[{address,slot_sha256:hash,before:digest,after:digest,owner_code_hash:"0x"+hash,frame:0,path:[],reverted:false,instruction:{pc:"7",code_reference:address,code_hash:"0x"+hash}}],registry_before:registry,registry_after:registry,proposal_before:proposal,proposal_after:{...proposal,status:"3",execution_count:"1"},effects:[{kind:"candidate_key_changed",candidate:address,before:candidate,after:{...candidate,key:{sha256:hash,bytes:48}}}],cause_status:"verified_transaction_effect"};
 return {status:"matched",cause_status:"verified_transaction_effect",truncated:false,evidence:[{binding:"matched",status:"matched",cause_status:"verified_transaction_effect",reason:"verified_transaction_effect",witness:{dataset_id:1,snapshot:hash,execution_snapshot:hash,blocks:4,transactions:1,source:{verifier,report:{protocol:"wbft-governance-transitions/1",execution,blocks:[],transactions:[]}}},replay:{dataset_id:1,snapshot:hash,headers_dataset:2,header_source_id:2,blocks:4,transactions:1,source:{verifier,report:execution}},block,point,operation:null,next_epoch:{...block,index:"3",epoch_registry:registry}}]};
}
it("shows root effects, proposal state, no-key candidates and independent epoch state separately",()=>{
 const html=renderToStaticMarkup(<GovernanceTransitions value={example()}/>);
 for(const text of ["Transaction caused the displayed registry changes","Before system processing","After finalization","Registry before transaction","Registry after transaction","No public key","candidate key changed","Proposal 9: status voting","executed","execution count 0","Next replayed epoch header: 3","does not establish the cause of validator selection","SSTORE at 7"])expect(html).toContain(text);
 expect(html).toContain("gov-state-content");expect(html).not.toContain("raw storage");
 expect(html).toContain("State-proof key comparisons are shown separately");
});
it("keeps deleted canonical dependencies and unknown registry states visibly unverified",()=>{
 const value=example();value.status="unverified";value.cause_status="unestablished";const entry=value.evidence[0]!;entry.binding="source_unavailable";entry.status="unverified";entry.cause_status="unestablished";entry.reason="source_unbound";entry.replay.headers_dataset=null;entry.point!.registry_before={status:"unavailable",reason:"unsupported_runtime",state:null};
 const html=renderToStaticMarkup(<GovernanceTransitions value={value}/>);
 expect(html).toContain("Registry-change cause remains unestablished");expect(html).toContain("no longer available");expect(html).toContain("does not establish that it was unchanged");expect(html).not.toContain("This witness binds the effective root transaction");
});
it("does not invent a transaction for epoch-only or empty evidence",()=>{
 const value=example();value.cause_status="unestablished";const entry=value.evidence[0]!;entry.point=null;entry.next_epoch=null;entry.reason="header_state_only";entry.cause_status="unestablished";entry.block.epoch_registry=example().evidence[0]!.point!.registry_after;
 const html=renderToStaticMarkup(<GovernanceTransitions value={value}/>);
 expect(html).toContain("header state");expect(html).toContain("Registry at this epoch header");expect(html).not.toContain("Observed registry effects");
 value.evidence=[];expect(renderToStaticMarkup(<GovernanceTransitions value={value}/>)).toContain("No transition witness is attached");
});
it("preserves truncated evidence and reverted writes",()=>{
 const value=example();value.status="ambiguous";value.cause_status="ambiguous";value.truncated=true;value.evidence[0]!.point!.writes[0]!.reverted=true;
 const html=renderToStaticMarkup(<GovernanceTransitions value={value}/>);
 expect(html).toContain("Conflicting or truncated witnesses cannot establish a cause");expect(html).toContain("first 20 witnesses");expect(html).toContain("reverted");
});
it("retains an order-only candidate change as its own registry effect",()=>{
 const value=example();value.evidence[0]!.point!.effects=[{kind:"candidate_order_changed",candidate:"",before:null,after:null}];
 const html=renderToStaticMarkup(<GovernanceTransitions value={value}/>);
 expect(html).toContain("candidate order changed");expect(html).not.toContain("No candidate, order, key or operator effect was established");
});
