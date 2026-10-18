import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {EpochRegistry,EpochRegistryRows,EpochRegistryDetail,epochRegistryRowKey,registryRowResult} from "./views/EpochRegistry";
import type {Schemas} from "./api/client";

type Row=Schemas["StoreEpochRegistryRow"];
type Page=Schemas["EpochRegistryPage"];
const address=(n:number)=>"0x"+n.toString(16).padStart(40,"0"),snapshot="a".repeat(64);
const candidate={address:address(3),operator:address(4),key:{sha256:"b".repeat(64),bytes:48}};
const state:Row={kind:"epoch_state",dataset_id:7,dataset_name:"synthetic source",node:"synthetic-node",capture_snapshot:snapshot,witness_snapshot:"c".repeat(64),execution_snapshot:"d".repeat(64),header_source_id:8,headers_dataset:8,verifier:{sha256:"e".repeat(64),origin:{path:"example.invalid/node",version:"v1",sum:"synthetic"}},config_sha256:"f".repeat(64),binding:"matched",status:"matched",reason:"header_state_only",epoch_header_status:"matched",registry:{status:"observed",reason:"reviewed_runtime",state:{layout:"wbft-validator-registry/1",address:address(1),code_hash:"0x"+"1".repeat(64),storage_root:"0x"+"2".repeat(64),candidates:[candidate],without_keys:[]}},effect:null,operations:[],operations_truncated:false};
const effect:Row={...state,kind:"transaction_effect",status:"verified_retained_registry_effect",reason:"verified_retained_registry_effect",registry:null,effect:{index:"12",transaction_index:0,hash:"0x"+"3".repeat(64),effect_ordinal:0,change:{kind:"candidate_added",candidate:candidate.address,before:null,after:candidate},retention:{status:"verified_retained_registry_effect",reason:"verified_retained_registry_effect",transaction_index:"12",epoch_index:"20",checked_blocks:9,checked_transactions:2}},operations:[{call_ordinal:1,entry_ordinal:501,normalized_pointer:"/data/500",status:"matched",comparisons_truncated:false}]};
const page=(rows:Row[]):Page=>({index:"20",hash:"0x"+"4".repeat(64),status:"available",snapshot,rows,total:rows.length,next:null});

it("opens replay evidence only when requested",()=>{
 const html=renderToStaticMarkup(<EpochRegistry net={2} index="20" onAuth={()=>{}}/>);
 expect(html).toContain("Inspect replayed registry effects");expect(html).toContain('aria-expanded="false"');expect(html).not.toContain("Epoch registry evidence");
});
it("keeps retained registry effects separate from epoch selection and links the exact operation",()=>{
 const html=renderToStaticMarkup(<EpochRegistryRows net={2} value={page([state,effect])} selected={epochRegistryRowKey(effect)}/>);
 expect(html).toContain("Registry effect retained to this epoch");expect(html).toContain("Validator selection and diligence remain separate header comparisons");
 expect(html).toContain("entry=501&amp;collection=operations&amp;snapshot="+snapshot);expect(html).toContain("Examined 9 blocks and 2 transactions");expect(html).toContain("Not a registry candidate");
});
it("preserves the unverified current source even when its historical retention was checked",()=>{
 const unavailable:Row={...effect,binding:"source_unavailable",headers_dataset:null,status:"unverified",reason:"source_unbound"};
 const html=renderToStaticMarkup(<EpochRegistryDetail net={2} row={unavailable}/>);
 expect(registryRowResult(unavailable)).toBe("Original sources remain unverified");expect(html).toContain("no longer available");expect(html).toContain("Historical replay comparison");expect(html).toContain("Current attribution remains unverified");
});
it("does not turn an empty result into absent operations or complete history",()=>{
 const html=renderToStaticMarkup(<EpochRegistryRows net={2} value={page([])}/>);
 expect(html).toContain("does not establish that no operation occurred or that history is complete");
});
it("keeps initial registry state independent from the genesis validator set",()=>{
 const initial:Row={...state,reason:"initial_registry_state",epoch_header_status:"not_compared_genesis"};
 const html=renderToStaticMarkup(<EpochRegistryRows net={2} value={{...page([initial]),index:"0",status:"genesis"}}/>);
 expect(html).toContain("initial validator set can predate the loaded registry");expect(html).toContain("Initial registry state observed");expect(html).not.toContain("Registry and epoch header match");
});
it("exposes original operation and witness comparison truncation",()=>{
 const partial:Row={...effect,status:"unverified",reason:"operation_ambiguous",operations_truncated:true,operations:[{...effect.operations[0]!,status:"ambiguous",comparisons_truncated:true}]};
 const html=renderToStaticMarkup(<EpochRegistryDetail net={2} row={partial}/>);
 expect(html).toContain("Conflicting or truncated operation evidence");expect(html).toContain("Only the first 20");expect(html).toContain("witness comparison truncated");
});
it("shows NoKey as replayed state without inventing an operation",()=>{
 const noKey:Row={...state,registry:{...state.registry!,state:{...state.registry!.state!,candidates:[{...candidate,key:{sha256:"5".repeat(64),bytes:0}}],without_keys:[candidate.address]}}};
 const html=renderToStaticMarkup(<EpochRegistryDetail net={2} row={noKey}/>);
 expect(html).toContain("1 candidate; 1 without a public key");expect(html).toContain("No public key");expect(html).not.toContain("Original operation references");
});
it("bounds candidate rendering while preserving navigation to the full ordered registry",()=>{
 const many=Array.from({length:201},(_,i)=>({...candidate,address:address(1000+i)}));
 const row:Row={...state,registry:{...state.registry!,state:{...state.registry!.state!,candidates:many}}};
 const html=renderToStaticMarkup(<EpochRegistryDetail net={2} row={row}/>);
 expect(html).toContain("Candidates 1–100 of 201");expect(html).toContain("Next candidates");expect(html).toContain(many[0]!.address);expect(html).not.toContain(many[200]!.address);
});
