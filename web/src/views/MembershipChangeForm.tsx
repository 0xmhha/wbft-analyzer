import {useState} from "react";
import type {Schemas} from "../api/client";
import {membershipChange,type SyntheticNodeFields} from "../membership-change";

const emptyNode=():SyntheticNodeFields=>({alias:"",start:"",timeout:"",period:"",cap:"",build:"",imports:""});

export function MembershipChangeForm({nodes,duration,disabled,busy,onSubmit}:{nodes:string[];duration:number;disabled:boolean;busy:boolean;onSubmit:(change:Schemas["ScenarioNetworkChange"])=>Promise<void>}){
 const [synthetic,setSynthetic]=useState<SyntheticNodeFields[]>([]),[links,setLinks]=useState(""),[epochs,setEpochs]=useState(""),[policy,setPolicy]=useState("merge"),[error,setError]=useState("");
 function update(index:number,field:keyof SyntheticNodeFields,value:string){setSynthetic(old=>old.map((node,i)=>i===index?{...node,[field]:value}:node));setError("")}
 async function submit(){try{const change=membershipChange(nodes.length,duration,policy,synthetic,links,epochs);setError("");await onSubmit(change)}catch(e){setError(e instanceof Error?e.message:"Invalid synthetic membership.")}}
 return <details><summary>Synthetic epoch membership</summary><form aria-label="Synthetic membership request" className="controls" onSubmit={e=>{e.preventDefault();void submit()}}>
 <p>Change epoch candidates using the WBFT core. Omit an existing index to remove that candidate. New nodes append after the recorded indices and are excluded from genesis. Candidate requests and actual validator selection are recorded separately.</p>
 <details><summary>Preserved recorded node indices</summary><ol start={0}>{nodes.map((node,i)=><li key={i}>{node}</li>)}</ol></details>
 <label>Epoch schedule policy <select disabled={disabled} value={policy} onChange={e=>setPolicy(e.target.value)}><option value="merge">Keep other recorded epoch changes</option><option value="replace_from_first_epoch">Replace recorded changes from the first requested epoch</option></select></label>
 <p>Keeping later recorded epochs can reverse an earlier synthetic change. Replacement removes the later recorded schedule; the last requested candidate list then persists. Removed schedules remain available as evidence.</p>
 <label>Epoch candidates <textarea required rows={4} disabled={disabled} value={epochs} onChange={e=>{setEpochs(e.target.value);setError("")}} placeholder="epoch block: 0,1,2,3"/></label>
 <p>One epoch block followed by ordered candidate indices per line. The server checks the registered chain's epoch boundaries and stop height. Candidate order is preserved.</p>
 {synthetic.map((node,i)=><fieldset key={i} disabled={disabled}><legend>Synthetic node {nodes.length+i}</legend>
 <label>Alias <input required value={node.alias} onChange={e=>update(i,"alias",e.target.value)}/></label>
 <p>Declared runtime: compat WBFT core with optional restart rules off, fresh test signing state without WAL replay, zero processing cost, independent fake application jobs, and a shared manual clock with zero skew. These assumptions are unmeasured.</p>
 {([["start","Startup nanoseconds"],["timeout","Request timeout seconds"],["period","Block period seconds"],["cap","Maximum request timeout seconds (0 removes cap)"],["build","Build delay samples ns, comma separated"],["imports","Import delay samples ns, comma separated"]] as const).map(([field,label])=><label key={field}>{label}<input required value={node[field]} onChange={e=>update(i,field,e.target.value)}/></label>)}
 <button type="button" onClick={()=>{setSynthetic(old=>old.filter((_,n)=>n!==i));setLinks("");setError("Node indices changed; review all candidate and link indices before submitting.")}}>Remove synthetic node {nodes.length+i}</button>
 </fieldset>)}
 <button type="button" disabled={disabled||nodes.length+synthetic.length>=256} onClick={()=>setSynthetic(old=>[...old,emptyNode()])}>Add synthetic node</button>
 {synthetic.length>0&&<><label>New directed links <textarea required rows={6} disabled={disabled} value={links} onChange={e=>{setLinks(e.target.value);setError("")}} placeholder="0 -> 4 | 1000000,2000000 | 0"/></label><p>List every ordered direction touching a new node: from -&gt; to | delay samples in ns | loss in parts per million (0–999999). No direction or sample is inferred. Existing recorded links remain unchanged.</p></>}
 <p>Synthetic counterfactual over the full registered {duration} ns. Baseline reproduction uses the original model and seeds. Synthetic node and link values have no measured provenance.</p>
 <button disabled={disabled}>{busy?"Queueing…":"Queue synthetic membership experiment"}</button>{error&&<p className="error" role="alert">{error}</p>}
 </form></details>;
}
