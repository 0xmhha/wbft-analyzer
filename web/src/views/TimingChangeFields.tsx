import type { TimingFields } from "../timing-change";
export function TimingChangeFields({value,onChange,disabled}:{value:TimingFields;onChange:(v:TimingFields)=>void;disabled:boolean}){
 return <fieldset disabled={disabled}><legend>Consensus timing</legend>
 <p>All values are integer seconds. Blank global fields and - in node rows inherit existing settings. An explicit maximum of 0 removes the timeout cap. Timeout and block period must be positive.</p>
 <label>Global request timeout seconds <input inputMode="numeric" value={value.timeout} onChange={e=>onChange({...value,timeout:e.target.value})}/></label>
 <label>Global block period seconds <input inputMode="numeric" value={value.period} onChange={e=>onChange({...value,period:e.target.value})}/></label>
 <label>Global maximum timeout seconds <input inputMode="numeric" value={value.cap} onChange={e=>onChange({...value,cap:e.target.value})}/></label>
 <label>Per-node timing overrides <textarea rows={5} value={value.nodes} onChange={e=>onChange({...value,nodes:e.target.value})} placeholder="0 3 - 0"/></label>
 <p>One recorded node index, request timeout, block period and maximum timeout per line; use - to inherit. For example, 0 3 - 0 sets node 0 to a 3-second request timeout with no cap. Global explicit fields apply to every node; per-node explicit fields then take precedence. Other existing fields are preserved.</p>
 <p>Settings apply throughout the registered run and every node incarnation. Different block periods can cause header rejection; successful execution does not establish baseline reproducibility.</p>
 </fieldset>;
}
