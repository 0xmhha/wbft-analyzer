import type {Schemas} from "../api/client";
import {get} from "../api/client";
import {Pending,useLoad} from "../ui";
type Native=Schemas["ScenarioRecordedMessageEvidence"];
export function RecordedMessageSource({net,dataset,row,onAuth}:{net:number;dataset:number;row:Native;onAuth:()=>void}) {
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:row.input,file:row.file,ordinal:row.ordinal}}),[net,dataset,row.input,row.file,row.ordinal]);
 return <aside aria-label="Original selected message record"><h4>Original record {row.input}:{row.file}:{row.ordinal}</h4><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<><p>Recorded receiver {load.data.node} · peer {load.data.peer||"unavailable"} · signer {load.data.signer||"unavailable"}</p><p>{load.data.phase} · height {load.data.height} / round {load.data.round} · writer {load.data.run} · capture {load.data.capture_id||"unavailable"}</p><p>Recorded wall {load.data.t_wall||"unavailable"} · monotonic ns {load.data.t_mono_ns??"unavailable"} · Offer {load.data.offer||"unavailable"} · projected signature {load.data.signature_status||"unavailable"}</p><p className="mono">Payload SHA256 {load.data.payload_sha256||"unavailable"}<br/>Input SHA256 {row.input_sha256}</p></>}</aside>;
}
