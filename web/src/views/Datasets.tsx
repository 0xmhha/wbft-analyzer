import {useState} from "react";
import {get,remove,ApiError,type Schemas} from "../api/client";
import {Pending,useLoad} from "../ui";

type Storage=Schemas["StoreDatasetInputStorage"];
type Dataset=Schemas["StoreDataset"];
type Deletion=Schemas["StoreDatasetDeletion"];
export function Datasets({net,onAuth}:{net:number;onAuth:()=>void}){
 const [refresh,setRefresh]=useState(0),[selected,setSelected]=useState(0),[result,setResult]=useState<Deletion>();
 const load=useLoad(()=>get("/v1/networks/{net}/datasets",{path:{net}}),[net,refresh]);
 return <section><h1>Datasets and retained inputs</h1><p>Delete an imported dataset and the input bytes owned by it. Original source files, shared inputs and network header facts remain separate. Active imports and replay jobs must finish before deletion.</p><button type="button" onClick={()=>setRefresh(n=>n+1)}>Refresh datasets</button>{result&&<p role="status">Dataset {result.name}: {result.status}. {result.input_files.toLocaleString()} owned input objects ({result.input_bytes.toLocaleString()} bytes) removed.</p>}<Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<><label>Dataset to manage <select value={selected} onChange={e=>setSelected(Number(e.target.value))}><option value={0}>Select a dataset</option>{load.data.datasets.map(d=><option key={d.id} value={d.id}>{d.name} · {d.kind} · {d.status}</option>)}</select></label>{load.data.datasets.filter(d=>d.id===selected).map(d=><Manage key={`${d.id}/${refresh}`} net={net} dataset={d} onAuth={onAuth} onDeleted={r=>{setResult(r);setSelected(0);setRefresh(n=>n+1)}}/>)}</>}</section>
}
function Manage({net,dataset,onAuth,onDeleted}:{net:number;dataset:Dataset;onAuth:()=>void;onDeleted:(d:Deletion)=>void}){
 const [name,setName]=useState(""),[pending,setPending]=useState(false),[error,setError]=useState("");
 const info=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/input-storage",{path:{net,dataset:dataset.id}}),[net,dataset.id]);
 const available=info.state==="done"&&["owned","empty","deleting"].includes(info.data.state);
 const submit=async()=>{if(name!==dataset.name||!available||pending)return;setPending(true);setError("");try{onDeleted(await remove("/v1/networks/{net}/datasets/{dataset}",{net,dataset:dataset.id},{confirm_name:name}))}catch(e){if(e instanceof ApiError&&e.status===401)onAuth();setError(e instanceof Error?e.message:"Dataset deletion failed. Refresh to inspect deletion status and retry.")}finally{setPending(false)}};
 return <article><h2>{dataset.name}</h2><Pending load={info} onAuth={onAuth}/>{info.state==="done"&&<InputStorageSummary storage={info.data}/>}<p>Deletion removes this dataset's records and replay results and cancels queued replay jobs. A referenced follow capture or running job blocks deletion. Interrupted cleanup remains visible and can be retried.</p><label>Confirm dataset name <input value={name} onChange={e=>setName(e.target.value)} autoComplete="off" disabled={pending}/></label><button type="button" disabled={!available||name!==dataset.name||pending} onClick={()=>void submit()}>{pending?"Deleting…":dataset.status==="deleting"?"Retry dataset deletion":"Delete dataset and owned inputs"}</button>{error&&<p className="error" role="alert">{error}</p>}</article>
}
export function InputStorageSummary({storage}:{storage:Storage}){
 switch(storage.state){
 case "owned":return <p>{storage.input_files.toLocaleString()} owned input objects · {storage.input_bytes.toLocaleString()} bytes.</p>;
 case "empty":return <p>No retained input bytes.</p>;
 case "deleting":return <p>Input cleanup is pending. Confirm the same dataset name to retry it.</p>;
 case "foreign":return <p>These input bytes belong to another database. Copy and verify them into storage owned by this database before deletion.</p>;
 case "unmanaged":return <p>These older inputs use shared storage. Copy and verify them into storage owned by this dataset before deletion.</p>;
 default:return <p>Input ownership is unavailable. Repair the owned storage before deletion.</p>;
 }
}
