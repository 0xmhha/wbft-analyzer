import { useState } from "react";
import { get, type Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";
import { eventSourceLink } from "../sourceLink";

type Evidence = Schemas["StoreReexecEventEvidence"];

export function ReplayEventEvidence({ net, dataset, run, ordinal, onAuth }: { net: number; dataset: number; run: number; ordinal: number; onAuth: () => void }) {
 const [events, setEvents] = useState(0);
 const choices = useLoad(async () => (await get("/v1/networks/{net}/datasets", { path: { net } })).datasets.filter(d => d.kind === "run" && d.status === "complete"), [net]);
 const load = useLoad(() => events ? get("/v1/networks/{net}/datasets/{dataset}/reexec/{reexec}/events", { path: { net, dataset, reexec: run }, query: { ordinal, event_dataset: events } }) : Promise.resolve(null), [net, dataset, run, ordinal, events]);
 return <aside aria-label="Recorded step events"><h3>Recorded step events</h3><p>Select the original event dataset. Links require the same retained source, verified message outcomes and clocks, and explicitly recorded writer, engine and step. Missing identity remains unknown.</p><Pending load={choices} onAuth={onAuth}/>{choices.state === "done" && <label>Event evidence dataset <select value={events} onChange={e => setEvents(Number(e.target.value))}><option value={0}>Select an event dataset</option>{choices.data.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</select></label>}<Pending load={load} onAuth={onAuth}/>{load.state === "done" && load.data && <ReplayEventList net={net} evidence={load.data}/>}</aside>;
}

export function ReplayEventList({net,evidence}:{net:number;evidence:Evidence}){
 if(evidence.status!=="matched") return <p role="status">Event evidence unavailable: {evidence.reason || "unknown"}. Replay classifications are unchanged.</p>;
 return <><p>{evidence.events.length} original events with verified step identity. This association does not establish core reproduction.</p><table><thead><tr><th>Original event</th><th>Time</th><th>Kind</th><th>View</th></tr></thead><tbody>{evidence.events.map(e=>{
 const link=eventSourceLink(net,{kind:"event",input:e.input,ordinal:e.line,dataset_id:evidence.event_dataset_id,node:e.node,run:e.run,t_wall:e.t_wall},evidence.event_dataset_id);
 return <tr key={`${e.input}/${e.line}`}><td>{link?<a href={link}>Open event {e.input}:{e.line}</a>:`${e.input}:${e.line}`}</td><td className="mono">{e.t_wall}</td><td>{e.kind}</td><td className="mono">{e.height || "unknown"} / {e.round || "unknown"}</td></tr>
 })}</tbody></table></>;
}
