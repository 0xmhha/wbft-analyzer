import { memo, useEffect, useMemo, useRef, useState } from "react";
import { selectFlowMetric,flowMarks, flowFraction, canonicalFlowNode } from "../messageFlow";
import type { FlowMark } from "../messageFlow";
import { ReplayMessageEvidence } from "./ReplayMessageEvidence";
import { get, type Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";
import { Projection, nsStamp, quorumCues, stampNs, sourcePosition } from "../replay";
import type { Record, Window, ReplayState } from "../replay";

const colours: {[kind:string]:string}={ROUND_ENTER:"#2563eb",SEND:"#d97706",QUORUM:"#9333ea",NEW_HEAD:"#16a34a",TIMER_FIRE:"#dc2626",STATE:"#0891b2",MSG_OUTCOME:"#6b7280"};
export function VisualReplay(props:{net:number;dataset:number;times:{from_t:string;to_t:string};node:string;focus?:Record;onAuth:()=>void;onPoint:(input:string,line:number)=>void}){
 const [open,setOpen]=useState(Boolean(props.focus));
 useEffect(()=>{if(props.focus)setOpen(true)},[props.focus?.input,props.focus?.line]);
 return <details open={open} onToggle={(e)=>setOpen(e.currentTarget.open)}><summary>Visual replay, node state and quorum race</summary>{open&&<ReplayLoader {...props}/>}</details>;
}
function ReplayLoader({net,dataset,times,node,focus,onAuth,onPoint}:{net:number;dataset:number;times:{from_t:string;to_t:string};node:string;focus?:Record;onAuth:()=>void;onPoint:(input:string,line:number)=>void}){
 const datasets=useLoad(async()=>(await get("/v1/networks/{net}/datasets",{path:{net}})).datasets.filter(d=>d.kind==="messages" || d.kind==="run"&&d.id===dataset),[net,dataset]);
 const [evidence,setEvidence]=useState(dataset);
 const [measurement,setMeasurement]=useState("recorded");
 const [original,setOriginal]=useState<Schemas["MessagesSource"]|null>(null);
 const originalRecord=useLoad(async()=>!original?null:original.kind==="message"?get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset:original.dataset_id||evidence},query:{input:original.input,file:original.file||"",ordinal:String(original.ordinal)}}):get("/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}",{path:{net,dataset:original.dataset_id||evidence,input:original.input,line:original.ordinal}}),[net,evidence,JSON.stringify(original)]);
 const [source,setSource]=useState({input:"",line:""}),[endpoint,setEndpoint]=useState<Record|null>(focus || null),[error,setError]=useState("");
 useEffect(()=>{if(focus)setEndpoint(focus)},[focus?.input,focus?.line]);
 const flowEnd=endpoint?.t_wall || times.to_t;
 const flow=useLoad(async()=>stampNs(flowEnd)<stampNs(times.from_t) || stampNs(flowEnd)>stampNs(times.to_t)?null:get("/v1/networks/{net}/datasets/{dataset}/messages/flow",{path:{net,dataset:evidence},query:{...times,to_t:flowEnd,events:dataset,...(measurement!=="recorded"?{metric:measurement}:{}),...(node?{node}:{})}}),[net,dataset,evidence,times.from_t,times.to_t,flowEnd,node,measurement]);
 const load=useLoad(async()=>endpoint && (stampNs(endpoint.t_wall)<stampNs(times.from_t) || stampNs(endpoint.t_wall)>stampNs(times.to_t)) ? null : get("/v1/networks/{net}/datasets/{dataset}/replay/window",{path:{net,dataset},query:{...times,...(node?{node}:{}),...(endpoint?{to_t:endpoint.t_wall,to_input:endpoint.input,to_line:endpoint.line}:{})}}),[net,dataset,times.from_t,times.to_t,node,endpoint?.input,endpoint?.line]);
 return <><label>Message timing <select value={measurement} onChange={e=>{setMeasurement(e.target.value);setOriginal(null)}}><option value="recorded">Recorded callback and event clocks</option><option value="write_start_to_read_complete">Measured write start to read complete</option></select></label><label>Message evidence dataset <select value={evidence} onChange={e=>{setEvidence(Number(e.target.value));setOriginal(null)}}><option value={dataset}>This event run ({dataset})</option>{datasets.state==="done"&&datasets.data.filter(d=>d.kind==="messages").map(d=><option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label><Pending load={flow} onAuth={onAuth}/>{flow.state==="done"&&flow.data&&<p>{flow.data.pairs.length} message groups overlap this window · source snapshot {flow.data.index.version}. Source-wide unpositioned groups: {flow.data.index.diagnostics.unpositioned_pairs||0}. Unknown peer/clock records are not invented.</p>}<form className="controls" onSubmit={async(e)=>{e.preventDefault();setError("");try{const row=await get("/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}",{path:{net,dataset,input:source.input,line:Number(source.line)}});setEndpoint(row)}catch(err){setError(String(err))}}}><label>Replay end source input <input value={source.input} onChange={(e)=>setSource({...source,input:e.target.value})}/></label><label>Replay end source line <input inputMode="numeric" value={source.line} onChange={(e)=>setSource({...source,line:e.target.value})}/></label><button>Use exact source end</button><button type="button" onClick={()=>setEndpoint(null)}>Use time window end</button></form>{error&&<p className="error">{error}</p>}{endpoint&&<p>End source {endpoint.input}:{endpoint.line} · {endpoint.t_wall}. Event records later in this same timestamp are excluded. Journal relationships retain independent recorded clocks.</p>}<Pending load={load} onAuth={onAuth}/>{load.state==="done"&&load.data&&<ReplayPlayer messagePairs={flow.state==="done"&&flow.data?selectFlowMetric(flow.data.pairs,measurement):[]} onMessageSource={s=>setOriginal(s)} net={net} evidenceDataset={evidence} eventDataset={dataset} focus={endpoint || undefined} key={`${net}:${dataset}:${times.from_t}:${times.to_t}:${node}:${endpoint?.input}:${endpoint?.line}`} data={load.data} times={{...times,...(endpoint?{to_t:endpoint.t_wall}:{})}} onPoint={onPoint}/>} {original&&<aside><h3>Original message observation</h3><Pending load={originalRecord} onAuth={onAuth}/>{originalRecord.state==="done"&&originalRecord.data&&<pre>{JSON.stringify(originalRecord.data,null,2)}</pre>}</aside>}</>;
}
export function ReplayPlayer({data,times,focus,messagePairs=[],net=0,evidenceDataset=0,eventDataset=0,onMessageSource,onPoint}:{data:Window;times:{from_t:string;to_t:string};focus?:Record;messagePairs?:Schemas["MessagesPair"][];net?:number;evidenceDataset?:number;eventDataset?:number;onMessageSource?:(source:Schemas["MessagesSource"])=>void;onPoint:(input:string,line:number)=>void}){
 const model=useMemo(()=>new Projection(data),[data]);
 const sources=useMemo(()=>new Map(data.events.map((e)=>[`${e.input}:${e.line}`,e])),[data]);
 const cues=useMemo(()=>quorumCues(data.events),[data]);
 const initial=sourcePosition(model,focus),focusIndex=initial.index;
 const [position,setPosition]=useState(()=>stampNs(initial.at || times.from_t));
 const [index,setIndex]=useState(focusIndex),[playing,setPlaying]=useState(false),[speed,setSpeed]=useState(1),[mode,setMode]=useState("time"),[loop,setLoop]=useState(false),[selectedNode,setSelectedNode]=useState("");
 const [loopFrom,setLoopFrom]=useState(0),[loopTo,setLoopTo]=useState(data.events.length),[trail,setTrail]=useState(5);
 const [selected,setSelected]=useState<Record|null>(initial.selected);
 const section=useRef<HTMLElement>(null);
 useEffect(()=>{if(!focus)return;const frame=requestAnimationFrame(()=>section.current?.scrollIntoView({block:"start",behavior:"instant"}));return()=>cancelAnimationFrame(frame)},[data,focus?.input,focus?.line]);
 const canvas=useRef<HTMLCanvasElement>(null),base=useRef<HTMLCanvasElement|null>(null);
 const current=useRef(index),playingRef=useRef(playing),lastPaint=useRef(0),durations=useRef<number[]>([]);
 const [frames,setFrames]=useState<{count:number;p95:number;fps:number}|null>(null);
 const begin=stampNs(times.from_t),end=stampNs(times.to_t),span=Number(end-begin)||1;
 const states=useMemo(()=>model.seek(index),[model,index]);
 const marks=useMemo(()=>flowMarks(messagePairs,focus?{dataset:eventDataset,input:focus.input,line:focus.line,at:stampNs(focus.t_wall)}:undefined),[messagePairs,focus?.input,focus?.line,eventDataset]);
 const [selectedMessage,setSelectedMessage]=useState<FlowMark|null>(null),[messageMotion,setMessageMotion]=useState(true),[reduced,setReduced]=useState(()=>window.matchMedia("(prefers-reduced-motion: reduce)").matches);
 useEffect(()=>setSelectedMessage(null),[marks]);
 useEffect(()=>{const q=window.matchMedia("(prefers-reduced-motion: reduce)"),change=()=>setReduced(q.matches);q.addEventListener("change",change);return()=>q.removeEventListener("change",change)},[]);
 const height=70+data.nodes.length*66;
 const flowX=(stamp:bigint)=>280+870*Number(stamp-begin)/span;
 const lane=(node:string)=>data.nodes.findIndex(n=>canonicalFlowNode(n.node)===canonicalFlowNode(node));
 const x=(i:number)=>mode==="events"?280+870*i/Math.max(1,data.events.length-1):280+870*Number((model.times[i]||begin)-begin)/span;
 useEffect(()=>{current.current=index},[index]);useEffect(()=>{playingRef.current=playing},[playing]);
 useEffect(()=>{
  const image=document.createElement("canvas");image.width=1200;image.height=height;const ctx=image.getContext("2d")!;
  // Pixel/kind bins bound paint work; original records remain selectable.
  const bins=new Set<string>();
  data.events.forEach((e,i)=>{const n=data.nodes.findIndex((n)=>n.node===e.node);const px=Math.round(x(i)),y=40+n*66,key=`${n}:${px}:${e.kind}`;if(bins.has(key))return;bins.add(key);ctx.fillStyle=colours[e.kind]||"#6b7280";ctx.fillRect(px,y+((Object.keys(colours).indexOf(e.kind)+8)%7)*3-9,2,3)});
  base.current=image;
 },[data,mode,height]);
 useEffect(()=>{
  const c=canvas.current;if(!c||!base.current)return;const ctx=c.getContext("2d")!,ratio=window.devicePixelRatio||1;
  c.width=1200*ratio;c.height=height*ratio;ctx.scale(ratio,ratio);ctx.fillStyle="#fff";ctx.fillRect(0,0,1200,height);
  data.nodes.forEach((n,i)=>{const state=states[n.node],y=40+i*66;ctx.fillStyle=state?.state==="Committed"?"#e0f2e2":state?.state==="Prepared"?"#ece5f8":state?.state==="Preprepared"?"#e0f1f7":"#f1f3f5";ctx.fillRect(280,y-18,870,40);ctx.fillStyle="#222";ctx.font="12px sans-serif";ctx.fillText(n.node.length>28?`${n.node.slice(0,25)}…`:n.node,8,y);ctx.fillText(n.levels.join(" / ")||"no records in window",8,y+16)});
  data.nodes.forEach((n,i)=>{for(const timer of Object.values(states[n.node]?.timers||{})){
   const source=sources.get(`${timer.source.input}:${timer.source.line}`);if(!source||source.t_mono_ns===null||source.t_mono_ns===undefined||!timer.deadline_mono_ns||mode!=="time")continue;
   const start=stampNs(source.t_wall),deadline=start+BigInt(timer.deadline_mono_ns)-BigInt(source.t_mono_ns),stop=timer.closed?stampNs(timer.closed.t_wall):deadline;
   const left=280+870*Number(start-begin)/span,right=280+870*Number(stop-begin)/span;
   ctx.strokeStyle=timer.status==="fired"?"#dc2626":"#9c6b20";ctx.setLineDash(timer.status==="cancelled"?[3,3]:[]);ctx.beginPath();ctx.moveTo(Math.max(280,left),62+i*66);ctx.lineTo(Math.min(1150,right),62+i*66);ctx.stroke();ctx.setLineDash([]);
  }});
  ctx.drawImage(base.current,0,0);const cursor=mode==="events"?(index>0?x(index-1):280):280+870*Number(position-begin)/span;
  if(trail>0){const old=mode==="events"?cursor-870*trail/Math.max(1,data.events.length/100):cursor-870*trail/(span/1e9);if(old>280){ctx.fillStyle="rgba(255,255,255,.65)";ctx.fillRect(280,18,Math.min(870,old-280),height-50)}}
  ctx.strokeStyle="#111";ctx.beginPath();ctx.moveTo(cursor,15);ctx.lineTo(cursor,height-35);ctx.stroke();ctx.fillStyle="#111";ctx.fillText(mode==="events"?"X axis: event ordinal":"X axis: wall time (cross-node order depends on the clock model)",280,height-10);
  // Relationships preserve source strength and clock status; only a valid
  // unique link animates between its two recorded endpoint timestamps.
  ctx.save();ctx.beginPath();ctx.rect(280,10,870,height-40);ctx.clip();
  if(mode==="time")for(const mark of marks){const p=mark.pair,sy=40+lane(p.sender)*66,ry=40+lane(p.receiver)*66;if(lane(p.sender)<0||lane(p.receiver)<0)continue;
   const sx=mark.send!==null?flowX(mark.send):null,rx=mark.receive!==null?flowX(mark.receive):null;
   ctx.strokeStyle=selectedMessage?.pair.id===p.id?"#111":p.status==="valid"?(p.path==="relay"?"#7c3aed":"#2563eb"):"#b45309";
   ctx.lineWidth=selectedMessage?.pair.id===p.id?2.5:1;ctx.setLineDash(p.strength==="link"&&p.status==="valid"?[]:p.strength==="key"?[2,4]:[6,4]);
   if(mark.band){const lo=flowX(mark.band[0]),hi=flowX(mark.band[1]);ctx.fillStyle="rgba(180,83,9,.18)";ctx.fillRect(Math.min(lo,hi),ry-9,Math.max(1,Math.abs(hi-lo)),18)}
   if(mark.connected && sx!==null && rx!==null){ctx.beginPath();ctx.moveTo(sx,sy);ctx.lineTo(rx,ry);ctx.stroke();const angle=Math.atan2(ry-sy,rx-sx);ctx.beginPath();ctx.moveTo(rx,ry);ctx.lineTo(rx-7*Math.cos(angle-.4),ry-7*Math.sin(angle-.4));ctx.moveTo(rx,ry);ctx.lineTo(rx-7*Math.cos(angle+.4),ry-7*Math.sin(angle+.4));ctx.stroke();
    const fraction=messageMotion&&!reduced?flowFraction(mark,position):null;if(fraction!==null){ctx.fillStyle="#2563eb";ctx.beginPath();ctx.arc(sx+(rx-sx)*fraction,sy+(ry-sy)*fraction,3,0,2*Math.PI);ctx.fill()}
   }else{for(const [px,py] of [[sx,sy],[rx,ry]] as const){if(px!==null){ctx.beginPath();ctx.arc(px,py,3,0,2*Math.PI);ctx.stroke()}}}
  }ctx.restore();ctx.setLineDash([]);
  if(selected){const i=data.events.indexOf(selected);if(i>=0){const lane=data.nodes.findIndex((n)=>n.node===selected.node);ctx.strokeStyle="#111";ctx.strokeRect(x(i)-4,40+lane*66-13,10,32)}}
 },[data,index,states,position,mode,trail,selected,height,marks,selectedMessage,messageMotion,reduced]);
 useEffect(()=>{
  if(!playing)return;let handle=0,last=performance.now(),virtual=index>0?model.times[index-1]||begin:begin,ordinal=index;
  const tick=(now:number)=>{const delta=now-last;last=now;durations.current.push(delta);if(durations.current.length>300)durations.current.shift();
   let next:number;
   if(mode==="events"){ordinal+=delta*.1*speed;next=Math.floor(ordinal)}else{virtual+=BigInt(Math.round(delta*1e6*speed));next=model.indexAt(virtual)}
   const finish=loop?loopTo:data.events.length;if(next>=finish){if(loop){next=loopFrom;ordinal=next;virtual=model.times[Math.max(0,next-1)]||begin}else{next=data.events.length;setPlaying(false);playingRef.current=false}}
   current.current=next;setIndex(next);setPosition(mode==="events"?(model.times[Math.max(0,next-1)]||begin):virtual>end?end:virtual);
   if(now-lastPaint.current>=500){lastPaint.current=now;const ds=[...durations.current].sort((a,b)=>a-b);const total=ds.reduce((a,b)=>a+b,0);setFrames({count:ds.length,p95:ds[Math.max(0,Math.ceil(ds.length*.95)-1)]||0,fps:total?1000*ds.length/total:0})}
   if(playingRef.current)handle=requestAnimationFrame(tick)
  };handle=requestAnimationFrame(tick);return()=>cancelAnimationFrame(handle);
 },[playing,mode,speed,loop,loopFrom,loopTo,model]);
 const seek=(n:number)=>{setPlaying(false);setIndex(Math.max(0,Math.min(data.events.length,n)));setPosition(model.times[Math.max(0,n-1)]||begin)};
 const step=(kind:string)=>{let i=index;const old=data.events[Math.max(0,index-1)]?.height;while(i<data.events.length){const e=data.events[i]!;if((!selectedNode||e.node===selectedNode)&&(kind==="event"||kind==="round"&&e.kind==="ROUND_ENTER"||kind==="height"&&e.kind==="ROUND_ENTER"&&e.height!==old)){seek(i+1);setSelected(e);return}i++}seek(data.events.length)};
 const selectPoint=(e:Record)=>{setSelected(e);onPoint(e.input,e.line)};
 const renderedTime=nsStamp(position);
 return <section ref={section} className="replay">{focus&&!initial.selected&&<p>The source is outside the selected node scope. The cursor uses its recorded time; no point is invented.</p>}<p>{data.events.length.toLocaleString()} source records · {data.version}. Points are recorded facts; send/handle logs do not prove wire receipt. State and timer gaps stay unknown. Event streams retain mono timestamps; this visual cross-node axis uses wall time. Clock skew and source regressions can affect order. Message arrows connect unique recorded endpoints. Solid lines are valid links; dashed lines retain weaker evidence or uncertain status. Amber bands show elapsed-time uncertainty relative to the recorded send, not corrected node clocks. Packet motion is an illustration between recorded endpoints; it adds no observation.</p>
  {mode!=="time"&&<p>Message lines use recorded wall timestamps. Switch to the wall-time axis to show them; original evidence stays available below.</p>}
  <label><input type="checkbox" checked={messageMotion} onChange={e=>setMessageMotion(e.target.checked)}/>Message motion (respects reduced-motion)</label>
  <div className="controls"><button type="button" onClick={()=>setPlaying(!playing)}>{playing?"Pause replay":"Play replay"}</button><button type="button" onClick={()=>seek(0)}>Rewind replay</button><button type="button" onClick={()=>step("event")}>Next event</button><button type="button" onClick={()=>step("height")}>Next height</button><button type="button" onClick={()=>step("round")}>Next round entry</button>
   <label>Step node <select value={selectedNode} onChange={(e)=>setSelectedNode(e.target.value)}><option value="">All nodes</option>{data.nodes.map((n)=><option key={n.node}>{n.node}</option>)}</select></label>
   <label>Replay speed <select value={speed} onChange={(e)=>setSpeed(Number(e.target.value))}>{[.1,.5,1,2,10,100].map((s)=><option key={s} value={s}>{s}×</option>)}</select></label>
   <label>Replay clock <select value={mode} onChange={(e)=>{setPlaying(false);setMode(e.target.value)}}><option value="time">Proportional to wall time</option><option value="events">Proportional to events (100/s at 1×)</option></select></label>
   <label>Trail <select value={trail} onChange={(e)=>setTrail(Number(e.target.value))}>{[0,1,5,20].map((s)=><option key={s} value={s}>{s||"off"}{s?" seconds at 1×":""}</option>)}</select></label>
  </div>
  <label>Replay position <input aria-label="Replay position" type="range" min={0} max={data.events.length} step={1} value={index} onChange={(e)=>seek(Number(e.target.value))}/></label><p className="mono">{index} / {data.events.length} · {renderedTime} {mode==="events"&&"· X shows event ordinal"}</p>
  <div className="controls"><label><input type="checkbox" checked={loop} onChange={(e)=>setLoop(e.target.checked)}/>Loop selected source interval</label><label>Loop from event <input type="number" min={0} max={loopTo-1} value={loopFrom} onChange={(e)=>setLoopFrom(Math.max(0,Math.min(loopTo-1,Number(e.target.value))))}/></label><label>Loop to event <input type="number" min={loopFrom+1} max={data.events.length} value={loopTo} onChange={(e)=>setLoopTo(Math.max(loopFrom+1,Math.min(data.events.length,Number(e.target.value))))}/></label></div>
  <canvas ref={canvas} className="replay-canvas" style={{height}} role="img" tabIndex={0} onKeyDown={(e)=>{if(e.key==="ArrowRight"){e.preventDefault();step("event")}else if(e.key==="ArrowLeft"){e.preventDefault();seek(index-1)}else if(e.key===" "){e.preventDefault();setPlaying(!playing)}}} aria-label="WBFT visual replay canvas" onClick={(e)=>{const rect=e.currentTarget.getBoundingClientRect(),px=(e.clientX-rect.left)*1200/rect.width,py=(e.clientY-rect.top)*height/rect.height,lane=Math.round((py-40)/66);const node=data.nodes[lane]?.node;let best:Record|null=null,distance=20;data.events.forEach((r,i)=>{const d=Math.abs(x(i)-px);if(r.node===node&&d<distance){best=r;distance=d}});if(best)selectPoint(best)}}/>
  {frames&&<p>Observed animation cadence: {frames.fps.toFixed(1)} fps · p95 frame interval {frames.p95.toFixed(2)} ms · {frames.count} recent frames. This measures the current device/window, not all datasets.</p>}
  {selectedMessage&&onMessageSource&&<ReplayMessageEvidence net={net} dataset={evidenceDataset} pair={selectedMessage.pair} onSource={onMessageSource}/>}
  <details><summary>Message relationships and evidence</summary><p>{marks.length} groups overlap the window. Select a row for exact original pointers. Ambiguous and missing observations do not become a transfer arrow.</p><div className="table-scroll"><table><thead><tr><th>Sender → receiver / phase</th><th>Evidence / clock / status</th><th>Valid / raw / interval</th><th>Originals</th></tr></thead><tbody>{marks.map(m=><tr key={m.pair.id} className={selectedMessage?.pair.id===m.pair.id?"selected":""}><td>{m.pair.sender} → {m.pair.receiver} / {m.pair.phase}</td><td>{m.pair.strength} / {m.pair.path} / {m.pair.clock} / {m.pair.status}</td><td>{m.pair.seconds??"unknown"} / {m.pair.raw_seconds??"unknown"} / [{m.pair.lower_seconds??"unknown"}, {m.pair.upper_seconds??"unknown"}] seconds</td><td><button type="button" onClick={()=>setSelectedMessage(m)}>Inspect message relationship</button></td></tr>)}</tbody></table></div></details>
  <ReplayStates states={Object.values(states)} onPoint={onPoint}/>
  <details><summary>Source levels and replay diagnostics</summary>{data.nodes.map((n)=><p key={n.node}>{n.node}: {n.levels.join(" / ")||"no records in this window"} · file sequence gaps {n.sequence_gaps} · monotonic regressions {n.monotonic_regressions} · wall regressions {n.wall_regressions}. These are source diagnostics, not proof of clock skew or complete coverage.</p>)}</details>
  {selected&&<aside><h3>{selected.kind} · {selected.node}</h3><p>{selected.input}:{selected.line} · full height {selected.height||"unknown"} / round {selected.round||"unknown"} · {selected.t_wall}</p><pre>{JSON.stringify(selected.fields,null,2)}</pre></aside>}
  <MemoReplayInfographics events={data.events} cues={cues} onPoint={onPoint}/>
 </section>;
}
export function ReplayStates({states,onPoint}:{states:ReplayState[];onPoint:(input:string,line:number)=>void}){
 return <div className="table-scroll"><table aria-label="Recorded replay node state"><thead><tr><th>Node / engine run</th><th>Full height / round / cause</th><th>Recorded state / engine active</th><th>Timers</th><th>Recorded quorum counts</th><th>Backlog / last head</th></tr></thead><tbody>{states.map((s)=><tr key={s.node}><td>{s.node}<br/>{s.run||"unknown"}</td><td>{s.view?.seq||"unknown"} / {s.view?.round||"unknown"} / {s.cause||"unknown"}</td><td>{s.state||"unknown"} / {s.engine_active===null?"unknown":String(s.engine_active)}{s.state_source&&<button type="button" onClick={()=>onPoint(s.state_source!.input,s.state_source!.line)}>state source</button>}</td><td>{Object.values(s.timers).map((t)=><p key={t.kind}>{t.kind}: {t.status} · generation {t.generation||"unknown"} · deadline mono {t.deadline_mono_ns||"unknown"} ns<button type="button" onClick={()=>onPoint(t.source.input,t.source.line)}>timer source</button></p>)}</td><td>{Object.entries(s.counters).map(([what,q])=><p key={what}>{what}: {q.count||"unknown"} / {q.quorum||"unknown"}<button type="button" onClick={()=>onPoint(q.source.input,q.source.line)}>quorum source</button></p>)}</td><td>{s.backlog??"unknown"}{s.backlog_partial&&" (partial prefix)"} / {s.last_head||"unknown"} {s.head_kind}</td></tr>)}</tbody></table></div>;
}
function ReplayInfographics({events,cues,onPoint}:{events:Record[];cues:ReturnType<typeof quorumCues>;onPoint:(input:string,line:number)=>void}){
 const heights=new Map<string,Map<string,number>>(),causes=new Map<string,number>();
 for(const e of events){if(e.kind!=="ROUND_ENTER"||!e.height)continue;const rs=heights.get(e.height)||new Map<string,number>();rs.set(e.round,(rs.get(e.round)||0)+1);heights.set(e.height,rs);const cause=String((e.fields as {[key:string]:unknown}).cause||"unknown");causes.set(cause,(causes.get(cause)||0)+1)}
 const rows=[...heights].slice(0,100),rounds=[...new Set(rows.flatMap(([,rs])=>[...rs.keys()]))].sort((a,b)=>BigInt(a||0)<BigInt(b||0)?-1:1);
 return <details><summary>Height/round heatmap, round causes and quorum race evidence</summary><p>Counts are node observations, including repeat entries. They do not count network decisions. Narrow the window when more than 100 heights are selected.</p><div className="table-scroll"><table aria-label="Height round heatmap"><thead><tr><th>Full height</th>{rounds.map((r)=><th key={r}>Round {r||"unknown"}</th>)}</tr></thead><tbody>{rows.map(([h,rs])=><tr key={h}><td>{h}</td>{rounds.map((r)=><td key={r} style={{background:rs.has(r)?`rgba(37,99,235,${Math.min(.8,.15+(rs.get(r)||0)*.08)})`:"transparent"}}>{rs.get(r)||0}</td>)}</tr>)}</tbody></table></div>
  <svg viewBox={`0 0 800 ${Math.max(100,causes.size*38)}`} role="img" aria-label="Round entry cause flows">{[...causes].map(([cause,count],i)=><g key={cause}><text x="10" y={25+i*38}>{cause}</text><path d={`M180 ${20+i*38} C350 ${20+i*38} 450 ${20+i*38} 600 ${20+i*38}`} fill="none" stroke="#7954c7" strokeWidth={Math.max(2,Math.min(22,count))}/><text x="620" y={25+i*38}>ROUND_ENTER · {count}</text></g>)}</svg>
  <QuorumRace events={events}/>
  <p>Quorum race links identify the recorded message step. Without a step, a preceding message is only inferred. Logs recording only a handle do not prove acceptance. The table is capped at 100 quorum records; use the event cursor for the rest.</p><table><thead><tr><th>Node / height / round</th><th>Quorum</th><th>Filling message / strength</th><th>Evidence</th></tr></thead><tbody>{cues.slice(0,100).map((c)=><tr key={`${c.quorum.input}:${c.quorum.line}`}><td>{c.quorum.node} / {c.quorum.height} / {c.quorum.round}</td><td>{String((c.quorum.fields as {[key:string]:unknown}).what||"unknown")}</td><td>{c.message?`${c.message.input}:${c.message.line}`:"unknown"} / {c.confidence}</td><td><button type="button" onClick={()=>onPoint(c.quorum.input,c.quorum.line)}>quorum</button>{c.message&&<button type="button" onClick={()=>onPoint(c.message!.input,c.message!.line)}>message</button>}</td></tr>)}</tbody></table>
 </details>;
}

const MemoReplayInfographics = memo(ReplayInfographics);

function QuorumRace({events}:{events:Record[]}){
 const samples=events.flatMap((e)=>{const f=e.fields as {[key:string]:unknown},what=String(f.what||"");const xs:{e:Record;phase:string;count:number;quorum:number|null}[]=[];
  for(const phase of ["PREPARE","COMMIT"]){const value=String(f[phase==="PREPARE"?"prepares.count":"commits.count"]??(what===phase?f.count:"")??"");const q=Number(f.quorum);if(/^\d+$/.test(value)&&Number.isSafeInteger(Number(value)))xs.push({e,phase,count:Number(value),quorum:Number.isSafeInteger(q)&&q>0?q:null})}return xs});
 const shown=samples.slice(0,5000),nodes=[...new Set(shown.map((s)=>s.e.node))],start=events[0]?stampNs(events[0].t_wall):0n,end=events.at(-1)?stampNs(events.at(-1)!.t_wall):start+1n,span=Number(end-start)||1,max=Math.max(1,...shown.map((s)=>s.count));
 return <figure><figcaption>Recorded quorum race counts · {samples.length} samples, {shown.length} drawn. Missing intermediate counts stay absent; points do not infer a quorum. PREPARE blue, COMMIT purple.</figcaption><svg viewBox={`0 0 1000 ${Math.max(100,nodes.length*80+40)}`} role="img" aria-label="Recorded quorum race counts">{nodes.map((node,i)=><g key={node}><text x="5" y={i*80+35}>{node.slice(0,20)}…</text><line x1="180" x2="970" y1={i*80+65} y2={i*80+65} stroke="#bbb"/></g>)}{shown.map((s,i)=><circle key={i} cx={180+790*Number(stampNs(s.e.t_wall)-start)/span} cy={65+nodes.indexOf(s.e.node)*80-s.count/max*50} r="3" fill={s.phase==="PREPARE"?"#2563eb":"#9333ea"}><title>{`${s.e.node} ${s.phase} ${s.count}/${s.quorum??"unknown"} h=${s.e.height} r=${s.e.round} ${s.e.input}:${s.e.line}`}</title></circle>)}</svg></figure>
}
