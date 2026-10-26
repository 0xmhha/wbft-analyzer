import {useRef,useState} from "react";
import {ApiError,inspectObservationBand,type Schemas} from "../api/client";
import "../observationBands.css";
type Inspection=Schemas["ObservationBandInspection"];
const names:Record<string,string>={NO_HISTORY:"No history",INSUFFICIENT_HISTORY:"Insufficient history",SUFFICIENT_HISTORY:"Sufficient history",IN_OBSERVED_BAND:"Within requested band",BELOW_OBSERVED_BAND:"Below requested band",BEFORE_ACTIVATION:"Before activation",UNAVAILABLE:"Observation state unavailable",DISABLED:"Observations disabled",UNSUPPORTED:"Diagnostic not supported",AVAILABLE:"Node report available"};
const label=(s:string)=>names[s]??s.replaceAll("_"," ").toLowerCase();
const integer=(s:string)=>/^(0|[1-9][0-9]{0,255})$/.test(s)?BigInt(s):null;
/** Display coordinates only; classification uses the server's exact check. */
export function bandCoordinate(numerator:string,denominator:string):number|null{
 const n=integer(numerator),d=integer(denominator);
 return n===null||d===null||d===0n||n>d?null:Number(n*100000n/d)/100;
}
function PhaseBar({phase,observed,eligible,numerator,denominator}:{phase:string;observed:string;eligible:string;numerator:string;denominator:string}){
 const value=bandCoordinate(observed,eligible),threshold=bandCoordinate(numerator,denominator);
 return <div className="band-phase"><div className="band-phase-title"><strong>{phase}</strong><span className="mono">{observed} / {eligible} opportunities</span></div>
  {value===null?<p className="muted">No ratio without eligible opportunities.</p>:<><svg viewBox="0 0 1000 36" className="band-meter" role="img" aria-label={`${phase}: ${observed} of ${eligible} opportunities; requested threshold ${numerator}/${denominator}`}><rect x="0" y="8" width="1000" height="20" className="band-track"/><rect x="0" y="8" width={value} height="20" className="band-fill"/>{threshold!==null&&<line x1={threshold} x2={threshold} y1="0" y2="36" className="band-threshold"/>}</svg><p className="muted">≈{(value/10).toFixed(2)}% observed · dashed mark: requested {numerator}/{denominator}</p></>}
 </div>;
}
export function ObservationBandPanel({inspection}:{inspection:Inspection}){
 const r=inspection.report,d=r.diagnostic,math=inspection.arithmetic;
 return <section className="band-result" aria-label="Observation band inspection">
  <div className="band-status"><strong>{label(r.status)}</strong><span className="band-badge">Node reported</span></div>
  <p className="muted">This checks declared counts and arithmetic. Header ancestry, signatures, membership and state roots are not independently verified here.</p>
  {r.reason&&<p>{r.reason.replaceAll("_"," ")}</p>}
  {d&&math?<><div className="band-grid">
   <section className="band-card"><h2>{label(math.history_status)}</h2><p><strong className="band-number">{d.eligible}</strong> eligible targets · minimum {d.minimum}</p><p>{math.observed_band?label(math.observed_band):"Band unclassified; no participation score is assigned."}</p></section>
   <section className="band-card"><h2>{d.view==="settled"?"Settled window":"Recent matured preview"}</h2><p className="mono">{d.from} → {d.through}</p><p>Retention H {d.retention} · carrier {d.carrier_height}</p><p>Each phase must meet the requested {d.numerator}/{d.denominator}.</p></section>
  </div><div className="band-grid band-phases"><PhaseBar phase="Prepare" observed={d.observed_prepare} eligible={d.eligible} numerator={d.numerator} denominator={d.denominator}/><PhaseBar phase="Commit" observed={d.observed_commit} eligible={d.eligible} numerator={d.numerator} denominator={d.denominator}/></div>
  <p className={math.matches_reported?"band-consistent":"band-mismatch"}>{math.matches_reported?"Reported arithmetic matches the count check.":"Reported classification differs from the count check."}</p>
  {!math.matches_reported&&<p>Node reported: {label(d.history_status)} · {d.observed_band?label(d.observed_band):"Unclassified"}. Arithmetic: {label(math.history_status)} · {math.observed_band?label(math.observed_band):"Unclassified"}.</p>}
  <p className="muted">An inclusion band does not establish signing intent, blacklist eligibility, validator selection or reward entitlement.</p>
  </>:<p className="band-empty">No numeric observation is available. Missing data is not a zero participation score.</p>}
  <details className="band-identity"><summary>Source identity</summary><dl><dt>Claimed chain</dt><dd className="mono">{r.chain_id||"Not supplied"}</dd><dt>Genesis</dt><dd className="mono">{r.genesis_hash||"Not supplied"}</dd><dt>Reported build</dt><dd className="mono">{r.core_version||"Not supplied"}</dd>
  {d&&<><dt>Queried address</dt><dd className="mono">{d.address}</dd><dt>Carrier</dt><dd className="mono">{d.carrier_hash}</dd><dt>State root</dt><dd className="mono">{d.state_root}</dd><dt>Observation policy</dt><dd className="mono">{d.observation_policy}</dd></>}<dt>Report text SHA256</dt><dd className="mono">{inspection.source_sha256}</dd></dl></details>
 </section>;
}
export function ObservationBands({onAuth}:{onAuth:()=>void}){
 const [raw,setRaw]=useState(""),[filename,setFilename]=useState("Pasted node report"),[result,setResult]=useState<Inspection|null>(null),[error,setError]=useState(""),[busy,setBusy]=useState(false);const serial=useRef(0);
 const replace=(text:string,name:string)=>{serial.current++;setRaw(text);setFilename(name);setResult(null);setError("");setBusy(false);};
 const load=async(file:File)=>{const id=++serial.current;setBusy(false);setRaw("");setFilename(file.name);setResult(null);setError("");try{if(file.size>65536)throw new Error("Choose UTF-8 JSON no larger than 64 KiB.");const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());if(id===serial.current)replace(text,file.name);}catch(e){if(id===serial.current)setError(e instanceof Error?e.message:"Cannot read this report.");}};
 const inspect=async()=>{const id=++serial.current;setBusy(true);setError("");setResult(null);try{if(new TextEncoder().encode(raw).length>65536)throw new Error("The report exceeds 64 KiB.");const value=await inspectObservationBand(raw);if(id===serial.current)setResult(value);}catch(e){if(id===serial.current){if(e instanceof ApiError&&e.status===401)onAuth();setError(e instanceof Error?e.message:"Cannot inspect this report.");}}finally{if(id===serial.current)setBusy(false);}};
 return <article className="observation-bands"><h1>WBFT participation observation bands</h1><p>Inspect a saved <code>wbft_observationBand</code> result or JSON-RPC response. Reports remain node claims; the read-only count check stores no report.</p>
 <div className="band-inputs"><label>Load node report <input type="file" accept=".json,application/json" onChange={e=>{const f=e.target.files?.[0];if(f)void load(f);}}/></label><button type="button" disabled={busy||!raw.trim()} onClick={()=>void inspect()}>{busy?"Checking…":"Check arithmetic"}</button></div>
 <details open={!result}><summary>{filename} · UTF-8 JSON, up to 64 KiB</summary><label>Node report JSON<textarea rows={7} maxLength={65536} value={raw} onChange={e=>replace(e.target.value,"Pasted node report")} spellCheck={false}/></label></details>
 {error&&<p className="error" role="alert">{error}</p>}<div aria-live="polite">{result&&<ObservationBandPanel inspection={result}/>}</div></article>;
}
