import { useEffect, useState } from "react";
import { ApiError, get, post, type Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

type Job = Schemas["StoreReexecJob"];

export function ReexecJobs({ net, dataset, refresh, onResult, onAuth }: {
  net: number; dataset: number; refresh: number; onResult: (id: number) => void; onAuth: () => void;
}) {
  const sources = useLoad(() => get("/v1/networks/{net}/datasets/{dataset}/reexec-sources", { path: { net, dataset } }), [net, dataset, refresh]);
  const [source, setSource] = useState(""), [from, setFrom] = useState("1"), [to, setTo] = useState("1"), [mode, setMode] = useState("closed");
  const [jobs, setJobs] = useState<Job[]>([]), [error, setError] = useState(""), [sending, setSending] = useState(false), [reload, setReload] = useState(0);
  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const result = await get("/v1/networks/{net}/datasets/{dataset}/reexec-jobs", { path: { net, dataset } });
        if (!live) return;
        setJobs(result.jobs);
        if (result.jobs.some(j => j.status === "queued" || j.status === "running")) timer = setTimeout(load, 2000);
      } catch (e) {
        if (!live) return;
        setError(e instanceof Error ? e.message : "Unable to load replay jobs.");
        if (e instanceof ApiError && e.status === 401) onAuth();
      }
    };
    void load();
    return () => { live = false; clearTimeout(timer); };
  }, [net, dataset, refresh, reload, onAuth]);
  const available = sources.state === "done" ? sources.data.sources : [];
  const chosen = available.find(s => s.id === source) ?? available[0];
  const chosenMode = chosen?.modes.includes(mode) ? mode : "closed";
  async function submit() {
    if (!chosen || sending) return;
    setSending(true); setError("");
    try {
      const job = await post("/v1/networks/{net}/datasets/{dataset}/reexec-jobs", { net, dataset }, { source_id: chosen.id, from_height: from, to_height: to, mode: chosenMode as "closed" | "counterfactual" });
      setJobs(old => [job, ...old].slice(0, 100)); setReload(n => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to queue replay.");
      if (e instanceof ApiError && e.status === 401) onAuth();
    } finally { setSending(false); }
  }
  return <section aria-label="Replay jobs"><h3>Start a core replay</h3>
    <Pending load={sources} onAuth={onAuth} />
    {sources.state === "done" && (!sources.data.enabled || !chosen) ? <p>No replay source is enabled for this dataset. Stored results remain available.</p> : chosen && <form className="controls" onSubmit={e => { e.preventDefault(); void submit(); }}>
      <label>Retained source <select value={chosen.id} onChange={e => { setSource(e.target.value); setMode("closed"); }} disabled={sending}>{available.map(s => <option key={s.id} value={s.id}>{s.id} · {s.input_id}</option>)}</select></label>
      <label>First active height <input inputMode="numeric" pattern="[1-9][0-9]*" required value={from} onChange={e => setFrom(e.target.value)} disabled={sending} /></label>
      <label>Last active height <input inputMode="numeric" pattern="[1-9][0-9]*" required value={to} onChange={e => setTo(e.target.value)} disabled={sending} /></label>
      <label>Replay mode <select value={chosenMode} onChange={e => setMode(e.target.value)} disabled={sending}>{chosen.modes.map(m => <option key={m} value={m}>{m === "closed" ? "Original inputs" : "Counterfactual input loss"}</option>)}</select></label>
      <button type="submit" disabled={sending}>{sending ? "Queueing replay…" : "Queue core replay"}</button>
      {chosenMode === "counterfactual" && <p className="error">This input loss experiment cannot establish reproduction of the original run.</p>}
    </form>}
    {error && <p className="error" role="alert">{error}</p>}
    <p role="status">{jobs.filter(j => j.status === "queued").length} queued · {jobs.filter(j => j.status === "running").length} running. Job success means execution finished; inspect the result for reproduction and completeness.</p>
    {jobs.length > 0 && <table><thead><tr><th>Job</th><th>Input / range</th><th>Mode</th><th>Status</th><th>Result</th></tr></thead><tbody>{jobs.map(j => <tr key={j.id}><td>{j.id}</td><td>{j.input_id} · {j.from_height}–{j.to_height}</td><td>{j.mode}</td><td>{j.status}{j.issue && <><br />{j.issue}</>}</td><td>{j.reexec_id != null && <button type="button" onClick={() => onResult(j.reexec_id!)}>Open result {j.reexec_id}</button>}</td></tr>)}</tbody></table>}
  </section>;
}
