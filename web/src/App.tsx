import { eventFocus, type EventFocus } from "./sourceLink";
import { useCallback, useEffect, useState } from "react";
import { setToken } from "./api/client";
import { MessageLatency } from "./views/MessageLatency";
import { Datasets } from "./views/Datasets";
import { Scenarios } from "./views/Scenarios";
import { Whatif } from "./views/Whatif";
import { Reexec } from "./views/Reexec";
import { Follow } from "./views/Follow";
import { Nodes } from "./views/Nodes";
import { Missing } from "./views/Missing";
import { Messages } from "./views/Messages";
import { Events } from "./views/Events";
import { Headers } from "./views/Headers";
import { Overview } from "./views/Overview";
import { Trends } from "./views/Trends";
import { Verdicts } from "./views/Verdicts";

type Route = { view: "overview" } | { view: "verdicts" | "trends" | "headers" | "events" | "messages" | "message-latency" | "missing" | "nodes" | "follow" | "reexec" | "whatif" | "scenarios" | "datasets"; net: number; focus?: EventFocus; headerFocus?:{index:string;dataset:number;node:string}; sourceError?:string };

/** Reads the route from the hash: #/, #/networks/N/verdicts, #/networks/N/trends. */
export function parseRoute(hash: string): Route {
  const [path, query] = hash.split("?");
  const m = /^#\/networks\/(\d+)\/(verdicts|trends|headers|events|messages|message-latency|missing|nodes|follow|reexec|whatif|scenarios|datasets)$/.exec(path || "");
  if (m && m[1] && m[2] && Number.isSafeInteger(Number(m[1])) && Number(m[1]) > 0) return { view: m[2] as "verdicts" | "trends" | "headers" | "events" | "messages" | "message-latency" | "missing" | "nodes" | "follow" | "reexec" | "whatif" | "scenarios" | "datasets", net: Number(m[1]), ...(m[2] === "events" ? eventFocus(query || "") : m[2] === "headers" ? headerEvidenceFocus(query||"") : {}) };
  return { view: "overview" };
}

export function App() {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  const [askToken, setAskToken] = useState(false);
  const [epoch, setEpoch] = useState(0); // bumped to reload after a token is given
  useEffect(() => {
    const f = () => setRoute(parseRoute(location.hash));
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  const onAuth = useCallback(() => setAskToken(true), []);
  return (
    <>
      <header>
        <a href="#/" className="brand">
          wbft-analyzer
        </a>
        {route.view !== "overview" && (
          <nav>
            network {route.net}: <a href={`#/networks/${route.net}/verdicts`} className={route.view === "verdicts" ? "here" : ""}>verdicts</a>{" "}
            · <a href={`#/networks/${route.net}/headers`} className={route.view === "headers" ? "here" : ""}>headers</a>{" "} · <a href={`#/networks/${route.net}/events`}>events</a> · <a href={`#/networks/${route.net}/messages`}>messages</a> · <a href={`#/networks/${route.net}/message-latency`}>message latency</a> · <a href={`#/networks/${route.net}/missing`}>vote evidence</a> · <a href={`#/networks/${route.net}/nodes`}>nodes</a> · <a href={`#/networks/${route.net}/follow`}>follow</a> · <a href={`#/networks/${route.net}/reexec`}>core replay</a> · <a href={`#/networks/${route.net}/whatif`}>timer experiments</a> · <a href={`#/networks/${route.net}/scenarios`}>network experiments</a> · <a href={`#/networks/${route.net}/datasets`}>datasets</a> · <a href={`#/networks/${route.net}/trends`} className={route.view === "trends" ? "here" : ""}>trends</a>
          </nav>
        )}
      </header>
      {askToken && (
        <TokenForm
          onToken={(t) => {
            setToken(t);
            setAskToken(false);
            setEpoch((e) => e + 1);
          }}
        />
      )}
      <main key={epoch}>
        {route.view === "overview" && <Overview onAuth={onAuth} />}
        {route.view === "verdicts" && <Verdicts net={route.net} onAuth={onAuth} />}
        {route.view === "events" && <Events key={`${route.net}:${JSON.stringify(route.focus)}:${route.sourceError}`} net={route.net} focus={route.focus} sourceError={route.sourceError} onAuth={onAuth} />}
 {route.view === "message-latency" && <MessageLatency key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "scenarios" && <Scenarios key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "whatif" && <Whatif key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "reexec" && <Reexec key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "datasets" && <Datasets key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "follow" && <Follow key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "nodes" && <Nodes key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "missing" && <Missing key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "messages" && <Messages key={route.net} net={route.net} onAuth={onAuth} />}
        {route.view === "headers" && <Headers key={`${route.net}:${JSON.stringify(route.headerFocus)}`} net={route.net} onAuth={onAuth} focus={route.headerFocus} sourceError={route.sourceError} />}
        {route.view === "trends" && <Trends net={route.net} onAuth={onAuth} />}
      </main>
    </>
  );
}

/** Asks for the bearer token of a server started with --auth token; it is kept for this tab only. */
function TokenForm({ onToken }: { onToken: (t: string) => void }) {
  const [t, set] = useState("");
  return (
    <div
      className="token"
      onKeyDown={(e) => {
        if (e.key === "Enter" && t) onToken(t);
      }}
    >
      <label>
        Token <input type="password" autoComplete="off" value={t} onChange={(e) => set(e.target.value)} />
      </label>{" "}
      <button type="button" disabled={!t} onClick={() => onToken(t)}>
        Use
      </button>
    </div>
  );
}

export function headerEvidenceFocus(query:string):{headerFocus?:{index:string;dataset:number;node:string};sourceError?:string} {
 if(!query)return {};
 const p=new URLSearchParams(query);const fail={sourceError:"Invalid canonical header evidence link."};
 if([...p.keys()].some(k=>!["index","dataset","node"].includes(k)||p.getAll(k).length!==1))return fail;
 const index=p.get("index")||"",dataset=p.get("dataset"),node=p.get("node")||"";
 if(!/^(0|[1-9][0-9]{0,19})$/.test(index)||BigInt(index)>18446744073709551615n)return fail;
 const id=dataset===null?0:Number(dataset);
 if(dataset!==null&&(!/^[1-9][0-9]*$/.test(dataset)||!Number.isSafeInteger(id)||!node)||dataset===null&&node)return fail;
 return {headerFocus:{index,dataset:id,node}};
}
