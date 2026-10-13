import { eventFocus, type EventFocus } from "./sourceLink";
import { useCallback, useEffect, useState } from "react";
import { setToken } from "./api/client";
import { MessageLatency } from "./views/MessageLatency";
import { Nodes } from "./views/Nodes";
import { Missing } from "./views/Missing";
import { Messages } from "./views/Messages";
import { Events } from "./views/Events";
import { Headers } from "./views/Headers";
import { Overview } from "./views/Overview";
import { Trends } from "./views/Trends";
import { Verdicts } from "./views/Verdicts";

type Route = { view: "overview" } | { view: "verdicts" | "trends" | "headers" | "events" | "messages" | "message-latency" | "missing" | "nodes"; net: number; focus?: EventFocus; sourceError?:string };

/** Reads the route from the hash: #/, #/networks/N/verdicts, #/networks/N/trends. */
export function parseRoute(hash: string): Route {
  const [path, query] = hash.split("?");
  const m = /^#\/networks\/(\d+)\/(verdicts|trends|headers|events|messages|message-latency|missing|nodes)$/.exec(path || "");
  if (m && m[1] && m[2] && Number.isSafeInteger(Number(m[1])) && Number(m[1]) > 0) return { view: m[2] as "verdicts" | "trends" | "headers" | "events" | "messages" | "message-latency" | "missing" | "nodes", net: Number(m[1]), ...(m[2] === "events" ? eventFocus(query || "") : {}) };
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
            · <a href={`#/networks/${route.net}/headers`} className={route.view === "headers" ? "here" : ""}>headers</a>{" "} · <a href={`#/networks/${route.net}/events`}>events</a> · <a href={`#/networks/${route.net}/messages`}>messages</a> · <a href={`#/networks/${route.net}/message-latency`}>message latency</a> · <a href={`#/networks/${route.net}/missing`}>vote evidence</a> · <a href={`#/networks/${route.net}/nodes`}>nodes</a> · <a href={`#/networks/${route.net}/trends`} className={route.view === "trends" ? "here" : ""}>trends</a>
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
 {route.view === "nodes" && <Nodes key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "missing" && <Missing key={route.net} net={route.net} onAuth={onAuth} />}
 {route.view === "messages" && <Messages key={route.net} net={route.net} onAuth={onAuth} />}
        {route.view === "headers" && <Headers net={route.net} onAuth={onAuth} />}
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
