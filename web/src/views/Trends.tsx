import { useState } from "react";
import { get, type Schemas } from "../api/client";
import { margin, plot } from "../trend";
import { Labelled, Pending, useLoad } from "../ui";
import { alertStates } from "../visual";

const width = 760;
const height = 260;

/** Is an observation becoming more frequent? Rate per height over report time, with the alert rules. */
export function Trends({ net, onAuth }: { net: number; onAuth: () => void }) {
  // The kinds and the time window come from the network's reports.
  const base = useLoad(async () => {
    const { reports } = await get("/v1/reports", { query: { net } });
    const kinds = new Set<string>();
    await Promise.all(
      reports.map(async (r) => {
        const a = await get("/v1/reports/{id}/observations", { path: { id: r.id } });
        a.observations.forEach((o) => kinds.add(o.kind));
      }),
    );
    const times = reports.map((r) => r.finished_at).sort();
    return { kinds: [...kinds].sort(), from: times[0], to: times[times.length - 1] };
  }, [net]);
  const [picked, setKind] = useState<string>();
  const kind = picked ?? (base.state === "done" ? base.data.kinds[0] : undefined);
  const series = useLoad(async () => {
    if (base.state !== "done" || !kind || !base.data.from || !base.data.to) return undefined;
    const [pts, rules, alerts] = await Promise.all([
      get("/v1/networks/{net}/trends/observations", { path: { net }, query: { kind, from_t: base.data.from, to_t: base.data.to } }),
      get("/v1/networks/{net}/alert-rules", { path: { net } }),
      get("/v1/alerts", { query: { net } }),
    ]);
    const mine = rules.rules.filter((r) => r.kind === kind && r.node === "");
    const states = new Map(alerts.alerts.map((a) => [a.rule.id, a]));
    return { points: pts.points, rules: mine, states };
  }, [base.state, kind, net]);
  return (
    <section>
      <h1>Is an observation becoming more frequent?</h1>
      <Pending load={base} onAuth={onAuth} />
      {base.state === "done" && base.data.kinds.length === 0 && <p className="muted">The reports of this network have no observations.</p>}
      {base.state === "done" && base.data.kinds.length > 0 && (
        <label>
          Observation kind{" "}
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {base.data.kinds.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </label>
      )}
      <Pending load={series} onAuth={onAuth} />
      {series.state === "done" && series.data && (
        <>
          <TrendChart points={series.data.points} rules={series.data.rules} />
          <ul className="rules">
            {series.data.rules.length === 0 && <li className="muted">No alert rule for this kind (over all nodes).</li>}
            {series.data.rules.map((r) => {
              const a = r.id === undefined ? undefined : series.data?.states.get(r.id);
              const enc = alertStates[a?.state ?? "pending"] ?? alertStates.pending!;
              return (
                <li key={r.id ?? `${r.mode}-${r.window}`}>
                  <Labelled enc={enc} />{" "}
                  <span className="mono">
                    rule {r.id}: {r.mode === "absolute" ? `median of last ${r.window} > ${r.threshold}` : `median of last ${r.window} > ${r.threshold} × median of the ${r.baseline} before`}
                    {a && ` (recent ${a.recent}${r.mode === "relative" ? `, baseline ${a.baseline}` : ""})`}
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}

function TrendChart({ points, rules }: { points: Schemas["TrendPoint"][]; rules: Schemas["AlertRule"][] }) {
  const p = plot(points, rules, width, height);
  return (
    <svg className="chart" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="observation rate over time">
      {p.yTicks.map((t) => (
        <g key={t.y}>
          <line className="grid" x1={margin.left} x2={width - margin.right} y1={t.y} y2={t.y} />
          <text className="tick" x={margin.left - 6} y={t.y} textAnchor="end" dominantBaseline="middle">
            {t.label}
          </text>
        </g>
      ))}
      {p.xTicks.map((t) => (
        <text key={t.x} className="tick" x={t.x} y={height - 8} textAnchor="middle">
          {t.label}
        </text>
      ))}
      {p.thresholds.map((t) => (
        <g key={t.label}>
          <line className="threshold" x1={margin.left} x2={width - margin.right} y1={t.y} y2={t.y} />
          <text className="direct" x={width - margin.right + 6} y={t.y} dominantBaseline="middle">
            {t.label}
          </text>
        </g>
      ))}
      <path className="series" d={p.path} />
      {p.dots.map((d) => (
        <circle key={d.at} className="dot" cx={d.x} cy={d.y} r={3}>
          <title>{`${d.at}: ${d.rate}`}</title>
        </circle>
      ))}
      <text className="axis" x={margin.left} y={margin.top - 2}>
        per height
      </text>
    </svg>
  );
}
