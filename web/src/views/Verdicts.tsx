import { get } from "../api/client";
import { buildMatrix } from "../matrix";
import { Glyph, Labelled, Pending, useLoad } from "../ui";
import { absent, verdictEncoding, verdicts } from "../visual";

/** Where are the specification violations? Requirements by reports, whole-run verdicts. */
export function Verdicts({ net, onAuth }: { net: number; onAuth: () => void }) {
  const load = useLoad(async () => {
    const { reports } = await get("/v1/reports", { query: { net } });
    const results = new Map(
      await Promise.all(
        reports.map(async (r) => {
          const a = await get("/v1/reports/{id}/results", { path: { id: r.id }, query: { node: "" } });
          return [r.id, a.results] as const;
        }),
      ),
    );
    return buildMatrix(reports, results);
  }, [net]);
  return (
    <section>
      <h1>Where are the specification violations?</h1>
      <p className="legend">
        {Object.values(verdicts).map((e) => (
          <Labelled key={e.label} enc={e} />
        ))}
        <Labelled enc={absent} />
      </p>
      <Pending load={load} onAuth={onAuth} />
      {load.state === "done" && load.data.reports.length === 0 && <p className="muted">No report on this network.</p>}
      {load.state === "done" && load.data.reports.length > 0 && (
        <div className="scroll">
          <table className="matrix">
            <thead>
              <tr>
                <th>Requirement</th>
                {load.data.reports.map((r) => (
                  <th key={r.id} className="col" title={`${r.run_id}\n${r.id}`}>
                    {r.finished_at.slice(0, 16).replace("T", " ")}
                  </th>
                ))}
                <th className="num">FAIL</th>
              </tr>
            </thead>
            <tbody>
              {load.data.rows.map((row) => (
                <tr key={row.requirement}>
                  <td className="mono">{row.requirement}</td>
                  {row.cells.map((v, i) => (
                    <td key={i} className="cell">
                      <Glyph enc={verdictEncoding(v)} />
                    </td>
                  ))}
                  <td className="num">{row.fails || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
