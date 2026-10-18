import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { buildMatrix } from "../matrix";
import { Glyph, Labelled, Pending, useLoad } from "../ui";
import { absent, partlyPassed, verdictEncoding, verdicts } from "../visual";

export function ReportIdentities({ reports }: { reports: Schemas["Report"][] }) {
  return <>
    <h2>Report build and stored scope</h2>
    <p className="muted">Inspector build identifies the report writer. Stored scope describes this copy's classification; a public inspector report may be stored privately.</p>
    <div className="scroll report-identities" role="region" aria-label="Report build and stored scope" tabIndex={0}>
      <table>
        <thead><tr><th>Column</th><th>Report identity</th><th>Inspector build</th><th>Stored scope</th></tr></thead>
        <tbody>{reports.map((r, i) => <tr key={r.id}>
          <th scope="row">Report {i + 1}</th>
          <td><div>{r.finished_at}</div><div>{r.run_id}</div><code>{r.id}</code></td>
          <td>{r.inspector_build}</td><td>{r.visibility}</td>
        </tr>)}</tbody>
      </table>
    </div>
  </>;
}

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
        <Labelled enc={partlyPassed} />
        <Labelled enc={absent} />
      </p>
      <p className="muted">Partly passed: some instances passed, none failed, and others could not be decided. The requirement is still undecided.</p>
      <Pending load={load} onAuth={onAuth} />
      {load.state === "done" && load.data.reports.length === 0 && <p className="muted">No report on this network.</p>}
      {load.state === "done" && load.data.reports.length > 0 && (
        <>
        <ReportIdentities reports={load.data.reports} />
        <div className="scroll">
          <table className="matrix">
            <thead>
              <tr>
                <th>Requirement</th>
                {load.data.reports.map((r, i) => (
                  <th key={r.id} className="col" title={`${r.run_id}\n${r.id}`}>
                    Report {i + 1} · {r.finished_at.slice(0, 16).replace("T", " ")}
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
                      <Glyph enc={verdictEncoding(v?.verdict, v?.coverage)} />
                    </td>
                  ))}
                  <td className="num">{row.fails || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </>
      )}
    </section>
  );
}
