import { get } from "../api/client";
import { Pending, useLoad } from "../ui";

/** Which networks and reports are loaded? */
export function Overview({ onAuth }: { onAuth: () => void }) {
  const load = useLoad(async () => {
    const [nets, reps] = await Promise.all([get("/v1/networks"), get("/v1/reports")]);
    return { networks: nets.networks, unassigned: reps.reports.filter((r) => r.network_id === null) };
  }, []);
  return (
    <section>
      <h1>Which networks and reports are loaded?</h1>
      <Pending load={load} onAuth={onAuth} />
      {load.state === "done" && (
        <>
          {load.data.networks.length === 0 && <p className="muted">No network yet: load reports that name one.</p>}
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Chain ID</th>
                <th>Genesis</th>
                <th className="num">Reports</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {load.data.networks.map((n) => (
                <tr key={n.id}>
                  <td>{n.name || `#${n.id}`}</td>
                  <td className="mono">{n.chain_id}</td>
                  <td className="mono" title={n.genesis_hash}>
                    {n.genesis_hash.slice(0, 10)}…
                  </td>
                  <td className="num">{n.reports}</td>
                  <td>
                    <a href={`#/networks/${n.id}/verdicts`}>verdicts</a> · <a href={`#/networks/${n.id}/headers`}>headers</a> · <a href={`#/networks/${n.id}/trends`}>trends</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {load.data.unassigned.length > 0 && (
            <p className="muted">
              {load.data.unassigned.length} report(s) name no network (no chain ID and genesis hash) and appear in no view.
            </p>
          )}
        </>
      )}
    </section>
  );
}
