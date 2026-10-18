import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { ReportIdentities } from "./views/Verdicts";

it("distinguishes a public writer from the private classification of its stored copy", () => {
  const report: Schemas["Report"] = {
    id: "a".repeat(64), network_id: 1, run_id: "original-run", started_at: "2026-10-12T00:00:00Z",
    finished_at: "2026-10-12T00:01:00Z", inspector_version: "v", inspector_commit: "commit",
    inspector_build: "public", visibility: "private", catalog_sha256: "catalog", spec_commit: "spec",
    network: null, range: null, summary: {}, loaded_at: "2026-10-12T00:02:00Z",
  };
  const operator = { ...report, id: "b".repeat(64), run_id: "operator-run", inspector_build: "operator" };
  const html = renderToStaticMarkup(<ReportIdentities reports={[report, operator]} />);
  const rows = html.match(/<tr>.*?<\/tr>/g) ?? [];
  expect(rows[1]).toContain("Report 1");
  expect(rows[1]).toContain(report.id);
  expect(rows[1]).toContain("original-run");
  expect(rows[1]).toContain("<td>public</td><td>private</td>");
  expect(rows[2]).toContain("Report 2");
  expect(rows[2]).toContain(operator.id);
  expect(rows[2]).toContain("<td>operator</td><td>private</td>");
  expect(html).toContain('role="region"');
  expect(html).toContain('tabindex="0"');
});
