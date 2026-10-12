// The verdict overlay: requirements by reports.
import type { Schemas } from "./api/client";

export interface Matrix {
  reports: Schemas["Report"][]; // columns, by finish time
  rows: { requirement: string; cells: (string | undefined)[]; fails: number }[];
}

/**
 * Builds the overlay of the whole-run verdicts of reports. Rows with a
 * FAIL come first (most FAILs first), then by requirement ID; a cell is
 * undefined where the report does not list the requirement.
 */
export function buildMatrix(reports: Schemas["Report"][], results: Map<string, Schemas["Result"][]>): Matrix {
  const cols = [...reports].sort((a, b) => a.finished_at.localeCompare(b.finished_at) || a.id.localeCompare(b.id));
  const byReq = new Map<string, (string | undefined)[]>();
  cols.forEach((r, i) => {
    for (const x of results.get(r.id) ?? []) {
      if (x.node !== "") continue;
      let cells = byReq.get(x.requirement);
      if (!cells) {
        cells = new Array<string | undefined>(cols.length).fill(undefined);
        byReq.set(x.requirement, cells);
      }
      cells[i] = x.verdict;
    }
  });
  const rows = [...byReq].map(([requirement, cells]) => ({
    requirement,
    cells,
    fails: cells.filter((v) => v === "FAIL").length,
  }));
  rows.sort((a, b) => b.fails - a.fails || a.requirement.localeCompare(b.requirement));
  return { reports: cols, rows };
}
