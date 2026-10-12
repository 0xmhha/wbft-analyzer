// The API client. Paths, parameters and answers come from the types
// generated from api/openapi.json (npm run gen), so a change of the API
// that the front end does not follow fails `npm run check`.
import type { components, paths } from "./schema";

export type Schemas = components["schemas"];

// The paths answered by GET with a JSON 200 answer.
type GetPath = {
  [P in keyof paths]: paths[P] extends { get: { responses: { 200: { content: { "application/json": unknown } } } } } ? P : never;
}[keyof paths];

type Answer<P extends GetPath> = paths[P] extends {
  get: { responses: { 200: { content: { "application/json": infer A } } } };
}
  ? A
  : never;

type Params<P extends GetPath> = paths[P] extends { get: { parameters: { path?: infer A; query?: infer Q } } }
  ? { path?: A; query?: Q }
  : never;

/** An answer that is not 2XX, with the server's message. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const tokenKey = "wbft-analyzer-token";

function readToken(): string {
  try {
    return sessionStorage.getItem(tokenKey) ?? "";
  } catch {
    return "";
  }
}

/** Sets the bearer token for this tab (a server started with --auth token). */
export function setToken(t: string): void {
  try {
    sessionStorage.setItem(tokenKey, t);
  } catch {
    // Storage blocked: the token lasts until the page is reloaded.
  }
  token = t;
}

let token = readToken();

/** Fills a path template such as /v1/networks/{net}. */
export function fill(template: string, values: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (_, k: string) => {
    const v = values[k];
    if (v === undefined) throw new Error(`no value for {${k}} in ${template}`);
    return encodeURIComponent(String(v));
  });
}

/** GETs an API path: the answer's type is that of the document. */
export async function get<P extends GetPath>(path: P, params?: Params<P>): Promise<Answer<P>> {
  let url = fill(path, (params?.path ?? {}) as Record<string, string | number>);
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries((params?.query ?? {}) as Record<string, unknown>)) {
    if (v !== undefined) q.set(k, String(v));
  }
  if ([...q].length > 0) url += `?${q}`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(url, { headers });
  if (!r.ok) {
    let msg = r.statusText;
    try {
      msg = ((await r.json()) as Schemas["Error"]).error;
    } catch {
      // Not the API's error answer.
    }
    throw new ApiError(r.status, msg);
  }
  return (await r.json()) as Answer<P>;
}
