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

type PostPath = {
  [P in keyof paths]: paths[P] extends { post: { requestBody: unknown; responses: { 202: unknown } } } ? P : never;
}[keyof paths];
type PostBody<P extends PostPath> = paths[P] extends { post: { requestBody: { content: { "application/json": infer B } } } } ? B : never;
type PostAnswer<P extends PostPath> = paths[P] extends { post: { responses: { 202: { content: { "application/json": infer A } } } } } ? A : never;
type PostParams<P extends PostPath> = paths[P] extends { post: { parameters: { path: infer A } } } ? A : never;

/** Queues a documented JSON operation with the tab's authentication. */
export async function post<P extends PostPath>(path: P, values: PostParams<P>, body: PostBody<P>): Promise<PostAnswer<P>> {
  const headers: Record<string, string> = { Accept: "application/json", "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(fill(path, values as Record<string, string | number>), { method: "POST", headers, body: JSON.stringify(body) });
  if (!r.ok) {
    let message = r.statusText;
    try { message = ((await r.json()) as Schemas["Error"]).error; } catch { /* Keep the HTTP status text. */ }
    throw new ApiError(r.status, message);
  }
  return (await r.json()) as PostAnswer<P>;
}

type DeletePath = {[P in keyof paths]: paths[P] extends {delete:{requestBody:unknown;responses:{200:unknown}}}?P:never}[keyof paths];
type DeleteBody<P extends DeletePath> = paths[P] extends {delete:{requestBody:{content:{"application/json":infer B}}}}?B:never;
type DeleteAnswer<P extends DeletePath> = paths[P] extends {delete:{responses:{200:{content:{"application/json":infer A}}}}}?A:never;
type DeleteParams<P extends DeletePath> = paths[P] extends {delete:{parameters:{path:infer A}}}?A:never;

/** Deletes a scoped resource only with its documented confirmation body. */
export async function remove<P extends DeletePath>(path:P,values:DeleteParams<P>,body:DeleteBody<P>):Promise<DeleteAnswer<P>>{
 const headers:Record<string,string>={Accept:"application/json","Content-Type":"application/json"};if(token)headers.Authorization=`Bearer ${token}`;
 const r=await fetch(fill(path,values as Record<string,string|number>),{method:"DELETE",headers,body:JSON.stringify(body)});
 if(!r.ok){let message=r.statusText;try{message=((await r.json()) as Schemas["Error"]).error}catch{/* Keep HTTP status text. */}throw new ApiError(r.status,message)}
 return await r.json() as DeleteAnswer<P>;
}
