import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { getOwnInputSource, matchesOwnInputSource, OwnInputEvidence } from "./views/OwnInputEvidence";
import { get } from "./api/client";
vi.mock("./api/client",()=>({get:vi.fn()}));
const proof:Schemas["MessagesOwnInputEvidence"]={outcome:{input:"native",file:"frames-public.jsonl",ordinal:3,seq:"9007199254740993"},input:{input:"native",file:"frames-public.jsonl",ordinal:4,seq:"9007199254740994"},engine_run:"9007199254740995",step:"9007199254740996",journal_position:{segment:"0",offset:"9007199254740997"}};
const record:Schemas["MessagesRecord"]={input:"native",file:"frames-public.jsonl",ordinal:2,seq:"3",node:"self",run:"writer",type:"frame",phase:"PREPARE",dedup_key:"key",own_input_evidence:proof};
describe("accepted own bytes",()=>{
 it("opens immutable file ordinal rather than the original sequence",async()=>{vi.mocked(get).mockResolvedValue({} as never);await getOwnInputSource(7,11,proof.input);expect(get).toHaveBeenCalledWith("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net:7,dataset:11},query:{input:"native",file:"frames-public.jsonl",ordinal:"4"}})});
 it("keeps large coordinates and distinguishes relation links from execution order",()=>{const html=renderToStaticMarkup(<OwnInputEvidence net={7} dataset={11} record={record} onAuth={()=>{}}/>);for(const n of [proof.outcome.seq,proof.input.seq,proof.engine_run,proof.step,proof.journal_position.offset])expect(html).toContain(n);expect(html).toContain("Link order is independent of execution time");expect(html).toContain("Open accepted outcome source");expect(html).toContain("Open internal input source");expect(renderToStaticMarkup(<OwnInputEvidence net={7} dataset={11} record={{...record,own_input_evidence:null}} onAuth={()=>{}}/>)).toBe("")});
 it("checks returned source identity rather than trusting a matching step alone",()=>{const original={...record,...proof.input,type:"own_input",engine_run:proof.engine_run,step:proof.step};expect(matchesOwnInputSource(record,original,proof.input,proof)).toBe(true);for(const change of [{run:"other"},{node:"other"},{engine_run:"2"},{seq:"8"},{ordinal:5},{dedup_key:"other"},{type:"outcome"}])expect(matchesOwnInputSource(record,{...original,...change},proof.input,proof)).toBe(false)});
});
