import {renderToStaticMarkup} from "react-dom/server";
import {describe,it,expect} from "vitest";
import {LegacyAssociations} from "./views/MessageLatency";
describe("legacy execution evidence",()=>{
 it("labels declarations separately from native step and wire receipt proof",()=>{
 const html=renderToStaticMarkup(<LegacyAssociations proofs={[{input:"legacy",node:"node",address:"0x"+"1".repeat(40),native_input:"native",sha256:"a".repeat(64),native_sha256:"b".repeat(64),from_t:"2020-01-01T00:00:00Z",to_t:"2020-01-01T00:00:10Z",status:"declared_head_anchors",records:3,head_anchors:2,anchors:[{height:"18446744073709551615",hash:"0x"+"a".repeat(64),legacy:{input:"legacy",ordinal:4,node:"node",run:"1",t_wall:"2020-01-01T00:00:02Z",kind:"log"},native:{input:"native",ordinal:8,node:"native",run:"writer",t_wall:"2020-01-01T00:00:02Z",kind:"event"}}]}]}/>);
 expect(html).toContain("operator declarations");expect(html).toContain("do not prove native step identity or wire receipt");expect(html).toContain("processing timestamps");expect(html).toContain("18446744073709551615");expect(html).toContain("legacy:4 / native native:8");
 });
});
