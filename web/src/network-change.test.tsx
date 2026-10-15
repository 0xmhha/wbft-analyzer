import { expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { networkChange } from "./network-change";
import { NetworkChangeEvidence } from "./views/NetworkChangeEvidence";
it("preserves historical outgoing request bytes and directed partition meaning",()=>{
 expect(JSON.stringify(networkChange("cut_outgoing",3,"", "0","120000000000",4,120000000000))).toBe('{"kind":"cut_outgoing","node":3,"from_ns":0,"to_ns":120000000000}');
 const c=networkChange("partition",0,"3 -> 2\n3 -> 0\n3 -> 1","0","120000000000",4,120000000000);
 expect(c).toEqual({kind:"partition",from_ns:0,to_ns:120000000000,edges:[{from:3,to:0},{from:3,to:1},{from:3,to:2}]});
 const html=renderToStaticMarkup(<NetworkChangeEvidence change={c}/>);expect(html).toContain("explicit directed partition");expect(html).toContain("Directed links (3)");expect(html).toContain("Reverse links remain unchanged");expect(html).toContain("Recorded sender index");expect(html).not.toContain("from recorded node 0");
});
it("refuses missing, repeated, self, unknown, imprecise and malformed directions",()=>{
 for(const text of ["","0 -> 0","4 -> 0","0 -> 1\n0 -> 1","1 -> 9007199254740993","1,2","01 -> 2","1 <-> 2","-1 -> 2"]){expect(()=>networkChange("partition",0,text,"0","1",4,10)).toThrow()}
 for(const [from,to] of [["-1","1"],["0","0"],["1","0"],["0","11"],["0","9007199254740993"]])expect(()=>networkChange("partition",0,"0 -> 1",from!,to!,4,10)).toThrow();
});
