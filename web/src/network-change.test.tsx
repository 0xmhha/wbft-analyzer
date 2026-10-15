import { expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { allDirectedLinks,networkChange } from "./network-change";
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

it("keeps full-run delay scope and exact rational values without changing old requests",()=>{
 const set=networkChange("set_link_delay",0,"0 -> 1","0","10",4,10,{nanoseconds:"250000000"});
 expect(set).toEqual({kind:"set_link_delay",from_ns:0,to_ns:10,edges:[{from:0,to:1}],delay_ns:250000000});
 const ratio=networkChange("scale_link_delay",0,"0 -> 1","0","10",4,10,{numerator:"18014398509481986",denominator:"2"});
 expect(ratio).toEqual({kind:"scale_link_delay",from_ns:0,to_ns:10,edges:[{from:0,to:1}],scale:{numerator:"9007199254740993",denominator:"1"}});
 const html=renderToStaticMarkup(<NetworkChangeEvidence change={ratio}/>);expect(html).toContain("9007199254740993/1");expect(html).toContain("whole registered run");expect(html).toContain("Loss probabilities are unchanged");
 for(const fields of [{numerator:"1",denominator:"0"},{numerator:"1.5",denominator:"1"},{numerator:"18446744073709551616",denominator:"1"}])expect(()=>networkChange("scale_link_delay",0,"0 -> 1","0","10",4,10,fields)).toThrow();
 expect(()=>networkChange("set_link_delay",0,"0 -> 1","1","10",4,10,{nanoseconds:"1"})).toThrow("whole registered run");
 expect(()=>networkChange("set_link_delay",0,"0 -> 1","0","10",4,10,{nanoseconds:"86400000000001"})).toThrow();
});
it("bounds the rendered edge evidence for the whole 256-node graph",()=>{
 const text=allDirectedLinks(256),change=networkChange("partition",0,text,"0","10",256,10);
 expect(change.kind).toBe("partition");if(change.kind!=="partition")throw new Error("wrong change");expect(change.edges).toHaveLength(65280);
 const html=renderToStaticMarkup(<NetworkChangeEvidence change={change}/>);
 expect(html).toContain("Directed links (65280)");expect(html).toContain("Showing 1–100 of 65280 directions.");expect((html.match(/<tr>/g)??[]).length).toBe(101);expect(html).not.toContain('<td>255</td><td>254</td>');expect(html).toContain("Last directed links");
});
