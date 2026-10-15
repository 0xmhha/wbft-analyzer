import {beforeEach,expect,it,vi} from "vitest";
const get=vi.hoisted(()=>vi.fn());
vi.mock("./api/client",()=>({get}));
import {loadMissingEvidence} from "./views/Missing";
beforeEach(()=>get.mockReset());
it("opens a journal checkpoint in its message dataset by immutable source coordinates",()=>{
 loadMissingEvidence(3,7,{kind:"message",dataset_id:11,input:"journal",file:"synthetic.wal",ordinal:19,node:"synthetic",run:"r",t_wall:""});
 expect(get).toHaveBeenCalledWith("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net:3,dataset:11},query:{input:"journal",file:"synthetic.wal",ordinal:"19"}});
});
it("keeps native coverage pointers in their original event dataset",()=>{
 loadMissingEvidence(3,7,{kind:"event",input:"events",ordinal:5,node:"synthetic",run:"r",t_wall:""});
 expect(get).toHaveBeenCalledWith("/v1/networks/{net}/datasets/{dataset}/events/{input}/{line}",{path:{net:3,dataset:7,input:"events",line:5}});
});

it("refuses an incomplete journal pointer instead of selecting the event dataset",async()=>{
 await expect(loadMissingEvidence(3,7,{kind:"message",input:"journal",ordinal:19,node:"synthetic",run:"r",t_wall:""})).rejects.toThrow("original dataset or file");
 expect(get).not.toHaveBeenCalled();
});
