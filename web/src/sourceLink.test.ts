import { expect, it } from "vitest";
import { parseRoute } from "./App";
import { eventFocus, eventSourceLink } from "./sourceLink";
import type { Schemas } from "./api/client";

it("keeps a companion source's dataset and exact source ordinal through an event route",()=>{
 const source:Schemas["MessagesSource"]={dataset_id:2,kind:"event",input:"events-a",ordinal:7,node:"a",run:"r",t_wall:"2020-01-01T00:00:00Z"};
 const hash=eventSourceLink(1,source,3)!;
 expect(parseRoute(hash)).toEqual({view:"events",net:1,focus:{dataset:2,input:"events-a",line:7,replay:true}});
 expect(eventSourceLink(1,{...source,kind:"message",file:"synthetic.wal"},3)).toBeUndefined();
 expect(eventSourceLink(1,{...source,input:"../file"},3)).toBeUndefined();
});
it("refuses ambiguous, unsafe and incomplete source links without silently choosing a source",()=>{
 for(const query of ["dataset=1&input=a&line=0","dataset=1&input=a&line=1&line=2","dataset=9007199254740993&input=a&line=1","dataset=1&input=../file&line=1","dataset=1&input=a","dataset=1&input=a&line=1&replay=2","dataset=1&input=a&line=1&url=https://example.com"]){
  expect(eventFocus(query).focus).toBeUndefined();expect(eventFocus(query).sourceError).toBeDefined();
 }
 expect(parseRoute("#/networks/9007199254740993/events?dataset=1&input=a&line=1")).toEqual({view:"overview"});
 expect(parseRoute("#/networks/1/events")).toEqual({view:"events",net:1});
});
