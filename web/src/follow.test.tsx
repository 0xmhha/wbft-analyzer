import { renderToStaticMarkup } from "react-dom/server";
import { expect,it } from "vitest";
import { parseRoute } from "./App";
import { FollowProgress } from "./views/Follow";
it("preserves full canonical index strings and the exact original companions",()=>{
 const html=renderToStaticMarkup(<FollowProgress state={{cursor:{dataset_id:1,next_index:"18446744073709551614",parent_hash:"synthetic-parent"},status:"ready",captured_heights:2,total_batches:1,last_issue:"participation_incomplete",last_commit_at:"2026-01-01T00:00:00Z",latest_batches:[{from_index:"18446744073709551612",to_index:"18446744073709551613",headers_dataset:2,observations_dataset:3}]}}/>);
 expect(html).toContain("18446744073709551614");expect(html).toContain("18446744073709551612–18446744073709551613");expect(html).toContain("synthetic-parent");expect(html).toContain("still running");expect(html).toContain("participation_incomplete");expect(parseRoute("#/networks/3/follow")).toEqual({view:"follow",net:3});
});
