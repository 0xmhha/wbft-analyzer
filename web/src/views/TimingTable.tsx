import {useState,type ReactNode} from "react";
export function TimingTable<T>({name,rows,headings,render}:{name:string;rows:T[];headings:string[];render:(row:T,index:number)=>ReactNode}){
 const [page,setPage]=useState(0),size=100,last=Math.max(0,Math.ceil(rows.length/size)-1),current=Math.min(page,last),start=current*size;
 return <section aria-label={name}><p role="status">Showing {rows.length?start+1:0}–{Math.min(start+size,rows.length)} of {rows.length} {name}.</p><table><thead><tr>{headings.map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{rows.slice(start,start+size).map((r,i)=>render(r,start+i))}</tbody></table><button disabled={current===0} onClick={()=>setPage(0)}>First {name}</button><button disabled={current===0} onClick={()=>setPage(current-1)}>Previous {name}</button><button disabled={current===last} onClick={()=>setPage(current+1)}>Next {name}</button><button disabled={current===last} onClick={()=>setPage(last)}>Last {name}</button></section>;
}
