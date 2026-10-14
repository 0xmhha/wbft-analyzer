import type { Schemas } from "./api/client";
type Point=Schemas["ScenarioDistributionPoint"];
type Band=Schemas["ScenarioSeedBand"];
export function extent(values:string[]):[string,string]{
 if(!values.length)return ["0","0"];
 let lo=BigInt(values[0]!),hi=lo;
 for(const value of values){const n=BigInt(value);if(n<lo)lo=n;if(n>hi)hi=n}
 return [lo.toString(),hi.toString()];
}
/** Only the final pixel ratio is approximated; labels and identity stay exact. */
export function pixel(value:string,[lo,hi]:[string,string],size:number):number{
 const n=BigInt(value),a=BigInt(lo),b=BigInt(hi);
 if(b===a)return 0;
 return Number((n-a)*1000000n/(b-a))/1000000*size;
}
export function ecdfPath(points:Point[],domain:[string,string],width=700,height=190):string{
 if(!points.length)return "";
 let path=`M0,${height}`;
 for(const point of points){path+=`H${pixel(point.value,domain,width)}V${height*(1-point.cumulative)}`}
 return path+`H${width}`;
}
export function bandPath(bands:Band[],x:[string,string],y:[string,string],width=700,height=190):string{
 if(!bands.length)return "";
 const point=(b:Band,value:string)=>`${pixel(b.height,x,width)},${height-pixel(value,y,height)}`;
 return "M"+bands.map(b=>point(b,b.maximum)).join("L")+"L"+[...bands].reverse().map(b=>point(b,b.minimum)).join("L")+"Z";
}
export function medianPath(bands:Band[],x:[string,string],y:[string,string],width=700,height=190):string{
 return bands.length?"M"+bands.map(b=>`${pixel(b.height,x,width)},${height-pixel(b.median,y,height)}`).join("L"):"";
}
