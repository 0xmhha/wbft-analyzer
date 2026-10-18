export type GovernanceFocus={dataset:number;call:number;entry:number;collection:"changes"|"operations";snapshot:string};

export function governanceFocus(query:string):{governanceFocus?:GovernanceFocus;sourceError?:string}{
 if(!query)return {};
 const p=new URLSearchParams(query),fail={sourceError:"Invalid governance source link."};
 const keys=["dataset","call","entry","collection","snapshot"];
 if(keys.some(k=>p.getAll(k).length!==1)||[...p.keys()].some(k=>!keys.includes(k)))return fail;
 const positive=(key:string)=>{const raw=p.get(key)||"";return /^[1-9][0-9]*$/.test(raw)&&Number.isSafeInteger(Number(raw))?Number(raw):0};
 const dataset=positive("dataset"),call=positive("call"),entry=positive("entry"),snapshot=p.get("snapshot")||"";
 const collection=p.get("collection");
 if(!dataset||!call||!entry||(collection!=="changes"&&collection!=="operations")||!/^[0-9a-f]{64}$/.test(snapshot))return fail;
 return {governanceFocus:{dataset,call,entry,collection,snapshot}};
}

export function governanceSourceLink(net:number,source:GovernanceFocus):string{
 return `#/networks/${net}/governance?dataset=${source.dataset}&call=${source.call}&entry=${source.entry}&collection=${source.collection}&snapshot=${source.snapshot}`;
}
