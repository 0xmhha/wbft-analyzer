import type {Schemas} from "./api/client";
type Native=Schemas["ScenarioRecordedMessageEvidence"];
export function messageChange(kind:"drop_message"|"swap_messages",rows:Native[],occurrences:string[],duration:number):Extract<Schemas["ScenarioNetworkChange"],{kind:"drop_message"|"swap_messages"}> {
 const count=kind==="drop_message"?1:2;
 if(rows.length!==count||occurrences.length!==count)throw new Error(`Choose exactly ${count} recorded incoming message${count===1?"":"s"}.`);
 const messages=rows.map((row,i)=>{
  const occurrence=occurrences[i]!;
  if(!/^[1-9][0-9]*$/.test(row.ordinal)||BigInt(row.ordinal)>9223372036854775807n||!/^[1-9][0-9]*$/.test(occurrence)||BigInt(occurrence)>18446744073709551615n)throw new Error("Use exact positive decimal source ordinals and model occurrences.");
  return {input:row.input,file:row.file,ordinal:row.ordinal,model_occurrence:occurrence};
 });
 if(count===2){
  if(rows[0]!.receiver.toLowerCase()!==rows[1]!.receiver.toLowerCase())throw new Error("Both messages must have the same recorded receiver.");
  if(messages[0]!.input===messages[1]!.input&&messages[0]!.file===messages[1]!.file&&messages[0]!.ordinal===messages[1]!.ordinal)throw new Error("Choose two different original records.");
 }
 if(!Number.isSafeInteger(duration)||duration<=0)throw new Error("Registered duration is unavailable.");
 return {kind,from_ns:0,to_ns:duration,messages};
}
