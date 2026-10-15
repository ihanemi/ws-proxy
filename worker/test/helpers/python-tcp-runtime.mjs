import { fixture } from './tcp-runtime-fixture.js';
const cleanup=[];
const {mf,cert,events}=await fixture({after:fn=>cleanup.push(fn)},true);
console.log(JSON.stringify({url:String(await mf.ready),ca:cert.toString()}));
process.stdin.setEncoding('utf8');
let pending='';
process.stdin.on('data',chunk=>{
  pending+=chunk;
  while(pending.includes('\n')){
    const i=pending.indexOf('\n');const cmd=pending.slice(0,i);pending=pending.slice(i+1);
    if(cmd==='stats')console.log(JSON.stringify({events}));
    if(cmd==='stop')process.stdin.destroy();
  }
});
process.stdin.on('close',async()=>{
  for(const fn of cleanup.reverse())await fn();
});
