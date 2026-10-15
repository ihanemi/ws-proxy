import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

// The production handler/session and cloudflare:sockets all run in workerd.
// Only the dial address is mapped to the isolated local TLS origin by this
// test entry point. Production destination validation is unchanged.
export async function fixture(t, secure = false) {
  const dir=mkdtempSync(join(tmpdir(),'wsvpn-tcp-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'key.pem'),'-out',join(dir,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
  const cert=readFileSync(join(dir,'cert.pem'));
  const key=readFileSync(join(dir,'key.pem'));
  const sockets=new Set(), events=[];
  const server=https.createServer({key:readFileSync(join(dir,'key.pem')),cert},(req,res)=>{
    let bytes=0;req.on('data',data=>{bytes+=data.length;});
    req.on('end',()=>{
      events.push({type:'origin.request',bytes});
      if (req.url === '/stall') return; // Test-only origin receives request but withholds response.
      const body=Buffer.alloc(180000,65);
      res.writeHead(200,{'Content-Length':body.length,'Connection':'close'});
      res.end(body,()=>events.push({type:'origin.response',bytes:body.length}));
    });
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{for(const s of sockets)s.destroy();server.close();});
  const entry=`import {connect} from 'cloudflare:sockets';import {createHandler} from './src/handler.js';export default {fetch:createHandler({connect:(address,options)=>connect({hostname:'127.0.0.1',port:${server.address().port}},options),fetcher:()=>{throw new Error('Unexpected DNS')},pair:()=>Object.values(new WebSocketPair()),upgrade:(webSocket,headers)=>new Response(null,{status:101,webSocket,headers})})};`;
  const bundle=await build({stdin:{contents:entry,resolveDir:process.cwd()},bundle:true,write:false,format:'esm',external:['cloudflare:sockets']});
  const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,compatibilityDate:'2026-09-09',bindings:{TUNNEL_TOKEN:'test-only-token'},...(secure?{https:true,httpsKey:key.toString(),httpsCert:cert.toString()}:{})}));
  t.after(()=>mf.dispose());
  return {cert,mf,events};
}

