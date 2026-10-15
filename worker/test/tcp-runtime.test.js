import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { Duplex } from 'node:stream';
import WebSocket from 'ws';
import { fixture } from './helpers/tcp-runtime-fixture.js';

for (const echo of [false,true]) for (const flow of [false,true]) {
  test(`real TCP HTTPS response: echo=${echo}, ACK=${flow}`,{timeout:20000},async t=>{
    const {cert,mf,events}=await fixture(t);
    const url=new URL('/tunnel',await mf.ready);url.protocol='ws:';
    const ws=new WebSocket(url,'wsvpn.v1',{headers:{Authorization:'Bearer test-only-token','X-Tunnel-Host':'8.8.8.8','X-Tunnel-Port':'443',...(flow?{'X-WSVPN-Flow-Control':'ack-v1'}:{}),...(echo?{'X-WSVPN-Path-Check':'echo-v1'}:{})},perMessageDeflate:false});
    t.after(()=>ws.terminate());
    let readyResolve,readyReject;const ready=new Promise((a,b)=>{readyResolve=a;readyReject=b;});
    let verified=false,up=0,down=0;const challenge=Buffer.alloc(33,42);challenge[0]=5;
    const wire=new Duplex({read(){},write(chunk,encoding,callback){up+=chunk.length;events.push({type:'client.ws.send',bytes:chunk.length});ws.send(Buffer.concat([Buffer.from([1]),chunk]),callback);},final(callback){ws.send(Buffer.from([2]),callback);}});
    wire.on('error',()=>{});t.after(()=>wire.destroy());
    ws.on('message',data=>{
      if(data.length===1&&data[0]===3){if(echo)ws.send(challenge);else{verified=true;readyResolve();}return;}
      if(echo&&!verified){assert.deepEqual(data,challenge);verified=true;readyResolve();return;}
      if(data[0]===1){down+=data.length-1;events.push({type:'client.ws.recv',bytes:data.length-1});wire.push(data.subarray(1));if(flow)ws.send(Buffer.from([4]));}
      else if(data.length===1&&data[0]===2)wire.push(null);
      else wire.destroy(new Error('Invalid frame'));
    });
    ws.on('error',e=>{readyReject(e);wire.destroy(e);});
    ws.on('close',()=>wire.destroy());
    await ready;
    const client=tls.connect({socket:wire,servername:'localhost',ca:cert,rejectUnauthorized:true});
    t.after(()=>client.destroy());
    const response=[];
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error('HTTPS response timeout: '+JSON.stringify(events))),6000);
      client.on('error',reject);
      client.once('secureConnect',()=>{
        assert.equal(client.authorized,true);events.push({type:'client.tls.verified'});
        client.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
      });
      client.on('data',data=>response.push(data));
      client.on('end',()=>{clearTimeout(timer);resolve();});
      client.on('error',()=>clearTimeout(timer));
    });
    const result=Buffer.concat(response);const split=result.indexOf('\r\n\r\n');
    assert.ok(result.subarray(0,split).toString().startsWith('HTTP/1.1 200'));
    assert.deepEqual(result.subarray(split+4),Buffer.alloc(180000,65));
    assert.equal(events.filter(x=>x.type==='origin.request').length,1);
    assert.ok(up>0&&down>180000);
  });
}
