import {getUser,json,body} from '../_lib/auth.js';
export async function onRequestGet({request,env}){
 const u=await getUser(request,env);if(!u)return json({error:'Oturum geçersiz.'},401);
 const obj=await env.BACKUPS.get('users/'+u.id+'/latest.json');if(!obj)return json({payload:null,updatedAt:null});
 const payload=await obj.json();return json({payload,updatedAt:obj.uploaded||null});
}
export async function onRequestPut({request,env}){
 const u=await getUser(request,env);if(!u)return json({error:'Oturum geçersiz.'},401);
 const x=await body(request);const payload=x?.payload;if(!payload||payload.v!==1||typeof payload.iv!=='string'||typeof payload.cipher!=='string')return json({error:'Geçersiz şifreli yedek.'},400);
 const raw=JSON.stringify(payload);if(raw.length>50_000_000)return json({error:'Yedek dosyası 50 MB sınırını aşıyor.'},413);
 const key='users/'+u.id+'/latest.json';const previous=await env.BACKUPS.get(key);
 if(previous){const stamp=new Date().toISOString().replace(/[:.]/g,'-');await env.BACKUPS.put('users/'+u.id+'/history/'+stamp+'.json',previous.body,{httpMetadata:{contentType:'application/json'}})}
 await env.BACKUPS.put(key,raw,{httpMetadata:{contentType:'application/json'}});
 await env.DB.prepare('INSERT INTO backups(user_id,updated_at,size_bytes) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET updated_at=excluded.updated_at,size_bytes=excluded.size_bytes').bind(u.id,Date.now(),raw.length).run();
 return json({ok:true,updatedAt:Date.now()});
}
