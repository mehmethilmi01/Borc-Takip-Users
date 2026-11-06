import {hashPassword,signToken,json,body} from '../../_lib/auth.js';
export async function onRequestPost({request,env}){
 const x=await body(request);const username=String(x?.username||'').trim();const password=String(x?.password||'');
 if(!/^[a-zA-Z0-9_.-]{3,24}$/.test(username))return json({error:'Kullanıcı adı 3-24 karakter olmalı.'},400);
 if(password.length<8||password.length>128)return json({error:'Şifre 8-128 karakter olmalı.'},400);
 const id=crypto.randomUUID();const p=await hashPassword(password);const backupSalt=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
 try{await env.DB.prepare('INSERT INTO users(id,username,username_norm,password_salt,password_hash,backup_salt,created_at) VALUES(?,?,?,?,?,?,?)').bind(id,username,username.toLowerCase(),p.salt,p.hash,backupSalt,Date.now()).run();}
 catch(e){return json({error:'Bu kullanıcı adı zaten alınmış.'},409)}
 const token=await signToken({sub:id,exp:Math.floor(Date.now()/1000)+60*60*24*30},env.AUTH_SECRET);
 return json({token,user:{id,username,backupSalt}});
}
