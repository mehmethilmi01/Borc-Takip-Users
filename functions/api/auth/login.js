import {hashPassword,signToken,json,body} from '../../_lib/auth.js';
export async function onRequestPost({request,env}){
 const x=await body(request);const username=String(x?.username||'').trim().toLowerCase();const password=String(x?.password||'');
 if(!username||!password)return json({error:'Kullanıcı adı ve şifre gerekli.'},400);
 const u=await env.DB.prepare('SELECT id,username,password_salt,password_hash,backup_salt FROM users WHERE username_norm=?').bind(username).first();
 if(!u)return json({error:'Kullanıcı adı veya şifre hatalı.'},401);
 const p=await hashPassword(password,u.password_salt);if(p.hash!==u.password_hash)return json({error:'Kullanıcı adı veya şifre hatalı.'},401);
 const token=await signToken({sub:u.id,exp:Math.floor(Date.now()/1000)+60*60*24*30},env.AUTH_SECRET);
 return json({token,user:{id:u.id,username:u.username,backupSalt:u.backup_salt}});
}
