import {requireAdmin,USERNAME_RE} from '../../_lib/admin.js';
import {json,body,hashPassword} from '../../_lib/auth.js';
export async function onRequestGet({request,env}){
  const r=await requireAdmin(request,env);if(r.err)return r.err;
  const rows=await env.DB.prepare('SELECT u.id,u.username,u.created_at,u.is_admin,b.updated_at AS backup_at,b.size_bytes FROM users u LEFT JOIN backups b ON b.user_id=u.id ORDER BY u.created_at DESC').all();
  return json({users:rows.results||[]});
}
export async function onRequestPost({request,env}){
  const r=await requireAdmin(request,env);if(r.err)return r.err;
  const x=await body(request);
  const username=String(x?.username||'').trim();const password=String(x?.password||'');
  if(!USERNAME_RE.test(username))return json({error:'Kullanıcı adı 3-24 karakter olmalı (harf, rakam, . _ -).'},400);
  if(password.length<8||password.length>128)return json({error:'Şifre 8-128 karakter olmalı.'},400);
  const id=crypto.randomUUID();const p=await hashPassword(password);
  const backupSalt=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  try{
    await env.DB.prepare('INSERT INTO users(id,username,username_norm,password_salt,password_hash,backup_salt,created_at,is_admin,must_change) VALUES(?,?,?,?,?,?,?,0,1)')
      .bind(id,username,username.toLowerCase(),p.salt,p.hash,backupSalt,Date.now()).run();
  }catch(e){return json({error:'Bu kullanıcı adı zaten var.'},409)}
  return json({ok:true,id,username});
}
