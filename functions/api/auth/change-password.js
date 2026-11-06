import {getUser,hashPassword,signToken,json,body} from '../../_lib/auth.js';
export async function onRequestPost({request,env}){
  const u=await getUser(request,env);if(!u)return json({error:'Oturum geçersiz. Tekrar giriş yap.'},401);
  const x=await body(request);
  const cur=String(x?.currentPassword||'');const np=String(x?.newPassword||'');
  if(np.length<8||np.length>128)return json({error:'Yeni şifre 8-128 karakter olmalı.'},400);
  const row=await env.DB.prepare('SELECT password_salt,password_hash,token_ver FROM users WHERE id=?').bind(u.id).first();
  if(!row)return json({error:'Kullanıcı bulunamadı.'},404);
  const check=await hashPassword(cur,row.password_salt);
  if(check.hash!==row.password_hash)return json({error:'Mevcut şifre hatalı.'},401);
  if(cur===np)return json({error:'Yeni şifre eskisiyle aynı olamaz.'},400);
  const p=await hashPassword(np);const ver=(row.token_ver||0)+1;
  await env.DB.prepare('UPDATE users SET password_salt=?,password_hash=?,must_change=0,token_ver=? WHERE id=?').bind(p.salt,p.hash,ver,u.id).run();
  const token=await signToken({sub:u.id,ver,exp:Math.floor(Date.now()/1000)+60*60*24*30},env.AUTH_SECRET);
  return json({ok:true,token});
}
