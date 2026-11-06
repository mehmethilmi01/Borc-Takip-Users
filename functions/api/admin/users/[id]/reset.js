import {requireAdmin,wipeBackups} from '../../../../_lib/admin.js';
import {json,body,hashPassword} from '../../../../_lib/auth.js';
export async function onRequestPost({request,env,params}){
  const r=await requireAdmin(request,env);if(r.err)return r.err;
  const id=String(params.id||'');
  const x=await body(request);const password=String(x?.password||'');
  if(password.length<8||password.length>128)return json({error:'Şifre 8-128 karakter olmalı.'},400);
  const t=await env.DB.prepare('SELECT is_admin FROM users WHERE id=?').bind(id).first();
  if(!t)return json({error:'Kullanıcı bulunamadı.'},404);
  if(t.is_admin===1&&id!==r.u.id)return json({error:'Başka bir yöneticinin şifresi buradan sıfırlanamaz.'},400);
  const p=await hashPassword(password);
  // token_ver artırılır: bu kullanıcının tüm açık oturumları geçersiz olur.
  await env.DB.prepare('UPDATE users SET password_salt=?,password_hash=?,token_ver=COALESCE(token_ver,0)+1 WHERE id=?').bind(p.salt,p.hash,id).run();
  await wipeBackups(env,id);
  return json({ok:true});
}
