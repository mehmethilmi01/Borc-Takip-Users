import {requireAdmin,wipeBackups} from '../../../../_lib/admin.js';
import {json} from '../../../../_lib/auth.js';
export async function onRequestDelete({request,env,params}){
  const r=await requireAdmin(request,env);if(r.err)return r.err;
  const id=String(params.id||'');
  if(id===r.u.id)return json({error:'Kendi hesabını silemezsin.'},400);
  const t=await env.DB.prepare('SELECT is_admin FROM users WHERE id=?').bind(id).first();
  if(!t)return json({error:'Kullanıcı bulunamadı.'},404);
  if(t.is_admin===1)return json({error:'Yönetici hesabı silinemez.'},400);
  await wipeBackups(env,id);
  await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
  return json({ok:true});
}
