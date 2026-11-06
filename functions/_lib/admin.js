import {getUser,json} from './auth.js';
export const USERNAME_RE=/^[a-zA-Z0-9_.-]{3,24}$/;
export async function requireAdmin(request,env){
  const u=await getUser(request,env);
  if(!u)return {err:json({error:'Oturum geçersiz.'},401)};
  const row=await env.DB.prepare('SELECT is_admin FROM users WHERE id=?').bind(u.id).first();
  if(!row||row.is_admin!==1)return {err:json({error:'Bu işlem için yetkin yok.'},403)};
  return {u};
}
export async function wipeBackups(env,userId){
  const prefix='users/'+userId+'/';let cursor;
  do{
    const l=await env.BACKUPS.list({prefix,cursor});
    const keys=l.objects.map(o=>o.key);
    if(keys.length)await env.BACKUPS.delete(keys);
    cursor=l.truncated?l.cursor:undefined;
  }while(cursor);
  await env.DB.prepare('DELETE FROM backups WHERE user_id=?').bind(userId).run();
}
