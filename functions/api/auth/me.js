import {getUser,json} from '../../_lib/auth.js';
export async function onRequestGet({request,env}){const u=await getUser(request,env);if(!u)return json({error:'Oturum geçersiz.'},401);const row=await env.DB.prepare('SELECT backup_salt FROM users WHERE id=?').bind(u.id).first();return json({user:{...u,backupSalt:row.backup_salt}})}
