import {requireAdmin} from '../../_lib/admin.js';
import {json} from '../../_lib/auth.js';
export async function onRequestGet({request,env}){
  const r=await requireAdmin(request,env);if(r.err)return r.err;
  return json({is_admin:true});
}
