const enc = new TextEncoder();
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
export async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{2}/g).map(x=>parseInt(x,16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:210000,hash:'SHA-256'},key,256);
  return {salt:[...salt].map(x=>x.toString(16).padStart(2,'0')).join(''),hash:b64u(bits)};
}
export async function signToken(payload, secret) {
  const body=b64u(enc.encode(JSON.stringify(payload)));
  const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=await crypto.subtle.sign('HMAC',key,enc.encode(body)); return body+'.'+b64u(sig);
}
export async function verifyToken(token, secret) {
  if(!token||!secret) return null; const [body,sig]=token.split('.'); if(!body||!sig)return null;
  const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
  const ok=await crypto.subtle.verify('HMAC',key,fromB64u(sig),enc.encode(body)); if(!ok)return null;
  const p=JSON.parse(new TextDecoder().decode(fromB64u(body))); if(!p.exp||p.exp<Date.now()/1000)return null; return p;
}
export async function getUser(request, env) {
  const token=(request.headers.get('Authorization')||'').replace(/^Bearer\s+/i,'');
  const p=await verifyToken(token,env.AUTH_SECRET); if(!p?.sub)return null;
  return await env.DB.prepare('SELECT id, username FROM users WHERE id=?').bind(p.sub).first();
}
export const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
export async function body(request){try{return await request.json()}catch{return null}}
