const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8787);
const DB = path.join(__dirname, 'licenses.json');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'CHANGE_THIS_ADMIN_TOKEN';
const HMAC_SECRET = process.env.HMAC_SECRET || 'CHANGE_THIS_LONG_RANDOM_SECRET';

function load(){ try{return JSON.parse(fs.readFileSync(DB,'utf8'));}catch{return {licenses:{}}} }
function save(db){fs.writeFileSync(DB,JSON.stringify(db,null,2));}
function json(res, code, obj){const b=Buffer.from(JSON.stringify(obj));res.writeHead(code,{'Content-Type':'application/json','Content-Length':b.length,'Access-Control-Allow-Origin':'*'});res.end(b)}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>s+=c);req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}})})}
function key(){return 'PM-'+crypto.randomBytes(16).toString('hex').toUpperCase()}
function deviceHash(x){return crypto.createHash('sha256').update(String(x)).digest('hex')}
function sig(obj){return crypto.createHmac('sha256',HMAC_SECRET).update(JSON.stringify(obj)).digest('hex')}

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, X-Admin-Token','Access-Control-Allow-Methods':'GET,POST,OPTIONS'});return res.end()}
  try{
    const url=new URL(req.url,`http://${req.headers.host}`);
    if(req.method==='POST' && url.pathname==='/activate'){
      const x=await body(req); const db=load(); const l=db.licenses[x.license];
      if(!l || l.revoked) return json(res,403,{ok:false,error:'INVALID_OR_REVOKED_LICENSE'});
      if(!x.deviceId) return json(res,400,{ok:false,error:'DEVICE_ID_REQUIRED'});
      const d=deviceHash(x.deviceId);
      if(!l.deviceHash){l.deviceHash=d;l.activatedAt=new Date().toISOString();save(db)}
      if(l.deviceHash!==d) return json(res,403,{ok:false,error:'LICENSE_ALREADY_BOUND_TO_ANOTHER_DEVICE'});
      const payload={license:x.license,deviceHash:d,exp:l.expiresAt||null};
      return json(res,200,{ok:true,token:Buffer.from(JSON.stringify(payload)).toString('base64url')+'.'+sig(payload),expiresAt:l.expiresAt||null});
    }
    if(req.method==='POST' && url.pathname==='/admin/create'){
      if(req.headers['x-admin-token']!==ADMIN_TOKEN)return json(res,401,{ok:false,error:'UNAUTHORIZED'});
      const x=await body(req);const db=load();const k=key();db.licenses[k]={owner:x.owner||'',revoked:false,createdAt:new Date().toISOString(),expiresAt:x.expiresAt||null,deviceHash:null};save(db);return json(res,200,{ok:true,license:k});
    }
    if(req.method==='POST' && url.pathname==='/admin/revoke'){
      if(req.headers['x-admin-token']!==ADMIN_TOKEN)return json(res,401,{ok:false,error:'UNAUTHORIZED'});
      const x=await body(req);const db=load();if(!db.licenses[x.license])return json(res,404,{ok:false,error:'NOT_FOUND'});db.licenses[x.license].revoked=true;save(db);return json(res,200,{ok:true});
    }
    if(req.method==='GET' && url.pathname==='/health')return json(res,200,{ok:true});
    return json(res,404,{ok:false,error:'NOT_FOUND'});
  }catch(e){return json(res,500,{ok:false,error:'SERVER_ERROR'})}
});
server.listen(PORT,()=>console.log(`License server listening on http://localhost:${PORT}`));
