import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import assert from 'node:assert/strict';
const root=path.resolve(import.meta.dirname,'..'),m=JSON.parse(fs.readFileSync(new URL('package-manifest.json',import.meta.url)));
assert.equal(m.schemaVersion,'g4.public-availability-pilot-release.v1');assert.equal(m.financialAcceptance,false);assert.equal(m.planSha256,'409bc5880c2ac4fdb207da6e6d596c5cea74c245664dd50dac1fec819aa4c481');
for(const f of m.files){assert.ok(/^[a-zA-Z0-9_./-]+$/.test(f.path)&&!f.path.split('/').includes('..'));const p=path.join(root,f.path),s=fs.lstatSync(p);assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1);const b=fs.readFileSync(p);assert.equal(b.length,f.bytes);assert.equal(crypto.createHash('sha256').update(b).digest('hex'),f.sha256);}
console.log(JSON.stringify({status:'PUBLIC_PILOT_RELEASE_VERIFIED',files:m.files.length,planSha256:m.planSha256,financialAcceptance:false}));
