const forge = require('node-forge');
const fs = require('fs');

const privPem = fs.readFileSync('./keys/prof_private.pem', 'utf8');
const pubPem = fs.readFileSync('./keys/prof_public.pem', 'utf8');

const student = 'Roberto Pérez';
const grade = '80';
const dataString = `${student}-${grade}`;

const privateKey = forge.pki.privateKeyFromPem(privPem);
const md = forge.md.sha256.create();
md.update(dataString, 'utf8');
const sigBytes = privateKey.sign(md);
const signatureHex = forge.util.bytesToHex(sigBytes);

console.log('DataString:', dataString);
console.log('Signature (hex) len:', signatureHex.length);
console.log('Signature (hex) prefix:', signatureHex.slice(0, 40));

const pub = forge.pki.publicKeyFromPem(pubPem);
const ok = pub.verify(md.digest().bytes(), forge.util.hexToBytes(signatureHex));
console.log('Verification result:', ok);

// Try verifying by creating a fresh md and using verify with md
const md2 = forge.md.sha256.create();
md2.update(dataString, 'utf8');
const ok2 = pub.verify(md2.digest().bytes(), forge.util.hexToBytes(signatureHex));
console.log('Verification with new md:', ok2);

// Try verifying using node's crypto (for comparison)
const crypto = require('crypto');
try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(dataString);
    verifier.end();
    const pubKey = pubPem; // PEM
    const ok3 = verifier.verify(pubKey, signatureHex, 'hex');
    console.log('Node crypto verify result:', ok3);
} catch (err) {
    console.error('Node crypto verify error:', err.message);
}
