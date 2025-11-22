const forge = require('node-forge');
const fs = require('fs');

(async () => {
    const privPem = fs.readFileSync('./keys/prof_private.pem', 'utf8');
    const serverPubPem = fs.readFileSync('./keys/server_public.pem', 'utf8');

    const student = 'Roberto Pérez';
    const grade = '80';
    const comment = 'Le faltó entregar 2 trabajitos, pero muy bien, que siga así';
    const dataString = `${student}-${grade}`;

    const privateKey = forge.pki.privateKeyFromPem(privPem);
    const md = forge.md.sha256.create();
    md.update(dataString, 'utf8');
    const sigBytes = privateKey.sign(md);
    const signatureHex = forge.util.bytesToHex(sigBytes);

    const payload = JSON.stringify({ student, grade, comment, signature: signatureHex });

    // AES key and iv
    const aesKey = forge.random.getBytesSync(32);
    const iv = forge.random.getBytesSync(16);
    const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(payload, 'utf8'));
    cipher.finish();
    const encryptedData = cipher.output.toHex();

    const serverPub = forge.pki.publicKeyFromPem(serverPubPem);
    const encryptedKey = serverPub.encrypt(aesKey, 'RSA-OAEP');
    const encryptedKeyB64 = forge.util.encode64(encryptedKey);

    const body = {
        encryptedData: encryptedData,
        encryptedKey: encryptedKeyB64,
        iv: forge.util.bytesToHex(iv)
    };

    console.log('Sending envelope to server...');

    const res = await fetch('http://localhost:3000/api/grades/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    const json = await res.json();
    console.log('Server response:', json);
})();
