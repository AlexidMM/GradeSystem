// generateKeys.js
const crypto = require('crypto');
const fs = require('fs');

if (!fs.existsSync('./keys')) fs.mkdirSync('./keys');

const gen = (name) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });
    fs.writeFileSync(`./keys/${name}_public.pem`, publicKey.export({ type: 'pkcs1', format: 'pem' }));
    fs.writeFileSync(`./keys/${name}_private.pem`, privateKey.export({ type: 'pkcs1', format: 'pem' }));
};

gen('server'); // Para cifrado híbrido
gen('prof');   // Para firma digital
console.log("Llaves generadas en la carpeta /keys");