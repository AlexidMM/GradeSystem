const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcrypt');
const forge = require('node-forge');
const path = require('path');

// Cargar llaves
const SERVER_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '../../keys/server_private.pem'), 'utf8');
// En un caso real, la pública del profe viene de una autoridad certificadora. Aquí la leemos del disco.
const PROF_PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '../../keys/prof_public.pem'), 'utf8');

// Llave Maestra derivada del .env para AES
const MASTER_KEY = crypto.createHash('sha256').update(process.env.MASTER_KEY_SECRET).digest();

const cryptoService = {
    // 1. LOGIN (HASH)
    hashPassword: async (pw) => await bcrypt.hash(pw, 10),
    verifyPassword: async (pw, hash) => await bcrypt.compare(pw, hash),

    // 2. DATOS EN REPOSO (AES - Para guardar en MySQL)
    encryptData: (text) => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', MASTER_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { content: encrypted, iv: iv.toString('hex') };
    },

    decryptData: (encryptedHex, ivHex) => {
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', MASTER_KEY, iv);
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    },

    // 3. VALIDAR FIRMA (RSA) - usar node-forge para ser consistente con el frontend
    verifySignature: (dataString, signatureHex) => {
        try {
            const pub = forge.pki.publicKeyFromPem(PROF_PUBLIC_KEY);
            const md = forge.md.sha256.create();
            md.update(dataString, 'utf8');
            const sigBytes = forge.util.hexToBytes(signatureHex);
            const ok = pub.verify(md.digest().bytes(), sigBytes);
            if (ok) return true;
            // Fallback: try Node's crypto verify which may accept a different padding/format
            try {
                const verify = crypto.createVerify('SHA256');
                verify.update(dataString);
                verify.end();
                const ok2 = verify.verify(PROF_PUBLIC_KEY, signatureHex, 'hex');
                if (ok2) {
                    console.warn('verifySignature: verification succeeded with Node crypto fallback');
                    return true;
                }
            } catch (err2) {
                console.warn('verifySignature: Node crypto fallback error', err2.message);
            }
            return false;
        } catch (err) {
            console.error('Error verificando firma:', err);
            return false;
        }
    },

    // 4. DESCIFRADO HÍBRIDO (Abrir el sobre del Frontend)
    hybridDecrypt: (package) => {
        const { encryptedData, encryptedKey, iv } = package;

        // A. Descifrar la llave AES temporal usando mi llave PRIVADA RSA
        const symmetricKey = crypto.privateDecrypt(
            { key: SERVER_PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
            Buffer.from(encryptedKey, 'base64')
        );

        // B. Usar esa llave AES para leer los datos
        const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, Buffer.from(iv, 'hex'));
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    }
};

module.exports = cryptoService;