const API = 'http://localhost:3000/api';

// --- Lógica de Login ---
async function register() {
    const user = document.getElementById('uUser').value;
    const pass = document.getElementById('uPass').value;
    await fetch(`${API}/auth/register`, {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ username: user, password: pass })
    });
    alert('Registrado. Ahora haz login.');
}

async function login() {
    const user = document.getElementById('uUser').value;
    const pass = document.getElementById('uPass').value;
    const res = await fetch(`${API}/auth/login`, {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ username: user, password: pass })
    });
    if (res.ok) {
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('app-section').style.display = 'block';
        loadGrades();
    } else {
        alert('Error credenciales');
    }
}

// --- LÓGICA CRIPTOGRÁFICA (LO IMPORTANTE) ---

async function submitSecure() {
    const student = document.getElementById('student').value;
    const grade = document.getElementById('grade').value;
    const comment = document.getElementById('comment').value;
    const profKeyPem = document.getElementById('profPrivateKey').value;

    if(!profKeyPem) return alert("Necesitas tu llave privada para firmar");

    // 1. OBTENER LLAVE PÚBLICA DEL SERVIDOR
    const keyRes = await fetch(`${API}/grades/public-key`);
    const { key: serverPublicKeyPem } = await keyRes.json();

    // 2. FIRMAR DATOS (Integridad)
    const md = forge.md.sha256.create();
    md.update(`${student}-${grade}`, 'utf8');
    const privateKey = forge.pki.privateKeyFromPem(profKeyPem);
    const signature = forge.util.bytesToHex(privateKey.sign(md));

    // Objeto a enviar
    const payload = JSON.stringify({ student, grade, comment, signature });

    // 3. CIFRADO HÍBRIDO (Confidencialidad)
    
    // A. Generar llave AES temporal (32 bytes)
    const aesKey = forge.random.getBytesSync(32);
    const iv = forge.random.getBytesSync(16);

    // B. Cifrar payload con AES
    const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(payload));
    cipher.finish();
    const encryptedData = cipher.output.toHex();

    // C. Cifrar llave AES con RSA Pública del Servidor
    const serverPub = forge.pki.publicKeyFromPem(serverPublicKeyPem);
    const encryptedKey = serverPub.encrypt(aesKey, 'RSA-OAEP');

    // 4. ENVIAR EL "SOBRE DIGITAL"
    const response = await fetch(`${API}/grades/submit`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            encryptedData: encryptedData,
            encryptedKey: forge.util.encode64(encryptedKey),
            iv: forge.util.bytesToHex(iv)
        })
    });

    const result = await response.json();
    alert(result.message || result.error);
    loadGrades();
}

async function loadGrades() {
    const res = await fetch(`${API}/grades/list`);
    const data = await res.json();
    document.getElementById('results').textContent = JSON.stringify(data, null, 2);
}