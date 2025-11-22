const db = require('../config/db');
const cryptoService = require('../services/cryptoService');

exports.submitGrade = async (req, res) => {
    try {
        // Recibe el "Sobre Digital" del Frontend
        const decryptedData = cryptoService.hybridDecrypt(req.body);
        
        // Requisito 3: Verificar Firma
        const stringToVerify = `${decryptedData.student}-${decryptedData.grade}`;
        const isSigned = cryptoService.verifySignature(stringToVerify, decryptedData.signature);
        
        if (!isSigned) return res.status(403).json({ error: 'FIRMA FALSA DETECTADA' });

        // Requisito 2: Cifrar para la BD (AES)
        const secureComment = cryptoService.encryptData(decryptedData.comment);

        await db.execute(
            'INSERT INTO grades (student_name, grade, comment_encrypted, iv, digital_signature) VALUES (?, ?, ?, ?, ?)',
            [decryptedData.student, decryptedData.grade, secureComment.content, secureComment.iv, decryptedData.signature]
        );

        res.json({ message: 'Calificación blindada y guardada.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error de seguridad o descifrado.' });
    }
};

exports.getAll = async (req, res) => {
    const [rows] = await db.query('SELECT * FROM grades');
    // Desciframos para mostrar en pantalla
    const data = rows.map(r => ({
        ...r,
        comment_readable: cryptoService.decryptData(r.comment_encrypted, r.iv)
    }));
    res.json(data);
};