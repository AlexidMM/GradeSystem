const db = require('../config/db');
const cryptoService = require('../services/cryptoService');

exports.register = async (req, res) => {
    const { username, password } = req.body;
    // Requisito 1: Hash antes de guardar
    const hash = await cryptoService.hashPassword(password);
    
    try {
        await db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
        res.json({ message: 'Usuario registrado seguro' });
    } catch (e) { res.status(500).json({ error: e.message }); }
};

exports.login = async (req, res) => {
    const { username, password } = req.body;
    const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });
    
    const isValid = await cryptoService.verifyPassword(password, rows[0].password_hash);
    if (!isValid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    res.json({ message: 'Login exitoso', userId: rows[0].id });
};