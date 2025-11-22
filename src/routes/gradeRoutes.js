const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/gradeController');
const fs = require('fs');
const path = require('path');

router.post('/submit', ctrl.submitGrade);
router.get('/list', ctrl.getAll);

// Endpoint extra para que el Frontend obtenga la llave pública del servidor
router.get('/public-key', (req, res) => {
    const key = fs.readFileSync(path.join(__dirname, '../../keys/server_public.pem'), 'utf8');
    res.json({ key });
});

module.exports = router;