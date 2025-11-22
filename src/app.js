const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public'))); // Servir el Frontend

app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/grades', require('./routes/gradeRoutes'));

module.exports = app;