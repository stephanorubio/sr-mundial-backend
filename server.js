require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');

const app = express();

// --- CONFIGURACIÓN ---
app.use(helmet());
app.use(express.json());
app.use(cors()); // Abierto a todo el mundo por ahora para pruebas

// --- CONEXIÓN BASE DE DATOS (NEON) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Necesario para conexiones SSL externas en Neon
  },
});

// --- RUTAS DE PRUEBA ---

// 1. Verificar que el servidor vive
app.get('/', (req, res) => {
    res.json({ status: 'success', message: 'API SR Mundial - Online v1.0' });
});

// 2. Verificar conexión a DB
app.get('/db-test', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ status: 'success', db_time: result.rows[0].now });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// --- INICIAR SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
