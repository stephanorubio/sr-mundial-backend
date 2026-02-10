require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors());

// --- CONEXIÓN DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_temporal_mundial_2026';

// --- MIDDLEWARE DE SEGURIDAD (EL GUARDIA) ---
// Esto verifica que el usuario tenga un token válido antes de dejarlo pasar
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

    if (!token) return res.status(401).json({ error: 'Acceso denegado. Falta token.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido o expirado.' });
        req.user = user; // Guardamos los datos del usuario en la petición
        next();
    });
};

// --- RUTAS DE AUTENTICACIÓN (Las que ya tenías) ---
function generateOTP() { return Math.floor(1000 + Math.random() * 9000).toString(); }

app.post('/api/auth/login-request', async (req, res) => {
    const { cedula } = req.body;
    try {
        const whitelistCheck = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        if (whitelistCheck.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado en la base.' });
        
        const userData = whitelistCheck.rows[0];
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60000);

        await pool.query(`
            INSERT INTO users (cedula, email, otp_code, otp_expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cedula) DO UPDATE SET otp_code = $3, otp_expires_at = $4`,
            [userData.cedula, userData.email, otp, expiresAt]
        );

        res.json({ success: true, message: 'OTP enviado', debug_code: otp, user_preview: { full_name: userData.full_name } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login-verify', async (req, res) => {
    const { cedula, code } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE cedula = $1', [cedula]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Solicite código primero.' });
        
        const user = result.rows[0];
        if (user.otp_code !== code) return res.status(401).json({ error: 'Código incorrecto.' });
        
        // Limpiamos OTP y generamos Token
        await pool.query('UPDATE users SET otp_code = NULL WHERE id = $1', [user.id]);
        const token = jwt.sign({ id: user.id, cedula: user.cedula }, JWT_SECRET, { expiresIn: '24h' });
        
        // Traemos info completa
        const profile = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        
        res.json({ success: true, token, user: profile.rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// NUEVAS RUTAS: GESTIÓN DE POLLAS
// ==========================================

// 1. DASHBOARD: Consultar estado (¿Qué he llenado?)
app.get('/api/dashboard/status', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // Viene del token

        // Verificamos si ya llenó la Polla 1
        const polla1 = await pool.query('SELECT id FROM prediction_million WHERE user_id = $1', [userId]);
        
        // Verificamos si ya llenó la Polla 2
        const polla2 = await pool.query('SELECT id FROM prediction_full_bracket WHERE user_id = $1', [userId]);

        res.json({
            polla_million_completed: polla1.rows.length > 0,
            polla_bracket_completed: polla2.rows.length > 0
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al consultar estado' });
    }
});

// 2. GUARDAR POLLA 1 (El Millón)
app.post('/api/predictions/million', authenticateToken, async (req, res) => {
    const { final_opponent, ecuador_score, opponent_score, champion } = req.body;
    const userId = req.user.id;

    // Validación básica
    if (!final_opponent || !champion) return res.status(400).json({ error: 'Faltan datos.' });

    try {
        // Usamos UPSERT (Insertar o Actualizar si ya existe)
        const query = `
            INSERT INTO prediction_million (user_id, final_opponent, ecuador_score, opponent_score, champion, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (user_id) 
            DO UPDATE SET 
                final_opponent = $2, 
                ecuador_score = $3, 
                opponent_score = $4, 
                champion = $5,
                updated_at = NOW()
            RETURNING id;
        `;
        
        await pool.query(query, [userId, final_opponent, ecuador_score, opponent_score, champion]);
        res.json({ success: true, message: 'Pronóstico del Millón guardado.' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al guardar pronóstico.' });
    }
});

const PORT = process.env.PORT || 3000;

// 3. CONSULTAR POLLA 1 (Para ver lo que ya guardé)
app.get('/api/predictions/million', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const result = await pool.query(
            'SELECT final_opponent, ecuador_score, opponent_score, champion FROM prediction_million WHERE user_id = $1', 
            [userId]
        );

        if (result.rows.length === 0) {
            // No ha votado todavía
            return res.json({ has_voted: false });
        }

        // Ya votó, devolvemos sus datos
        res.json({ 
            has_voted: true, 
            prediction: result.rows[0] 
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al cargar predicción' });
    }
});
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
