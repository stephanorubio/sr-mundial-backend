require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();

// --- CONFIGURACIÓN ---
app.use(helmet());
app.use(express.json());
app.use(cors());

// --- BASE DE DATOS ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'secreto_temporal_mundial_2026';

// --- MIDDLEWARE DE SEGURIDAD ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Falta token' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// ==========================================
// RUTA DE EQUIPOS (Para que cargue la lista)
// ==========================================
app.get('/api/teams', async (req, res) => {
    try {
        const result = await pool.query('SELECT name, flag_url FROM teams ORDER BY name ASC');
        res.json(result.rows);
    } catch (err) {
        console.error("Error teams:", err);
        res.status(500).json({ error: 'Error obteniendo equipos' });
    }
});

// ==========================================
// AUTENTICACIÓN (LOGIN)
// ==========================================
function generateOTP() { return Math.floor(1000 + Math.random() * 9000).toString(); }

app.post('/api/auth/login-request', async (req, res) => {
    const { cedula } = req.body;
    try {
        const check = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        if (check.rows.length === 0) return res.status(404).json({ error: 'Cédula no encontrada en la base.' });

        const user = check.rows[0];
        const otp = generateOTP();
        const expires = new Date(Date.now() + 15 * 60000); 

        await pool.query(`
            INSERT INTO users (cedula, email, otp_code, otp_expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cedula) DO UPDATE SET otp_code = $3, otp_expires_at = $4`,
            [user.cedula, user.email, otp, expires]
        );

        // 🟢 CORRECCIÓN 1: Enviar email enmascarado para quitar el "undefined"
        const maskedEmail = user.email.replace(/(.{2})(.*)(@.*)/, "$1***$3");

        res.json({ 
            success: true, 
            message: 'OTP Enviado', 
            debug_code: otp, 
            user_preview: { 
                full_name: user.full_name,
                email_masked: maskedEmail // <--- AQUÍ ESTABA EL FALTANTE
            } 
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login-verify', async (req, res) => {
    const { cedula, code } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE cedula = $1', [cedula]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Pida el código primero.' });
        
        const user = result.rows[0];
        
        // Validar código
        if (user.otp_code !== code) return res.status(401).json({ error: 'Código incorrecto.' });
        
        // Limpiar OTP y generar Token
        await pool.query('UPDATE users SET otp_code = NULL WHERE id = $1', [user.id]);
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });
        
        // 🟢 CORRECCIÓN 2: Buscar datos completos del usuario para devolverlos al Frontend
        const profile = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        
        res.json({ 
            success: true, 
            token, 
            user: profile.rows[0] // <--- AQUÍ ESTABA EL OTRO FALTANTE QUE CAUSABA EL ERROR ROJO
        });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// RUTAS PRIVADAS (Dashboard y Pronósticos)
// ==========================================
app.get('/api/dashboard/status', authenticateToken, async (req, res) => {
    try {
        const p1 = await pool.query('SELECT id FROM prediction_million WHERE user_id = $1', [req.user.id]);
        const p2 = await pool.query('SELECT id FROM prediction_full_bracket WHERE user_id = $1', [req.user.id]);
        res.json({ polla_million_completed: p1.rows.length > 0, polla_bracket_completed: p2.rows.length > 0 });
    } catch (err) { res.status(500).json({ error: 'Error status' }); }
});

app.get('/api/predictions/million', authenticateToken, async (req, res) => {
    try {
        const resDb = await pool.query('SELECT final_opponent, ecuador_score, opponent_score, champion FROM prediction_million WHERE user_id = $1', [req.user.id]);
        if (resDb.rows.length === 0) return res.json({ has_voted: false });
        res.json({ has_voted: true, prediction: resDb.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Error get prediction' }); }
});

app.post('/api/predictions/million', authenticateToken, async (req, res) => {
    const { final_opponent, ecuador_score, opponent_score, champion } = req.body;
    try {
        const query = `
            INSERT INTO prediction_million (user_id, final_opponent, ecuador_score, opponent_score, champion, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (user_id) DO UPDATE SET 
                final_opponent = $2, ecuador_score = $3, opponent_score = $4, champion = $5, updated_at = NOW()`;
        await pool.query(query, [req.user.id, final_opponent, ecuador_score, opponent_score, champion]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Error save prediction' }); }
});
// ==========================================
// RUTAS POLLA 2 (BRACKET / GRUPOS)
// ==========================================

// 1. OBTENER EL CALENDARIO (FIXTURE)
app.get('/api/fixture', async (req, res) => {
    try {
        // Consulta compleja: Traemos el partido + Nombres y Banderas de los equipos
        const query = `
            SELECT 
                m.id as match_id,
                m.group_letter,
                m.match_date,
                t1.name as home_team, t1.flag_url as home_flag,
                t2.name as away_team, t2.flag_url as away_flag
            FROM matches m
            JOIN teams t1 ON m.home_team_id = t1.id
            JOIN teams t2 ON m.away_team_id = t2.id
            WHERE m.stage = 'GROUP_STAGE'
            ORDER BY m.group_letter, m.match_date ASC;
        `;
        const result = await pool.query(query);
        
        // Agrupamos por GRUPO (A, B, C...) para facilitar el frontend
        const groups = {};
        result.rows.forEach(match => {
            if (!groups[match.group_letter]) groups[match.group_letter] = [];
            groups[match.group_letter].push(match);
        });

        res.json(groups); // Devuelve: { "A": [partidos...], "B": [partidos...] }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error cargando fixture' });
    }
});

// 2. GUARDAR PRONÓSTICOS DEL BRACKET (JSON GIGANTE)
app.post('/api/predictions/bracket', authenticateToken, async (req, res) => {
    const { predictions } = req.body; // Esperamos un objeto JSON: { "match_1": {home: 2, away: 1}, ... }
    const userId = req.user.id;

    if (!predictions) return res.status(400).json({ error: 'Faltan pronósticos' });

    try {
        const query = `
            INSERT INTO prediction_full_bracket (user_id, predictions, last_updated)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id) 
            DO UPDATE SET predictions = $2, last_updated = NOW()
        `;
        await pool.query(query, [userId, JSON.stringify(predictions)]);
        
        res.json({ success: true, message: 'Bracket guardado correctamente' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error guardando bracket' });
    }
});

// 3. CARGAR PRONÓSTICOS EXISTENTES
app.get('/api/predictions/bracket', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT predictions FROM prediction_full_bracket WHERE user_id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.json({ has_voted: false });
        
        res.json({ has_voted: true, predictions: result.rows[0].predictions });
    } catch (err) {
        res.status(500).json({ error: 'Error cargando bracket' });
    }
});

// --- ARRANCAR SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor escuchando en puerto ${PORT}`);
});
