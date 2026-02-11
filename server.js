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

// 1. OBTENER EL CALENDARIO (FIXTURE) - VERSIÓN CORREGIDA
app.get('/api/fixture', async (req, res) => {
    try {
        const query = `
            SELECT 
                m.id as match_id,
                m.group_letter,
                m.match_date,
                m.status,        -- ¡IMPORTANTE! Para saber si ya terminó
                m.home_score,    -- ¡IMPORTANTE! Para ver el gol local
                m.away_score,    -- ¡IMPORTANTE! Para ver el gol visitante
                t1.name as home_team, t1.flag_url as home_flag,
                t2.name as away_team, t2.flag_url as away_flag
            FROM matches m
            JOIN teams t1 ON m.home_team_id = t1.id
            JOIN teams t2 ON m.away_team_id = t2.id
            WHERE m.stage = 'GROUP_STAGE'
            ORDER BY m.group_letter, m.match_date ASC;
        `;
        const result = await pool.query(query);
        
        const groups = {};
        result.rows.forEach(match => {
            if (!groups[match.group_letter]) groups[match.group_letter] = [];
            groups[match.group_letter].push(match);
        });

        res.json(groups);
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

// ==========================================
// ZONA ADMIN (CORREGIDA)
// ==========================================

// Middleware Admin con Logs de Depuración
const verifyAdmin = async (req, res, next) => {
    try {
        // 1. Buscamos quién es el usuario logueado
        const userQuery = await pool.query('SELECT cedula FROM users WHERE id = $1', [req.user.id]);
        
        if (userQuery.rows.length === 0) {
            console.log("Admin Check: Usuario no encontrado en tabla users");
            return res.status(403).json({ error: 'Usuario no identificado' });
        }

        const cedula = userQuery.rows[0].cedula;

        // 2. Verificamos si esa cédula es Admin en allowed_users
        const adminCheck = await pool.query('SELECT is_admin FROM allowed_users WHERE cedula = $1', [cedula]);

        if (adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin === true) {
            next(); // ¡Es admin!
        } else {
            console.log(`Admin Check Fallido: La cédula ${cedula} no tiene is_admin = true`);
            res.status(403).json({ error: 'No tienes permisos de Administrador' });
        }
    } catch (err) {
        console.error("Error en verifyAdmin:", err);
        res.status(500).json({ error: 'Error de servidor validando admin' });
    }
};

// Guardar Resultado Real (Con Logs)
app.post('/api/admin/set-result', authenticateToken, verifyAdmin, async (req, res) => {
    const { match_id, home_score, away_score } = req.body;
    
    console.log(`Guardando resultado: Match ${match_id} -> ${home_score} - ${away_score}`);

    try {
        const query = `
            UPDATE matches 
            SET home_score = $1, away_score = $2, status = 'FINISHED'
            WHERE id = $3
            RETURNING *`; // Agregamos RETURNING para ver si guardó
        
        const result = await pool.query(query, [home_score, away_score, match_id]);

        if (result.rowCount === 0) {
            console.log("Error: No se encontró el partido con ID", match_id);
            return res.status(404).json({ error: 'Partido no encontrado ID incorrecto' });
        }

        res.json({ success: true, match: result.rows[0] });
    } catch (err) {
        console.error("Error guardando SQL:", err);
        res.status(500).json({ error: 'Error guardando en base de datos' });
    }
});

// ==========================================
// CONFIGURACIÓN DE PUNTOS (ADMIN)
// ==========================================

// Obtener reglas actuales
app.get('/api/admin/rules', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM point_rules');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error obteniendo reglas' }); }
});

// Guardar nuevas reglas
app.post('/api/admin/rules', authenticateToken, verifyAdmin, async (req, res) => {
    const { rules } = req.body; // Array de reglas
    try {
        for (const r of rules) {
            await pool.query(
                'UPDATE point_rules SET points_winner=$1, points_bonus=$2, bonus_active=$3 WHERE stage=$4',
                [r.points_winner, r.points_bonus, r.bonus_active, r.stage]
            );
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Error guardando reglas' }); }
});

// ==========================================
// RANKING DINÁMICO (Cálculo Nuevo)
// ==========================================

app.get('/api/leaderboard', async (req, res) => {
    try {
        // 1. Obtener Reglas de Puntos
        const rulesRes = await pool.query('SELECT * FROM point_rules');
        const rules = {};
        rulesRes.rows.forEach(r => rules[r.stage] = r);

        // 2. Obtener Partidos Terminados
        const matchesRes = await pool.query(`SELECT id, stage, home_score, away_score FROM matches WHERE status = 'FINISHED'`);
        const realResults = matchesRes.rows;

        // 3. Obtener Pronósticos
        const usersRes = await pool.query(`
            SELECT u.id, a.full_name, p.predictions 
            FROM users u
            JOIN allowed_users a ON u.cedula = a.cedula
            LEFT JOIN prediction_full_bracket p ON u.id = p.user_id
        `);

        // 4. Calcular
        const leaderboard = usersRes.rows.map(user => {
            let points = 0;
            let exactHits = 0;

            if (user.predictions && realResults.length > 0) {
                const preds = user.predictions;

                realResults.forEach(match => {
                    const p = preds[match.id] || preds[String(match.id)];
                    if (p) {
                        const userH = parseInt(p.home);
                        const userA = parseInt(p.away);
                        const realH = match.home_score;
                        const realA = match.away_score;
                        
                        // Obtener regla para esta fase (o default si no existe)
                        const rule = rules[match.stage] || { points_winner: 3, points_bonus: 2, bonus_active: true };

                        // Lógica de Puntos
                        const userSign = Math.sign(userH - userA);
                        const realSign = Math.sign(realH - realA);
                        let matchPoints = 0;

                        // A. Acierto de Ganador (Base)
                        if (userSign === realSign) {
                            matchPoints += rule.points_winner;
                            
                            // B. Acierto Exacto (Bono)
                            if (userH === realH && userA === realA) {
                                exactHits++;
                                if (rule.bonus_active) {
                                    matchPoints += rule.points_bonus;
                                }
                            }
                        }
                        points += matchPoints;
                    }
                });
            }
            return { name: user.full_name, points, exacts: exactHits };
        });

        // Ordenar
        leaderboard.sort((a, b) => b.points - a.points || b.exacts - a.exacts);
        leaderboard.forEach((u, i) => u.rank = i + 1);

        res.json(leaderboard);

    } catch (err) { console.error(err); res.status(500).json({ error: 'Error ranking' }); }
});
// --- ARRANCAR SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor escuchando en puerto ${PORT}`);
});
