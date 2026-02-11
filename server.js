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

        const maskedEmail = user.email.replace(/(.{2})(.*)(@.*)/, "$1***$3");

        res.json({ 
            success: true, 
            message: 'OTP Enviado', 
            debug_code: otp, 
            user_preview: { 
                full_name: user.full_name,
                email_masked: maskedEmail
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
        
        if (user.otp_code !== code) return res.status(401).json({ error: 'Código incorrecto.' });
        
        await pool.query('UPDATE users SET otp_code = NULL WHERE id = $1', [user.id]);
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });
        
        const profile = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        
        res.json({ 
            success: true, 
            token, 
            user: profile.rows[0]
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

app.get('/api/fixture', async (req, res) => {
    try {
        const query = `
            SELECT 
                m.id as match_id,
                m.group_letter,
                m.match_date,
                m.status,
                m.home_score,
                m.away_score,
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

app.post('/api/predictions/bracket', authenticateToken, async (req, res) => {
    const { predictions } = req.body;
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
// ZONA ADMIN
// ==========================================

const verifyAdmin = async (req, res, next) => {
    try {
        const userQuery = await pool.query('SELECT cedula FROM users WHERE id = $1', [req.user.id]);
        
        if (userQuery.rows.length === 0) {
            console.log("Admin Check: Usuario no encontrado");
            return res.status(403).json({ error: 'Usuario no identificado' });
        }

        const cedula = userQuery.rows[0].cedula;
        const adminCheck = await pool.query('SELECT is_admin FROM allowed_users WHERE cedula = $1', [cedula]);

        if (adminCheck.rows.length > 0 && adminCheck.rows[0].is_admin === true) {
            next();
        } else {
            console.log(`Admin Check Fallido para cédula ${cedula}`);
            res.status(403).json({ error: 'No tienes permisos de Administrador' });
        }
    } catch (err) {
        console.error("Error en verifyAdmin:", err);
        res.status(500).json({ error: 'Error de servidor validando admin' });
    }
};

app.post('/api/admin/set-result', authenticateToken, verifyAdmin, async (req, res) => {
    const { match_id, home_score, away_score } = req.body;
    
    try {
        const query = `
            UPDATE matches 
            SET home_score = $1, away_score = $2, status = 'FINISHED'
            WHERE id = $3
            RETURNING *`;
        
        const result = await pool.query(query, [home_score, away_score, match_id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Partido no encontrado' });
        }

        res.json({ success: true, match: result.rows[0] });
    } catch (err) {
        console.error("Error guardando SQL:", err);
        res.status(500).json({ error: 'Error guardando en base de datos' });
    }
});

app.get('/api/admin/rules', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM point_rules');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Error obteniendo reglas' }); }
});

app.post('/api/admin/rules', authenticateToken, verifyAdmin, async (req, res) => {
    const { rules } = req.body;
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
// RANKING DINÁMICO
// ==========================================

app.get('/api/leaderboard', async (req, res) => {
    try {
        const rulesRes = await pool.query('SELECT * FROM point_rules');
        const rules = {};
        rulesRes.rows.forEach(r => rules[r.stage] = r);

        const matchesRes = await pool.query(`SELECT id, stage, home_score, away_score FROM matches WHERE status = 'FINISHED'`);
        const realResults = matchesRes.rows;

        // OBTENER PUNTOS DE COMODINES PARA TODOS LOS USUARIOS
        const wildcardScores = await pool.query(`
            SELECT r.user_id, SUM(q.points) as total
            FROM user_wildcard_responses r
            JOIN wildcard_questions q ON r.question_id = q.id
            WHERE r.user_answer = q.correct_answer AND q.status = 'CLOSED'
            GROUP BY r.user_id
        `);
        const wildcardMap = {};
        wildcardScores.rows.forEach(row => wildcardMap[row.user_id] = parseInt(row.total || 0));

        const usersRes = await pool.query(`
            SELECT u.id, a.full_name, p.predictions 
            FROM users u
            JOIN allowed_users a ON u.cedula = a.cedula
            LEFT JOIN prediction_full_bracket p ON u.id = p.user_id
        `);

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
                        
                        const rule = rules[match.stage] || { points_winner: 3, points_bonus: 2, bonus_active: true };

                        const userSign = Math.sign(userH - userA);
                        const realSign = Math.sign(realH - realA);
                        let matchPoints = 0;

                        if (userSign === realSign) {
                            matchPoints += rule.points_winner;
                            if (userH === realH && userA === realA) {
                                exactHits++;
                                if (rule.bonus_active) matchPoints += rule.points_bonus;
                            }
                        }
                        points += matchPoints;
                    }
                });
            }

            // SUMAR PUNTOS DE COMODINES AL TOTAL
            points += (wildcardMap[user.id] || 0);

            return { name: user.full_name, points, exacts: exactHits };
        });

        leaderboard.sort((a, b) => b.points - a.points || b.exacts - a.exacts);
        leaderboard.forEach((u, i) => u.rank = i + 1);

        res.json(leaderboard);

    } catch (err) { console.error(err); res.status(500).json({ error: 'Error ranking' }); }
});

app.get('/api/user/my-stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const rulesRes = await pool.query('SELECT * FROM point_rules');
        const rules = {};
        rulesRes.rows.forEach(r => rules[r.stage] = r);

        const matchesRes = await pool.query("SELECT id, stage, home_score, away_score FROM matches WHERE status = 'FINISHED'");
        const realResults = matchesRes.rows;

        const predRes = await pool.query('SELECT predictions FROM prediction_full_bracket WHERE user_id = $1', [userId]);
        
        let totalPoints = 0;
        let exacts = 0;

        if (predRes.rows.length > 0 && realResults.length > 0) {
            const preds = predRes.rows[0].predictions;

            realResults.forEach(match => {
                const p = preds[match.id] || preds[String(match.id)];
                if (p) {
                    const rule = rules[match.stage] || { points_winner: 3, points_bonus: 2, bonus_active: true };
                    const userH = parseInt(p.home), userA = parseInt(p.away);
                    const realH = match.home_score, realA = match.away_score;

                    if (Math.sign(userH - userA) === Math.sign(realH - realA)) {
                        totalPoints += rule.points_winner;
                        if (userH === realH && userA === realA && rule.bonus_active) {
                            totalPoints += rule.points_bonus;
                            exacts++;
                        }
                    }
                }
            });
        }

        // SUMAR COMODINES AL PERFIL DEL USUARIO
        const wildcardPtsQuery = await pool.query(`
            SELECT SUM(q.points) as total
            FROM user_wildcard_responses r
            JOIN wildcard_questions q ON r.question_id = q.id
            WHERE r.user_id = $1 AND r.user_answer = q.correct_answer AND q.status = 'CLOSED'
        `, [userId]);
        const wildcardPoints = parseInt(wildcardPtsQuery.rows[0].total || 0);
        totalPoints += wildcardPoints;

        res.json({
            points: totalPoints,
            exact_matches: exacts
        });

    } catch (err) {
        res.status(500).json({ error: 'Error obteniendo estadísticas' });
    }
});

app.get('/api/user/dashboard-stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const leaderboardRes = await fetch(`${req.protocol}://${req.get('host')}/api/leaderboard`);
        const leaderboard = await leaderboardRes.json();

        const userQuery = await pool.query('SELECT cedula FROM users WHERE id = $1', [userId]);
        const cedula = userQuery.rows[0].cedula;
        const nameQuery = await pool.query('SELECT full_name FROM allowed_users WHERE cedula = $1', [cedula]);
        const fullName = nameQuery.rows[0].full_name;

        const myStats = leaderboard.find(u => u.name === fullName);

        if (!myStats) {
            return res.json({ points: 0, exacts: 0, rank: '--', name: fullName });
        }

        res.json({
            points: myStats.points,
            exacts: myStats.exacts,
            rank: myStats.rank,
            name: fullName
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error obteniendo estadísticas del dashboard' });
    }
});

// ==========================================
// COMODINES (WILD CARDS)
// ==========================================

app.post('/api/admin/wildcards', authenticateToken, verifyAdmin, async (req, res) => {
    const { question_text, category, options, points } = req.body;
    try {
        await pool.query(
            'INSERT INTO wildcard_questions (question_text, category, options, points) VALUES ($1, $2, $3, $4)',
            [question_text, category, JSON.stringify(options), points]
        );
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear pregunta' });
    }
});

app.get('/api/admin/wildcards', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM wildcard_questions ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener comodines' });
    }
});

app.post('/api/admin/wildcards/resolve', authenticateToken, verifyAdmin, async (req, res) => {
    const { question_id, correct_answer } = req.body;
    try {
        await pool.query(
            "UPDATE wildcard_questions SET correct_answer = $1, status = 'CLOSED' WHERE id = $2",
            [correct_answer, question_id]
        );
        res.json({ success: true, message: 'Pregunta cerrada y ganadora definida' });
    } catch (err) { res.status(500).json({ error: 'Error al cerrar' }); }
});

// --- RUTA PÚBLICA ACTUALIZADA: Listar comodines (Abiertos y Cerrados) ---
app.get('/api/wildcards', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        // Seleccionamos status y correct_answer para poder comparar en el frontend
        // Quitamos el filtro "WHERE q.status = 'OPEN'" para que el usuario vea sus resultados pasados
        const query = `
            SELECT q.id, q.question_text, q.category, q.options, q.points, q.status, q.correct_answer, r.user_answer
            FROM wildcard_questions q
            LEFT JOIN user_wildcard_responses r ON q.id = r.question_id AND r.user_id = $1
            ORDER BY q.status DESC, q.id DESC
        `;
        const result = await pool.query(query, [userId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener comodines' });
    }
});

app.post('/api/user/wildcards/answer', authenticateToken, async (req, res) => {
    const { question_id, user_answer } = req.body;
    const userId = req.user.id;

    try {
        const checkExisting = await pool.query(
            "SELECT user_answer FROM user_wildcard_responses WHERE user_id = $1 AND question_id = $2",
            [userId, question_id]
        );

        if (checkExisting.rows.length > 0) {
            return res.status(400).json({ error: 'Ya has respondido a esta pregunta y no se puede cambiar.' });
        }

        const query = `
            INSERT INTO user_wildcard_responses (user_id, question_id, user_answer)
            VALUES ($1, $2, $3)
        `;
        await pool.query(query, [userId, question_id, user_answer]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar la respuesta' });
    }
});
// --- ADMIN: Borrar Comodín y sus respuestas ---
app.delete('/api/admin/wildcards/:id', authenticateToken, verifyAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // Al usar DELETE CASCADE en la base de datos o borrar manualmente:
        // Primero borramos las respuestas de los usuarios para evitar errores de llave foránea
        await pool.query('DELETE FROM user_wildcard_responses WHERE question_id = $1', [id]);
        // Luego borramos la pregunta
        const result = await pool.query('DELETE FROM wildcard_questions WHERE id = $1', [id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Pregunta no encontrada' });
        }

        res.json({ success: true, message: 'Pregunta y puntos eliminados correctamente' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar el comodín' });
    }
});
// --- ARRANCAR SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor escuchando en puerto ${PORT}`);
});
