require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken'); // Necesitaremos generar tokens de sesión

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors());

// Conexión a Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Clave secreta para firmar tokens (En producción esto va en .env)
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_temporal_mundial_2026';

// --- UTILIDAD: Generar 4 dígitos aleatorios ---
function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

app.get('/', (req, res) => {
    res.json({ status: 'success', message: 'API SR Mundial - Auth OTP v2.0' });
});

// ==========================================
// RUTA 1: SOLICITAR INGRESO (Ingresa Cédula)
// ==========================================
app.post('/api/auth/login-request', async (req, res) => {
    const { cedula } = req.body;

    if (!cedula) return res.status(400).json({ error: 'Cédula requerida' });

    try {
        // 1. Validar si existe en la Whitelist (Clientes con seguro)
        const whitelistCheck = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);
        
        if (whitelistCheck.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Usted no cuenta con una póliza vigente para participar.' 
            });
        }

        const userData = whitelistCheck.rows[0];

        // 2. Generar Código de 4 dígitos y fecha de expiración (15 mins)
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60000); // 15 minutos

        // 3. GUARDAR o ACTUALIZAR en la tabla de usuarios activos (Upsert)
        // Si el usuario ya existe, actualizamos su código. Si no, lo creamos.
        const upsertQuery = `
            INSERT INTO users (cedula, email, otp_code, otp_expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cedula) 
            DO UPDATE SET otp_code = $3, otp_expires_at = $4
            RETURNING id;
        `;
        
        await pool.query(upsertQuery, [userData.cedula, userData.email, otp, expiresAt]);

        // 4. "ENVIAR" EL CÓDIGO (Simulación)
        // EN PRODUCCIÓN: Aquí llamaríamos a un servicio de Email (SendGrid/Resend) para enviar el código al correo userData.email
        // PARA DESARROLLO: Te devuelvo el código en el JSON para que puedas probar.
        
        console.log(`LOGIN CÉDULA ${cedula} - CÓDIGO GENERADO: ${otp}`);

        res.json({
            success: true,
            message: 'Código enviado a su correo electrónico.',
            debug_code: otp, // <--- OJO: Esto se quita en producción
            user_preview: {
                full_name: userData.full_name,
                email_masked: userData.email.replace(/(.{2})(.*)(@.*)/, "$1***$3") // Enmascarar email
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// ==========================================
// RUTA 2: VALIDAR CÓDIGO (Ingresa Cédula + Código)
// ==========================================
app.post('/api/auth/login-verify', async (req, res) => {
    const { cedula, code } = req.body;

    if (!cedula || !code) return res.status(400).json({ error: 'Faltan datos' });

    try {
        // 1. Buscar usuario y código
        const result = await pool.query(
            'SELECT * FROM users WHERE cedula = $1', 
            [cedula]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Solicite un código primero.' });
        }

        const user = result.rows[0];

        // 2. Validar coincidencia y expiración
        if (user.otp_code !== code) {
            return res.status(401).json({ error: 'Código incorrecto.' });
        }

        if (new Date() > new Date(user.otp_expires_at)) {
            return res.status(401).json({ error: 'El código ha expirado. Solicite uno nuevo.' });
        }

        // 3. ÉXITO: Limpiar código (para que no se use 2 veces) y generar Token
        await pool.query('UPDATE users SET otp_code = NULL WHERE id = $1', [user.id]);

        // Generamos un JWT para que el usuario navegue sin loguearse de nuevo
        const token = jwt.sign(
            { id: user.id, cedula: user.cedula },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Traemos datos completos de la whitelist para el frontend
        const profile = await pool.query('SELECT * FROM allowed_users WHERE cedula = $1', [cedula]);

        res.json({
            success: true,
            token: token, // Guarda esto en el LocalStorage del navegador
            user: profile.rows[0]
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al validar' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
