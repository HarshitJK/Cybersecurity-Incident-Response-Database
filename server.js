// server.js — SOC Shield Express server
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');

const authRoutes = require('./routes/auth');
const incidentRoutes = require('./routes/incidents');
const userRoutes = require('./routes/users');
const reportRoutes = require('./routes/reports');
const logRoutes = require('./routes/logs');
const systemRoutes = require('./routes/systems');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'soc_shield_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // set true if using HTTPS
        httpOnly: true,
        maxAge: 8 * 60 * 60 * 1000, // 8 hours
    },
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ─── API Routes ───────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/users', userRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/systems', systemRoutes);

// ─── RBAC Info endpoint ───────────────────────────────────────────────────
const db = require('./database/db');
app.get('/api/rbac/permissions', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM RolePermissions ORDER BY role_name, resource, action');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch permissions.' });
    }
});

// ─── Serve frontend for all non-API routes ────────────────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`
  ╔══════════════════════════════════════════════╗
  ║   🛡️  SOC SHIELD - Incident Response DB      ║
  ║   Server running on http://localhost:${PORT}   ║
  ╚══════════════════════════════════════════════╝
  `);
    console.log('📌 Demo accounts:');
    console.log('   admin@soc.com    / admin123');
    console.log('   manager@soc.com  / manager123');
    console.log('   analyst@soc.com  / analyst123');
    console.log('   auditor@soc.com  / auditor123\n');
});
