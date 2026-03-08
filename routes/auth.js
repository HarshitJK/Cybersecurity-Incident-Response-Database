// routes/auth.js — Login, logout, session management
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const router = express.Router();

// POST /api/auth/login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const [users] = await db.query(
            `SELECT u.*, r.role_name 
       FROM Users u 
       JOIN Roles r ON u.role_id = r.role_id 
       WHERE u.email = ? AND u.is_active = 1`,
            [email]
        );

        if (!users.length) {
            await db.query(
                `INSERT INTO AccessLogs (user_email, action, resource, status, ip_address)
         VALUES (?, ?, ?, ?, ?)`,
                [email, 'Failed login attempt - user not found', 'auth', 'Denied', req.ip || '0.0.0.0']
            );
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            await db.query(
                `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)`,
                [user.user_id, email, 'Failed login attempt - wrong password', 'auth', 'Denied', req.ip || '0.0.0.0']
            );
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Update last login
        await db.query('UPDATE Users SET last_login = NOW() WHERE user_id = ?', [user.user_id]);

        // Log success
        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [user.user_id, email, 'User login successful', 'auth', 'Success', req.ip || '0.0.0.0']
        );

        // Set session
        req.session.user = {
            user_id: user.user_id,
            name: user.name,
            email: user.email,
            role_id: user.role_id,
            role_name: user.role_name,
        };

        res.json({
            message: 'Login successful',
            user: {
                user_id: user.user_id,
                name: user.name,
                email: user.email,
                role_name: user.role_name,
            },
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error during login.' });
    }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
    const user = req.session.user;
    if (user) {
        db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [user.user_id, user.email, 'User logged out', 'auth', 'Success', req.ip || '0.0.0.0']
        ).catch(() => { });
    }
    req.session.destroy();
    res.json({ message: 'Logged out successfully.' });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
    if (!req.session?.user) {
        return res.status(401).json({ error: 'Not authenticated.' });
    }
    res.json({ user: req.session.user });
});

module.exports = router;
