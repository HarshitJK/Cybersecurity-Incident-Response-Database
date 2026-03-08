// routes/users.js — User management (Admin only)
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/users
router.get('/', requireAuth, requirePermission('users', 'SELECT'), async (req, res) => {
    try {
        const [rows] = await db.query(`
      SELECT u.user_id, u.name, u.email, u.is_active, u.last_login, u.created_at,
             r.role_name, r.description as role_description
      FROM Users u
      JOIN Roles r ON u.role_id = r.role_id
      ORDER BY u.created_at DESC
    `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users.' });
    }
});

// GET /api/users/analysts — list analysts (for assignment dropdowns)
router.get('/analysts', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.query(`
      SELECT u.user_id, u.name, u.email
      FROM Users u
      JOIN Roles r ON u.role_id = r.role_id
      WHERE r.role_name = 'security_analyst' AND u.is_active = 1
    `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch analysts.' });
    }
});

// GET /api/users/roles — list all roles
router.get('/roles', requireAuth, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM Roles ORDER BY role_id');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch roles.' });
    }
});

// POST /api/users — create user (Admin only)
router.post('/', requireAuth, requirePermission('users', 'INSERT'), async (req, res) => {
    const { name, email, password, role_id } = req.body;
    if (!name || !email || !password || !role_id) {
        return res.status(400).json({ error: 'Name, email, password, and role are required.' });
    }

    try {
        const [existing] = await db.query('SELECT user_id FROM Users WHERE email = ?', [email]);
        if (existing.length) return res.status(409).json({ error: 'Email already registered.' });

        const hash = await bcrypt.hash(password, 12);
        const [result] = await db.query(
            'INSERT INTO Users (name, email, password, role_id) VALUES (?, ?, ?, ?)',
            [name, email, hash, role_id]
        );

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Created new user: ${email} (user_id: ${result.insertId})`, 'users', 'Success', req.ip || '0.0.0.0']
        );

        res.status(201).json({ message: 'User created.', user_id: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create user.' });
    }
});

// PUT /api/users/:id — update user (Admin only)
router.put('/:id', requireAuth, requirePermission('users', 'UPDATE'), async (req, res) => {
    const { name, email, role_id, is_active, password } = req.body;

    try {
        const fields = [];
        const params = [];

        if (name) { fields.push('name = ?'); params.push(name); }
        if (email) { fields.push('email = ?'); params.push(email); }
        if (role_id) { fields.push('role_id = ?'); params.push(role_id); }
        if (is_active !== undefined) { fields.push('is_active = ?'); params.push(is_active); }
        if (password) {
            const hash = await bcrypt.hash(password, 12);
            fields.push('password = ?');
            params.push(hash);
        }

        if (!fields.length) return res.status(400).json({ error: 'No fields to update.' });

        params.push(req.params.id);
        await db.query(`UPDATE Users SET ${fields.join(', ')} WHERE user_id = ?`, params);

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Updated user #${req.params.id}`, 'users', 'Success', req.ip || '0.0.0.0']
        );

        res.json({ message: 'User updated.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update user.' });
    }
});

// DELETE /api/users/:id — Admin only
router.delete('/:id', requireAuth, requirePermission('users', 'DELETE'), async (req, res) => {
    if (parseInt(req.params.id) === req.session.user.user_id) {
        return res.status(400).json({ error: 'Cannot delete your own account.' });
    }
    try {
        await db.query('UPDATE Users SET is_active = 0 WHERE user_id = ?', [req.params.id]);

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Deactivated user #${req.params.id}`, 'users', 'Warning', req.ip || '0.0.0.0']
        );

        res.json({ message: 'User deactivated.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to deactivate user.' });
    }
});

module.exports = router;
