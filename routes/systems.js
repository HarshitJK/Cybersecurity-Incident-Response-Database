// routes/systems.js — Systems management
const express = require('express');
const db = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/systems
router.get('/', requireAuth, requirePermission('systems', 'SELECT'), async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM Systems ORDER BY system_id');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch systems.' });
    }
});

// POST /api/systems — Admin only
router.post('/', requireAuth, requirePermission('systems', 'INSERT'), async (req, res) => {
    const { system_name, ip_address, owner, os_type, location, status } = req.body;
    if (!system_name || !ip_address) {
        return res.status(400).json({ error: 'System name and IP are required.' });
    }
    try {
        const [result] = await db.query(
            'INSERT INTO Systems (system_name, ip_address, owner, os_type, location, status) VALUES (?, ?, ?, ?, ?, ?)',
            [system_name, ip_address, owner, os_type, location, status || 'Online']
        );
        res.status(201).json({ message: 'System added.', system_id: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add system.' });
    }
});

// PUT /api/systems/:id
router.put('/:id', requireAuth, requirePermission('systems', 'UPDATE'), async (req, res) => {
    const { system_name, ip_address, owner, status } = req.body;
    try {
        await db.query(
            'UPDATE Systems SET system_name=?, ip_address=?, owner=?, status=? WHERE system_id=?',
            [system_name, ip_address, owner, status, req.params.id]
        );
        res.json({ message: 'System updated.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update system.' });
    }
});

// DELETE /api/systems/:id
router.delete('/:id', requireAuth, requirePermission('systems', 'DELETE'), async (req, res) => {
    try {
        await db.query('DELETE FROM Systems WHERE system_id = ?', [req.params.id]);
        res.json({ message: 'System removed.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to remove system.' });
    }
});

module.exports = router;
