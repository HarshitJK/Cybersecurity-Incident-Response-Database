// routes/incidents.js — Incident CRUD with RBAC enforcement
const express = require('express');
const db = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/incidents — list incidents (filtered by role)
router.get('/', requireAuth, requirePermission('incidents', 'SELECT'), async (req, res) => {
    try {
        const user = req.session.user;
        let query = `
      SELECT i.*,
        reporter.name AS reporter_name,
        reporter.email AS reporter_email,
        assignee.name AS assignee_name,
        assignee.email AS assignee_email
      FROM Incidents i
      LEFT JOIN Users reporter ON i.reported_by = reporter.user_id
      LEFT JOIN Users assignee ON i.assigned_to = assignee.user_id
    `;
        const params = [];

        // Analysts only see assigned incidents
        if (user.role_name === 'security_analyst') {
            query += ' WHERE i.assigned_to = ?';
            params.push(user.user_id);
        }

        query += ' ORDER BY i.created_at DESC';
        const [rows] = await db.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch incidents.' });
    }
});

// GET /api/incidents/stats — dashboard statistics
router.get('/stats', requireAuth, async (req, res) => {
    try {
        const [[totals]] = await db.query('SELECT COUNT(*) as total FROM Incidents');
        const [bySeverity] = await db.query('SELECT severity, COUNT(*) as count FROM Incidents GROUP BY severity');
        const [byStatus] = await db.query('SELECT status, COUNT(*) as count FROM Incidents GROUP BY status');
        const [[open]] = await db.query("SELECT COUNT(*) as count FROM Incidents WHERE status = 'Open'");
        const [[critical]] = await db.query("SELECT COUNT(*) as count FROM Incidents WHERE severity = 'Critical'");
        const [[resolved]] = await db.query("SELECT COUNT(*) as count FROM Incidents WHERE status = 'Resolved'");
        const [recent] = await db.query(`
      SELECT i.*, reporter.name as reporter_name
      FROM Incidents i
      LEFT JOIN Users reporter ON i.reported_by = reporter.user_id
      ORDER BY i.created_at DESC LIMIT 5
    `);

        res.json({ total: totals.total, open: open.count, critical: critical.count, resolved: resolved.count, bySeverity, byStatus, recent });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch stats.' });
    }
});

// GET /api/incidents/:id — single incident detail
router.get('/:id', requireAuth, requirePermission('incidents', 'SELECT'), async (req, res) => {
    try {
        const user = req.session.user;
        const [rows] = await db.query(`
      SELECT i.*,
        reporter.name AS reporter_name, reporter.email AS reporter_email,
        assignee.name AS assignee_name, assignee.email AS assignee_email
      FROM Incidents i
      LEFT JOIN Users reporter ON i.reported_by = reporter.user_id
      LEFT JOIN Users assignee ON i.assigned_to = assignee.user_id
      WHERE i.incident_id = ?
    `, [req.params.id]);

        if (!rows.length) return res.status(404).json({ error: 'Incident not found.' });

        // Analyst can only view their assigned incidents
        if (user.role_name === 'security_analyst' && rows[0].assigned_to !== user.user_id) {
            return res.status(403).json({ error: 'Access Denied: You can only view your assigned incidents.' });
        }

        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch incident.' });
    }
});

// POST /api/incidents — create incident (Admin, Manager)
router.post('/', requireAuth, requirePermission('incidents', 'INSERT'), async (req, res) => {
    const { title, description, severity, affected_system, vector } = req.body;
    if (!title || !description || !severity) {
        return res.status(400).json({ error: 'Title, description, and severity are required.' });
    }

    try {
        const [result] = await db.query(
            `INSERT INTO Incidents (title, description, severity, status, reported_by, affected_system, vector)
       VALUES (?, ?, ?, 'Open', ?, ?, ?)`,
            [title, description, severity, req.session.user.user_id, affected_system || null, vector || null]
        );

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Created new incident #${result.insertId}: ${title}`, 'incidents', 'Success', req.ip || '0.0.0.0']
        );

        res.status(201).json({ message: 'Incident created.', incident_id: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create incident.' });
    }
});

// PUT /api/incidents/:id — update incident (Analyst updates status; Manager assigns)
router.put('/:id', requireAuth, requirePermission('incidents', 'UPDATE'), async (req, res) => {
    const { status, assigned_to, severity, title, description, affected_system, vector } = req.body;
    const user = req.session.user;

    try {
        const [existing] = await db.query('SELECT * FROM Incidents WHERE incident_id = ?', [req.params.id]);
        if (!existing.length) return res.status(404).json({ error: 'Incident not found.' });

        // Analyst can only update their own assigned incidents
        if (user.role_name === 'security_analyst') {
            if (existing[0].assigned_to !== user.user_id) {
                return res.status(403).json({ error: 'Access Denied: You can only update your assigned incidents.' });
            }
            // Analyst can only change status
            if (assigned_to !== undefined || severity !== undefined || title !== undefined) {
                return res.status(403).json({ error: 'Access Denied: Analysts can only update the status field.' });
            }
        }

        const fields = [];
        const params = [];

        if (status) { fields.push('status = ?'); params.push(status); }
        if (assigned_to !== undefined) { fields.push('assigned_to = ?'); params.push(assigned_to || null); }
        if (severity) { fields.push('severity = ?'); params.push(severity); }
        if (title) { fields.push('title = ?'); params.push(title); }
        if (description) { fields.push('description = ?'); params.push(description); }
        if (affected_system) { fields.push('affected_system = ?'); params.push(affected_system); }
        if (vector) { fields.push('vector = ?'); params.push(vector); }
        if (status === 'Resolved') { fields.push('resolved_at = NOW()'); }

        if (!fields.length) return res.status(400).json({ error: 'No fields to update.' });

        params.push(req.params.id);
        await db.query(`UPDATE Incidents SET ${fields.join(', ')} WHERE incident_id = ?`, params);

        const changes = Object.entries({ status, assigned_to, severity }).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`).join(', ');
        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [user.user_id, user.email, `Updated incident #${req.params.id}: ${changes}`, 'incidents', 'Success', req.ip || '0.0.0.0']
        );

        res.json({ message: 'Incident updated successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update incident.' });
    }
});

// DELETE /api/incidents/:id — Admin only
router.delete('/:id', requireAuth, requirePermission('incidents', 'DELETE'), async (req, res) => {
    try {
        await db.query('DELETE FROM ThreatReports WHERE incident_id = ?', [req.params.id]);
        await db.query('DELETE FROM Incidents WHERE incident_id = ?', [req.params.id]);

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Deleted incident #${req.params.id}`, 'incidents', 'Warning', req.ip || '0.0.0.0']
        );

        res.json({ message: 'Incident deleted.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete incident.' });
    }
});

module.exports = router;
