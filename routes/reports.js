// routes/reports.js — Threat Reports routes
const express = require('express');
const db = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/reports — list reports (by role)
router.get('/', requireAuth, requirePermission('threat_reports', 'SELECT'), async (req, res) => {
    try {
        const user = req.session.user;
        let query = `
      SELECT tr.*,
        i.title AS incident_title, i.severity,
        u.name AS analyst_name, u.email AS analyst_email
      FROM ThreatReports tr
      JOIN Incidents i  ON tr.incident_id = i.incident_id
      JOIN Users u      ON tr.analyst_id  = u.user_id
    `;
        const params = [];

        if (user.role_name === 'security_analyst') {
            query += ' WHERE tr.analyst_id = ?';
            params.push(user.user_id);
        }

        query += ' ORDER BY tr.created_at DESC';
        const [rows] = await db.query(query, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch reports.' });
    }
});

// GET /api/reports/:id
router.get('/:id', requireAuth, requirePermission('threat_reports', 'SELECT'), async (req, res) => {
    try {
        const [rows] = await db.query(`
      SELECT tr.*,
        i.title AS incident_title, i.severity, i.status AS incident_status,
        u.name AS analyst_name
      FROM ThreatReports tr
      JOIN Incidents i ON tr.incident_id = i.incident_id
      JOIN Users u     ON tr.analyst_id  = u.user_id
      WHERE tr.report_id = ?
    `, [req.params.id]);

        if (!rows.length) return res.status(404).json({ error: 'Report not found.' });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch report.' });
    }
});

// POST /api/reports — analysts submit reports
router.post('/', requireAuth, requirePermission('threat_reports', 'INSERT'), async (req, res) => {
    const { incident_id, report_text, findings, recommendations, ioc_data } = req.body;
    if (!incident_id || !report_text) {
        return res.status(400).json({ error: 'Incident ID and report text are required.' });
    }

    try {
        // Verify analyst is assigned to the incident (for analyst role)
        if (req.session.user.role_name === 'security_analyst') {
            const [inc] = await db.query(
                'SELECT * FROM Incidents WHERE incident_id = ? AND assigned_to = ?',
                [incident_id, req.session.user.user_id]
            );
            if (!inc.length) {
                return res.status(403).json({ error: 'Access Denied: You can only submit reports for your assigned incidents.' });
            }
        }

        const [result] = await db.query(
            `INSERT INTO ThreatReports (incident_id, analyst_id, report_text, findings, recommendations, ioc_data)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [incident_id, req.session.user.user_id, report_text, findings || null, recommendations || null, ioc_data || null]
        );

        await db.query(
            `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [req.session.user.user_id, req.session.user.email,
            `Submitted threat report #${result.insertId} for incident #${incident_id}`,
                'threat_reports', 'Success', req.ip || '0.0.0.0']
        );

        res.status(201).json({ message: 'Report submitted.', report_id: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to submit report.' });
    }
});

module.exports = router;
