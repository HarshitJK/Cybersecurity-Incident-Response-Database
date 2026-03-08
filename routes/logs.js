// routes/logs.js — Access Logs (audit trail)
const express = require('express');
const db = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/logs — paginated access logs
router.get('/', requireAuth, requirePermission('access_logs', 'SELECT'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        const status = req.query.status || null;

        let whereClause = '';
        const params = [];
        if (status) {
            whereClause = 'WHERE al.status = ?';
            params.push(status);
        }

        const [[{ total }]] = await db.query(
            `SELECT COUNT(*) as total FROM AccessLogs al ${whereClause}`, params
        );

        const [rows] = await db.query(`
      SELECT al.*, u.name AS user_name, u.email AS user_email_ref
      FROM AccessLogs al
      LEFT JOIN Users u ON al.user_id = u.user_id
      ${whereClause}
      ORDER BY al.timestamp DESC
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

        res.json({ logs: rows, total, page, pages: Math.ceil(total / limit) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch logs.' });
    }
});

// GET /api/logs/stats — log statistics
router.get('/stats', requireAuth, requirePermission('access_logs', 'SELECT'), async (req, res) => {
    try {
        const [[totals]] = await db.query('SELECT COUNT(*) as total FROM AccessLogs');
        const [[denied]] = await db.query("SELECT COUNT(*) as count FROM AccessLogs WHERE status='Denied'");
        const [[warnings]] = await db.query("SELECT COUNT(*) as count FROM AccessLogs WHERE status='Warning'");
        const [byStatus] = await db.query('SELECT status, COUNT(*) as count FROM AccessLogs GROUP BY status');
        const [byResource] = await db.query('SELECT resource, COUNT(*) as count FROM AccessLogs GROUP BY resource ORDER BY count DESC');
        const [topUsers] = await db.query(`
      SELECT user_email, COUNT(*) as count FROM AccessLogs
      WHERE user_email IS NOT NULL
      GROUP BY user_email ORDER BY count DESC LIMIT 5
    `);

        res.json({ total: totals.total, denied: denied.count, warnings: warnings.count, byStatus, byResource, topUsers });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch log stats.' });
    }
});

module.exports = router;
