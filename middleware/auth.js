// middleware/auth.js — Authentication & RBAC middleware
const db = require('../database/db');

// ─── Ensure user is logged in ──────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }
    next();
}

// ─── Check SQL-style RBAC permission ──────────────────────────────────────
async function checkPermission(roleName, resource, action) {
    try {
        const [rows] = await db.query(
            `SELECT * FROM RolePermissions WHERE role_name = ? AND resource = ? AND action = ?`,
            [roleName, resource, action]
        );
        return rows.length > 0;
    } catch (err) {
        return false;
    }
}

// ─── Middleware factory: require RBAC permission ───────────────────────────
function requirePermission(resource, action) {
    return async (req, res, next) => {
        if (!req.session || !req.session.user) {
            return res.status(401).json({ error: 'Unauthorized. Please log in.' });
        }

        const userRole = req.session.user.role_name;
        const allowed = await checkPermission(userRole, resource, action);

        // Log the access attempt
        try {
            const logStatus = allowed ? 'Success' : 'Denied';
            const actionMsg = allowed
                ? `${action} on ${resource}`
                : `Attempted ${action} on ${resource} - ACCESS DENIED`;

            await db.query(
                `INSERT INTO AccessLogs (user_id, user_email, action, resource, status, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    req.session.user.user_id,
                    req.session.user.email,
                    actionMsg,
                    resource,
                    logStatus,
                    req.ip || '0.0.0.0',
                ]
            );
        } catch (_) {/* ignore log errors */ }

        if (!allowed) {
            return res.status(403).json({
                error: `Access Denied: Role '${userRole}' does not have ${action} permission on '${resource}'.`,
                rbac_info: {
                    role: userRole,
                    resource,
                    action,
                    sql_equivalent: `REVOKE ${action} ON ${resource} FROM ${userRole};`,
                },
            });
        }

        next();
    };
}

// ─── Require specific roles ────────────────────────────────────────────────
function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.session?.user) {
            return res.status(401).json({ error: 'Unauthorized.' });
        }
        if (!roles.includes(req.session.user.role_name)) {
            return res.status(403).json({
                error: `Access Denied: This action requires one of these roles: ${roles.join(', ')}.`,
            });
        }
        next();
    };
}

module.exports = { requireAuth, requirePermission, requireRole, checkPermission };
