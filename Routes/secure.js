// Routes/logs.js
const express = require('express');
const router = express.Router();
const verifyToken = require('../Middleware/token');
const requireRole = require('../Middleware/role');
const db = require('../Models/database');

// Admin-only view all logs (compliance and audit)
router.get('/audit', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const [rows] = await db.query(`
      SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.timestamp, audit_logs.ip_address
      FROM audit_logs
      JOIN users ON audit_logs.user_id = users.id
      ORDER BY audit_logs.timestamp DESC
    `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// regular users can view compliance logs (not audit logs)
router.get('/compliance', verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
      SELECT compliance_logs.id, users.username, compliance_logs.regulation,
             compliance_logs.status, compliance_logs.notes, compliance_logs.created_at
      FROM compliance_logs
      JOIN users ON compliance_logs.user_id = users.id
      ORDER BY compliance_logs.created_at DESC
    `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
