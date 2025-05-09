const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const verifyToken = require('../Middleware/token');
const requireRole = require('../Middleware/role');
const db = require('../Models/database');
const logAction = require('../Services/auditlog');
const { Parser } = require('json2csv');
const PDFDocument = require('pdfkit');

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

// All users can view logs
router.get('/compliance', verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT compliance_logs.id, users.username, compliance_logs.regulation,
                   compliance_logs.status, compliance_logs.notes, compliance_logs.created_at, compliance_logs.user_id
            FROM compliance_logs
            JOIN users ON compliance_logs.user_id = users.id
            ORDER BY compliance_logs.created_at DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create log
router.post(
    '/compliance',
    verifyToken,
    [
        body('regulation').notEmpty().withMessage('Regulation is required'),
        body('status').notEmpty().withMessage('Status is required'),
        body('notes').optional().isString()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { regulation, status, notes } = req.body;
        try {
            await db.query(
                'INSERT INTO compliance_logs (user_id, regulation, status, notes) VALUES (?, ?, ?, ?)',
                [req.user.id, regulation, status, notes]
            );
            res.status(201).json({ message: 'Compliance log created successfully' });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }
);

// Update log
router.put(
    '/compliance/:id',
    verifyToken,
    [
        body('regulation').notEmpty().withMessage('Regulation is required'),
        body('status').notEmpty().withMessage('Status is required'),
        body('notes').optional().isString()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const logId = req.params.id;
        const { regulation, status, notes } = req.body;

        try {
            const [rows] = await db.query('SELECT * FROM compliance_logs WHERE id = ?', [logId]);
            const log = rows[0];
            if (!log) return res.status(404).json({ message: 'Log not found' });

            if (req.user.id !== log.user_id && req.user.role !== 'admin') {
                return res.status(403).json({ message: 'Unauthorized to edit this log' });
            }

            await db.query(
                'UPDATE compliance_logs SET regulation = ?, status = ?, notes = ? WHERE id = ?',
                [regulation, status, notes, logId]
            );
            await logAction(req.user.id, `EDIT_COMPLIANCE_LOG_ID_${logId}`, req.ip);
            res.json({ message: 'Compliance log updated' });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }
);

// Delete log
router.delete('/compliance/:id', verifyToken, async (req, res) => {
    const logId = req.params.id;

    try {
        const [rows] = await db.query('SELECT * FROM compliance_logs WHERE id = ?', [logId]);
        const log = rows[0];
        if (!log) return res.status(404).json({ message: 'Log not found' });

        if (req.user.id !== log.user_id && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized to delete this log' });
        }

        await db.query('DELETE FROM compliance_logs WHERE id = ?', [logId]);
        await logAction(req.user.id, `DELETE_COMPLIANCE_LOG_ID_${logId}`, req.ip);
        res.json({ message: 'Compliance log deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Export logs (CSV)
router.get('/compliance/export/csv', verifyToken, async (req, res) => {
    try {
        const [logs] = await db.query(`
            SELECT compliance_logs.id, users.username, compliance_logs.regulation,
                   compliance_logs.status, compliance_logs.notes, compliance_logs.created_at
            FROM compliance_logs
            JOIN users ON compliance_logs.user_id = users.id
        `);

        const parser = new Parser();
        const csv = parser.parse(logs);
        res.header('Content-Type', 'text/csv');
        res.attachment('compliance_logs.csv');
        return res.send(csv);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Export logs (PDF)
router.get('/compliance/export/pdf', verifyToken, async (req, res) => {
    try {
        const [logs] = await db.query(`
            SELECT compliance_logs.id, users.username, compliance_logs.regulation,
                   compliance_logs.status, compliance_logs.notes, compliance_logs.created_at
            FROM compliance_logs
            JOIN users ON compliance_logs.user_id = users.id
        `);

        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=compliance_logs.pdf');
        doc.pipe(res);

        doc.fontSize(16).text('Compliance Logs Report', { align: 'center' });
        doc.moveDown();

        logs.forEach(log => {
            doc
                .fontSize(12)
                .text(`ID: ${log.id}, User: ${log.username}, Regulation: ${log.regulation}, Status: ${log.status}`)
                .text(`Notes: ${log.notes || 'None'}`)
                .text(`Date: ${new Date(log.created_at).toLocaleString()}`)
                .moveDown();
        });

        doc.end();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
