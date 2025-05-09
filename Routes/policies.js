const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const verifyToken = require('../Middleware/token');
const requireRole = require('../Middleware/role');
const db = require('../Models/database');
const logAction = require('../Services/auditlog');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = './uploads/policies';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const timestamp = Date.now();
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        cb(null, `${timestamp}_${safeName}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB upload cap, small for actual policies this is just for demonstration
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.pdf', '.docx', '.txt'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) cb(null, true);
        else cb(new Error('Only PDF, DOCX, and TXT files are allowed'));
    }
});

router.post('/upload', verifyToken, requireRole('admin'), upload.single('file'), async (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'File upload failed' });

    try {
        await db.query(
            'INSERT INTO policy_library (filename, originalname, uploaded_by, uploaded_at) VALUES (?, ?, ?, NOW())',
            [file.filename, file.originalname, req.user.id]
        );
        await logAction(req.user.id, `UPLOAD_POLICY_${file.originalname}`, req.ip);
        res.status(201).json({ message: 'File uploaded successfully' });
    } catch (err) {
        console.error('DB insert failed:', err);
        res.status(500).json({ error: err.message });
    }
});

router.get('/', verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT id, originalname, filename, uploaded_at FROM policy_library ORDER BY uploaded_at DESC'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.get('/download/:filename', verifyToken, async (req, res) => {
    const filePath = path.join(__dirname, '../uploads/policies', req.params.filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ message: 'File not found' });
    res.download(filePath);
});

router.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    const policyId = req.params.id;

    try {
        const [[policy]] = await db.query('SELECT * FROM policy_library WHERE id = ?', [policyId]);
        if (!policy) return res.status(404).json({ message: 'Policy not found' });

        const filePath = path.join(__dirname, '../uploads/policies', policy.filename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

        await db.query('DELETE FROM policy_library WHERE id = ?', [policyId]);
        await logAction(req.user.id, `DELETE_POLICY_${policy.filename}`, req.ip);

        res.json({ message: 'Policy deleted successfully' });
    } catch (err) {
        console.error('Delete failed:', err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
