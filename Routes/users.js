// Routes/users.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const verifyToken = require('../Middleware/token');
const requireRole = require('../Middleware/role');
const db = require('../Models/database');
const logAction = require('../Services/auditlog');

// Admin-Only: Create a user
router.post('/', verifyToken, requireRole('admin'), async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, and role are required' });
    }

    try {
        const [existing] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length) return res.status(400).json({ message: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role]);

        const [created] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
        await logAction(req.user.id, `CREATE_USER_ID_${created[0].id}`, req.ip);

        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin-Only: Delete a user
router.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    const userId = req.params.id;

    try {
        const [existing] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        if (!existing.length) return res.status(404).json({ message: 'User not found' });

        await db.query('DELETE FROM users WHERE id = ?', [userId]);
        await logAction(req.user.id, `DELETE_USER_ID_${userId}`, req.ip);

        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin-Only: Update user role
router.put('/:id/role', verifyToken, requireRole('admin'), async (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;

    if (!role) return res.status(400).json({ message: 'Role is required' });

    try {
        await db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
        await logAction(req.user.id, `UPDATE_ROLE_USER_ID_${userId}_TO_${role.toUpperCase()}`, req.ip);

        res.json({ message: 'User role updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin-Only: Get all users
router.get('/', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const [users] = await db.query('SELECT id, username, role FROM users ORDER BY id ASC');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
