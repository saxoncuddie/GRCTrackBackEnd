// login logic
const db = require('../Models/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const logAction = require('../Services/auditlog');

exports.register = async (req, res) => {
    const { username, password } = req.body;
    try { //hash pashword 
        const [existing] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length) return res.status(400).json({ message: 'Username already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.login = async (req, res) => {
    const { username, password } = req.body;
    try { //find user
        const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (!users.length) return res.status(400).json({ message: 'Invalid credentials' });

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'Incorrect password' });

        const token = jwt.sign(
            { id: user.id, role: user.role, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // log event
        const ip = req.ip || req.headers['x-forwarded-for'];
        await logAction(user.id, 'LOGIN', ip);

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};