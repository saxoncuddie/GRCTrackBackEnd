router.post('/compliance', verifyToken, async (req, res) => {
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
});

router.put('/compliance/:id', verifyToken, async (req, res) => {
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
        res.json({ message: 'Compliance log updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.delete('/compliance/:id', verifyToken, async (req, res) => {
    const logId = req.params.id;

    try {
        // check role
        const [rows] = await db.query('SELECT * FROM compliance_logs WHERE id = ?', [logId]);
        const log = rows[0];
        if (!log) return res.status(404).json({ message: 'Log not found' });

        if (req.user.id !== log.user_id && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized to delete this log' });
        }

        await db.query('DELETE FROM compliance_logs WHERE id = ?', [logId]);
        res.json({ message: 'Compliance log deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
