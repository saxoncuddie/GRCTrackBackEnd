const express = require('express');
const router = express.Router();
const verifyToken = require('../Middleware/token');
const db = require('../Models/database');

// Create event
router.post('/', verifyToken, async (req, res) => {
    const { title, description, scheduled_date } = req.body;
    if (!title || !scheduled_date) {
        return res.status(400).json({ message: 'Title and scheduled date are required' });
    }

    try {
        await db.query(
            'INSERT INTO audit_events (title, description, scheduled_date, created_by) VALUES (?, ?, ?, ?)',
            [title, description, scheduled_date, req.user.id]
        );
        res.status(201).json({ message: 'Event scheduled' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all events
router.get('/', verifyToken, async (req, res) => {
    try {
        const [events] = await db.query(
            'SELECT id, title, description, scheduled_date, status, notes, created_by FROM audit_events ORDER BY scheduled_date DESC'
        );
        res.json(events);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update event
router.put('/:id', verifyToken, async (req, res) => {
    const { title, description, scheduled_date } = req.body;
    const eventId = req.params.id;

    try {
        const [[event]] = await db.query('SELECT * FROM audit_events WHERE id = ?', [eventId]);
        if (!event) return res.status(404).json({ message: 'Event not found' });

        if (req.user.id !== event.created_by && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to update this event' });
        }

        await db.query(
            'UPDATE audit_events SET title = ?, description = ?, scheduled_date = ? WHERE id = ?',
            [title, description, scheduled_date, eventId]
        );
        res.json({ message: 'Event updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete event
router.delete('/:id', verifyToken, async (req, res) => {
    const eventId = req.params.id;

    try {
        const [[event]] = await db.query('SELECT * FROM audit_events WHERE id = ?', [eventId]);
        if (!event) return res.status(404).json({ message: 'Event not found' });

        if (req.user.id !== event.created_by && req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to delete this event' });
        }

        await db.query('DELETE FROM audit_events WHERE id = ?', [eventId]);
        res.json({ message: 'Event deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
