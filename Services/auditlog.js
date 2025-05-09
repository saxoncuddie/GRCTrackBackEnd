//audit log
const db = require('../Models/database');

async function logAction(user_id, action, ip = null) {
    try {
        await db.query(
            'INSERT INTO audit_logs (user_id, action, ip_address) VALUES (?, ?, ?)',
            [user_id, action, ip]
        );
    } catch (err) {
        console.error('Failed to log action:', err.message);
    }
}

module.exports = logAction;