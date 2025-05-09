const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const loginController = require('../Controllers/login');

// POST register
router.post(
    '/register',
    [
        body('password').isStrongPassword().withMessage('Password must be complexity requirements (uppercase, lowercase, number, symbol)')
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        loginController.register(req, res);
    }
);

// POST login
router.post(
    '/login',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        loginController.login(req, res);
    }
);

module.exports = router;
