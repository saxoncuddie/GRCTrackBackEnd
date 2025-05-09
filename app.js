// app.js (Backend Entry Point)
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minute rate limit
    max: 100,
});
app.use(limiter);

app.use('/api/auth', require('./Routes/auth'));
app.use('/api/logs', require('./Routes/logs'));
app.use('/api/users', require('./Routes/users'));
app.use('/api/grcevents', require('./Routes/GRCEvents'));
app.use('/api/policies', require('./Routes/policies'));

app.get('/', (req, res) => {
    res.send('GRCTrack Backend is running');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});
