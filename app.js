const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();
const mysql = require('mysql2');

const app = express();

app.use(helmet());
app.use(cors({
    origin: 'grctrackfrontend-a0g0csghatcehffq.centralus-01.azurewebsites.net', 
    credentials: true
}));
app.use(express.json());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});
app.use(limiter);


db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to MySQL database.');
    }
});


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
