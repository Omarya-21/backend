const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

/* ===== CORS (PRODUCTION SAFE) ===== */
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://omaryamminepro.netlify.app'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

/* ===== DATABASE ===== */
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  ssl: { rejectUnauthorized: false }
});

/* ===== HELPERS ===== */
const validatePassword = (password) => {
  if (!password || password.length < 6) {
    return 'Password must be at least 6 characters long';
  }
  return null;
};

/* ===== REGISTER ===== */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const conn = await pool.getConnection();

    const [existing] = await conn.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      conn.release();
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hash = await bcrypt.hash(password, 12);

    const [result] = await conn.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hash]
    );

    conn.release();

    const token = jwt.sign(
      { userId: result.insertId, username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: { id: result.insertId, username }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/* ===== START ===== */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
