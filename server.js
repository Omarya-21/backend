require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

/* ------------------ CORS ------------------ */
const allowedOrigins = [
  'http://localhost:3000',
  'https://omaryamminepro.netlify.app' // 🔴 CHANGE THIS
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.use(express.json());

/* ------------------ DATABASE ------------------ */
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10
});

/* ------------------ TEST ROUTE ------------------ */
app.get('/', (req, res) => {
  res.json({ message: 'Backend running' });
});

/* ------------------ REGISTER ------------------ */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const connection = await pool.getConnection();

    try {
      // check if user exists
      const [existing] = await connection.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );

      if (existing.length > 0) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // 👇 IMPORTANT FIX
      const [result] = await connection.query(
        'INSERT INTO users (id, username, password) VALUES (NULL, ?, ?)',
        [username, hashedPassword]
      );

      const token = jwt.sign(
        { userId: result.insertId, username },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        token,
        user: { id: result.insertId, username }
      });

    } finally {
      connection.release();
    }

  } catch (err) {
    console.error('REGISTER ERROR:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/* ------------------ LOGIN ------------------ */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username }
    });

  } catch (err) {
    console.error('LOGIN ERROR:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------ START ------------------ */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
