// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ---------------- CORS CONFIGURATION ----------------
const allowedOrigins = [
  'http://localhost:3000',                    // React dev server
  'https://omaryamminepro.netlify.app'     // Replace with your Netlify URL
];

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.options('*', cors({ origin: allowedOrigins, credentials: true }));

// ---------------- BODY PARSERS ----------------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ---------------- DATABASE CONNECTION ----------------
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
});

// Test database connection and create users table if not exists
const initializeDatabase = async () => {
  try {
    const connection = await pool.getConnection();
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    connection.release();
    console.log('✅ Database ready');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
  }
};

// ---------------- HELPERS ----------------
const validateUsername = (username) => {
  if (!username || username.trim().length < 3) return 'Username must be at least 3 characters';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'Username can only contain letters, numbers, and underscores';
  return null;
};

const validatePassword = (password) => {
  if (!password || password.length < 6) return 'Password must be at least 6 characters';
  return null;
};

// ---------------- ROUTES ----------------

// Test endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Backend is running' });
});

// Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ success: false, error: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ success: false, error: passwordError });

    const connection = await pool.getConnection();

    try {
      // Check if username exists
      const [existingUsers] = await connection.query('SELECT id FROM users WHERE username = ?', [username.trim()]);
      if (existingUsers.length > 0) return res.status(400).json({ success: false, error: 'Username already taken' });

      // Hash password and insert user
      const hashedPassword = await bcrypt.hash(password, 12);
      const [result] = await connection.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username.trim(), hashedPassword]
      );

      // Generate JWT
      const token = jwt.sign(
        { userId: result.insertId, username: username.trim() },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        success: true,
        message: 'Registration successful!',
        token,
        user: { id: result.insertId, username: username.trim() }
      });

    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Username and password required' });

    const connection = await pool.getConnection();
    try {
      const [users] = await connection.query('SELECT id, username, password FROM users WHERE username = ?', [username.trim()]);
      if (users.length === 0) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      const user = users[0];
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });

      res.json({ success: true, message: 'Login successful', token, user: { id: user.id, username: user.username } });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

// Check auth
app.get('/api/check-auth', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.json({ isLoggedIn: false });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    res.json({ isLoggedIn: true, user: { id: decoded.userId, username: decoded.username } });
  } catch (error) {
    res.json({ isLoggedIn: false });
  }
});

// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 10000;

initializeDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
});
