const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ================= CONFIG =================

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',           // React dev
  'https://your-netlify-site.netlify.app' // Netlify frontend
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================= DATABASE =================

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

// Initialize database and create table if missing
const initializeDatabase = async () => {
  try {
    const connection = await pool.getConnection();
    
    // Ensure users table exists
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    
    console.log('✅ Database connected and users table ready');
    connection.release();
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1); // Stop server if DB fails
  }
};

// ================= HELPERS =================

const validateUsername = (username) => {
  if (!username || username.trim().length < 3) return 'Username must be at least 3 characters';
  if (username.length > 50) return 'Username must be less than 50 characters';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'Username can only contain letters, numbers, and underscores';
  return null;
};

const validatePassword = (password) => {
  if (!password || password.length < 6) return 'Password must be at least 6 characters';
  if (password.length > 100) return 'Password is too long';
  return null;
};

// ================= ROUTES =================

// Root
app.get('/', (req, res) => {
  res.json({ success: true, message: 'Backend running', timestamp: new Date().toISOString() });
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate
    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ success: false, error: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ success: false, error: passwordError });

    const connection = await pool.getConnection();

    try {
      // Check existing username
      const [existing] = await connection.query('SELECT id FROM users WHERE username = ?', [username.trim()]);
      if (existing.length > 0) return res.status(400).json({ success: false, error: 'Username already taken' });

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Insert user
      const [result] = await connection.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username.trim(), hashedPassword]
      );

      // JWT token
      const token = jwt.sign(
        { userId: result.insertId, username: username.trim() },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        success: true,
        message: 'Registration successful',
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
      if (users.length === 0) return res.status(401).json({ success: false, error: 'Invalid username or password' });

      const user = users[0];
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(401).json({ success: false, error: 'Invalid username or password' });

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
app.get('/api/check-auth', (req, res) => {
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

// Start server
const startServer = async () => {
  await initializeDatabase();
  const PORT = process.env.PORT || 10000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
};

startServer();
