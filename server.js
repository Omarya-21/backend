import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

/* ---------- MIDDLEWARE ---------- */
app.use(express.json());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://YOUR-SITE.netlify.app' // CHANGE THIS
  ]
}));

/* ---------- DATABASE ---------- */
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE
});

db.connect(err => {
  if (err) {
    console.error('❌ MySQL error:', err);
  } else {
    console.log('✅ MySQL connected');
  }
});

/* ---------- HEALTH CHECK ---------- */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* ---------- REGISTER ---------- */
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Missing fields' });

  db.query(
    'SELECT id FROM users WHERE username = ?',
    [username],
    async (err, result) => {
      if (result.length > 0)
        return res.status(400).json({ error: 'User already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword],
        (err) => {
          if (err) return res.status(500).json({ error: 'Database error' });

          const token = jwt.sign(
            { username },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
          );

          res.json({
            token,
            user: { username }
          });
        }
      );
    }
  );
});

/* ---------- LOGIN ---------- */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, result) => {
      if (result.length === 0)
        return res.status(401).json({ error: 'Invalid credentials' });

      const user = result[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match)
        return res.status(401).json({ error: 'Invalid credentials' });

      const token = jwt.sign(
        { username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );

      res.json({
        token,
        user: { username: user.username }
      });
    }
  );
});

/* ---------- AUTH CHECK ---------- */
app.get('/api/check-auth', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.json({ isLoggedIn: false });

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({
      isLoggedIn: true,
      user: { username: decoded.username }
    });
  } catch {
    res.json({ isLoggedIn: false });
  }
});

/* ---------- START SERVER ---------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
