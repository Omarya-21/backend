const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Enhanced CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
  'https://*.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, postman)
    if (!origin) return callback(null, true);
    
    // Check if the origin is in allowed origins
    if (allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp(allowedOrigin.replace('*.', '.*\.'));
        return regex.test(origin);
      }
      return allowedOrigin === origin;
    })) {
      return callback(null, true);
    }
    
    console.log('CORS blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Authorization']
}));

// Handle preflight requests
app.options('*', cors());

// Body parser with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('Origin:', req.headers.origin || 'No origin');
  console.log('Body:', req.body);
  next();
});

// Railway MySQL connection with SSL for production
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || 'localhost',
  port: process.env.MYSQLPORT || 3306,
  user: process.env.MYSQLUSER || 'root',
  password: process.env.MYSQLPASSWORD || '',
  database: process.env.MYSQLDATABASE || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  connectTimeout: 10000,
  acquireTimeout: 10000
});

// Test database connection
const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connected to MySQL database');
    console.log(`📊 Database: ${process.env.MYSQLDATABASE || 'railway'}`);
    console.log(`🏷️ Host: ${process.env.MYSQLHOST || 'localhost'}`);
    connection.release();
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
};

// Initialize database
const initDB = async () => {
  try {
    const conn = await pool.getConnection();
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    conn.release();
    console.log('✅ Database table ready');
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
  }
};

// Initialize database on startup
(async () => {
  await testConnection();
  await initDB();
})();

// ============= ROUTES =============

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'PC Parts API - Railway Backend',
    status: 'online',
    endpoints: [
      '/api/test',
      '/api/health',
      '/api/register',
      '/api/login',
      '/api/check-auth'
    ]
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend is working!',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query('SELECT 1 as status');
    conn.release();
    
    res.json({ 
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ 
      status: 'unhealthy',
      database: 'disconnected',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt received');
    
    const { username, password } = req.body;
    
    // Validation
    if (!username || !password) {
      console.log('❌ Missing fields');
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ 
        error: 'Username must be at least 3 characters long' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long' 
      });
    }
    
    // Check if user already exists
    const conn = await pool.getConnection();
    
    try {
      // Check for existing user
      const [existingUsers] = await conn.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );
      
      if (existingUsers.length > 0) {
        return res.status(400).json({ 
          error: 'Username already exists' 
        });
      }
      
      // Hash password and create user
      const hashedPassword = await bcrypt.hash(password, 12);
      
      const [result] = await conn.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword]
      );
      
      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: result.insertId, 
          username: username 
        },
        process.env.JWT_SECRET || 'fallback-secret-key-change-in-production',
        { expiresIn: '7d' }
      );
      
      console.log(`✅ User registered: ${username} (ID: ${result.insertId})`);
      
      res.status(201).json({ 
        success: true, 
        message: 'Registration successful',
        token: token,
        user: { 
          id: result.insertId, 
          username: username 
        }
      });
      
    } finally {
      conn.release();
    }
    
  } catch (error) {
    console.error('❌ Registration error:', error);
    
    // Handle specific MySQL errors
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Username already exists' 
      });
    }
    
    if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      return res.status(500).json({ 
        error: 'Database access denied' 
      });
    }
    
    if (error.code === 'ECONNREFUSED') {
      return res.status(500).json({ 
        error: 'Database connection refused' 
      });
    }
    
    // Generic error
    res.status(500).json({ 
      error: 'Registration failed. Please try again later.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔑 Login attempt received');
    
    const { username, password } = req.body;
    
    // Validation
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }
    
    const conn = await pool.getConnection();
    
    try {
      // Find user
      const [users] = await conn.query(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );
      
      if (users.length === 0) {
        return res.status(401).json({ 
          error: 'Invalid username or password' 
        });
      }
      
      const user = users[0];
      
      // Verify password
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        return res.status(401).json({ 
          error: 'Invalid username or password' 
        });
      }
      
      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: user.id, 
          username: user.username 
        },
        process.env.JWT_SECRET || 'fallback-secret-key-change-in-production',
        { expiresIn: '7d' }
      );
      
      console.log(`✅ User logged in: ${username} (ID: ${user.id})`);
      
      res.json({ 
        success: true, 
        message: 'Login successful',
        token: token,
        user: { 
          id: user.id, 
          username: user.username 
        }
      });
      
    } finally {
      conn.release();
    }
    
  } catch (error) {
    console.error('❌ Login error:', error);
    
    res.status(500).json({ 
      error: 'Login failed. Please try again later.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Check authentication endpoint
app.get('/api/check-auth', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ 
        isLoggedIn: false,
        message: 'No token provided'
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Verify token
    const decoded = jwt.verify(
      token, 
      process.env.JWT_SECRET || 'fallback-secret-key-change-in-production'
    );
    
    // Optional: Check if user still exists in database
    const conn = await pool.getConnection();
    const [users] = await conn.query(
      'SELECT id, username FROM users WHERE id = ?',
      [decoded.userId]
    );
    conn.release();
    
    if (users.length === 0) {
      return res.json({ 
        isLoggedIn: false,
        message: 'User no longer exists'
      });
    }
    
    res.json({ 
      isLoggedIn: true,
      user: {
        id: decoded.userId,
        username: decoded.username
      }
    });
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.json({ 
        isLoggedIn: false,
        message: 'Invalid or expired token'
      });
    }
    
    console.error('❌ Check auth error:', error);
    res.json({ 
      isLoggedIn: false,
      message: 'Authentication check failed'
    });
  }
});

// Database info endpoint (for debugging)
app.get('/api/db-info', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [users] = await conn.query('SELECT COUNT(*) as count FROM users');
    const [tables] = await conn.query('SHOW TABLES');
    conn.release();
    
    res.json({
      userCount: users[0].count,
      tables: tables.map(t => Object.values(t)[0]),
      database: process.env.MYSQLDATABASE,
      host: process.env.MYSQLHOST
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.url,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled error:', err);
  
  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      error: 'CORS error',
      message: 'Request blocked by CORS policy',
      origin: req.headers.origin,
      allowedOrigins: allowedOrigins
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      error: 'Invalid token' 
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ 
      error: 'Token expired' 
    });
  }
  
  // Default error
  res.status(err.status || 500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    timestamp: new Date().toISOString()
  });
});

// Start server
const PORT = process.env.PORT || 10000;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log('='.repeat(50));
  console.log(`🚀 Server started successfully!`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🏠 Host: ${HOST}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️ Database: ${process.env.MYSQLDATABASE || 'railway'}`);
  console.log(`🔗 CORS Origins: ${allowedOrigins.join(', ')}`);
  console.log('='.repeat(50));
  console.log(`✅ API is ready at http://${HOST}:${PORT}`);
  console.log(`✅ Health check: http://${HOST}:${PORT}/api/health`);
  console.log('='.repeat(50));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  pool.end();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  pool.end();
  process.exit(0);
});