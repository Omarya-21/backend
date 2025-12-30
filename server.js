const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ============= CONFIGURATION =============

// CORS Configuration - Allow all for now, tighten in production
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
}));

// Handle preflight requests
app.options('*', cors());

// Body parser with larger limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  console.log('  Origin:', req.headers.origin || 'No origin');
  console.log('  Content-Type:', req.headers['content-type']);
  console.log('  Body:', req.body);
  next();
});

// ============= DATABASE CONNECTION =============

console.log('🔧 Initializing MySQL connection...');
console.log('  Host:', process.env.MYSQLHOST || 'localhost');
console.log('  Port:', process.env.MYSQLPORT || '3306');
console.log('  Database:', process.env.MYSQLDATABASE || 'railway');

const pool = mysql.createPool({
  host: process.env.MYSQLHOST || 'localhost',
  port: process.env.MYSQLPORT || 3306,
  user: process.env.MYSQLUSER || 'root',
  password: process.env.MYSQLPASSWORD || '',
  database: process.env.MYSQLDATABASE || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : undefined,
  connectTimeout: 30000,
  acquireTimeout: 30000,
  charset: 'utf8mb4'
});

// Test database connection on startup
const initializeDatabase = async () => {
  try {
    console.log('🔄 Testing database connection...');
    const connection = await pool.getConnection();
    
    // Test connection
    const [rows] = await connection.query('SELECT 1 + 1 AS result');
    console.log('✅ Database connection test successful:', rows[0].result);
    
    // Check if database exists
    const [databases] = await connection.query('SHOW DATABASES LIKE ?', [process.env.MYSQLDATABASE || 'railway']);
    if (databases.length === 0) {
      console.log('⚠️ Database does not exist. Creating...');
      await connection.query(`CREATE DATABASE IF NOT EXISTS ${process.env.MYSQLDATABASE || 'railway'}`);
      console.log('✅ Database created');
    }
    
    // Use the database
    await connection.query(`USE ${process.env.MYSQLDATABASE || 'railway'}`);
    
    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    
    console.log('✅ Users table ready');
    
    // Count existing users
    const [userCount] = await connection.query('SELECT COUNT(*) as count FROM users');
    console.log(`📊 Total users in database: ${userCount[0].count}`);
    
    connection.release();
    console.log('✅ Database initialization complete');
    
    return true;
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    console.error('Error code:', error.code);
    console.error('Error SQL:', error.sql);
    
    // Try to create database if it doesn't exist
    if (error.code === 'ER_BAD_DB_ERROR') {
      console.log('🔄 Attempting to create database...');
      try {
        const tempConnection = await mysql.createConnection({
          host: process.env.MYSQLHOST || 'localhost',
          port: process.env.MYSQLPORT || 3306,
          user: process.env.MYSQLUSER || 'root',
          password: process.env.MYSQLPASSWORD || '',
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
        });
        
        await tempConnection.query(`CREATE DATABASE IF NOT EXISTS ${process.env.MYSQLDATABASE || 'railway'}`);
        console.log('✅ Database created');
        await tempConnection.end();
        
        return true;
      } catch (createError) {
        console.error('❌ Failed to create database:', createError.message);
        return false;
      }
    }
    
    return false;
  }
};

// ============= HELPER FUNCTIONS =============

const validateUsername = (username) => {
  if (!username || username.trim().length < 3) {
    return 'Username must be at least 3 characters long';
  }
  if (username.length > 50) {
    return 'Username must be less than 50 characters';
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return 'Username can only contain letters, numbers, and underscores';
  }
  return null;
};

const validatePassword = (password) => {
  if (!password || password.length < 6) {
    return 'Password must be at least 6 characters long';
  }
  if (password.length > 100) {
    return 'Password is too long';
  }
  return null;
};

// ============= ROUTES =============

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'PC Parts API Backend',
    version: '1.0.0',
    status: 'online',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/api/health',
      test: '/api/test',
      dbTest: '/api/test-db',
      register: '/api/register',
      login: '/api/login',
      checkAuth: '/api/check-auth',
      debug: '/api/debug-register'
    }
  });
});

// Simple test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Server is working! 🚀',
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [dbResult] = await connection.query('SELECT 1 as healthy');
    connection.release();
    
    res.json({
      success: true,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected',
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    });
  }
});

// Database test endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get database info
    const [dbInfo] = await connection.query('SELECT DATABASE() as db, USER() as user, VERSION() as version');
    
    // Get table info
    const [tables] = await connection.query('SHOW TABLES');
    const tableNames = tables.map(table => Object.values(table)[0]);
    
    // Get user count
    const [userCount] = await connection.query('SELECT COUNT(*) as count FROM users');
    
    connection.release();
    
    res.json({
      success: true,
      database: {
        name: dbInfo[0].db,
        user: dbInfo[0].user,
        version: dbInfo[0].version,
        tables: tableNames,
        userCount: userCount[0].count
      },
      connection: {
        host: process.env.MYSQLHOST || 'localhost',
        port: process.env.MYSQLPORT || 3306
      }
    });
    
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      code: error.code,
      sqlMessage: error.sqlMessage,
      tip: 'Check your MySQL connection settings in Railway variables'
    });
  }
});

// Debug registration endpoint
app.post('/api/debug-register', async (req, res) => {
  console.log('=== DEBUG REGISTRATION STARTED ===');
  
  try {
    const { username, password } = req.body;
    
    console.log('1. Request received:', { username, password: password ? '***' : 'missing' });
    
    // Validate input
    if (!username || !password) {
      console.log('2. Validation failed: Missing fields');
      return res.status(400).json({
        success: false,
        error: 'Username and password are required'
      });
    }
    
    console.log('3. Connecting to database...');
    const connection = await pool.getConnection();
    
    try {
      console.log('4. Checking if user exists...');
      const [existingUsers] = await connection.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );
      
      if (existingUsers.length > 0) {
        console.log('5. User already exists');
        return res.status(400).json({
          success: false,
          error: 'Username already exists'
        });
      }
      
      console.log('6. Hashing password...');
      const hashedPassword = await bcrypt.hash(password, 12);
      
      console.log('7. Inserting user...');
      const [result] = await connection.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword]
      );
      
      console.log('8. Generating token...');
      const token = jwt.sign(
        {
          userId: result.insertId,
          username: username
        },
        process.env.JWT_SECRET || 'fallback-secret-change-this',
        { expiresIn: '7d' }
      );
      
      console.log('9. Registration successful!');
      console.log(`   User ID: ${result.insertId}`);
      console.log(`   Username: ${username}`);
      
      res.json({
        success: true,
        message: 'Registration successful (debug mode)',
        token: token,
        user: {
          id: result.insertId,
          username: username
        },
        debug: {
          stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9],
          insertId: result.insertId
        }
      });
      
    } finally {
      connection.release();
      console.log('10. Database connection released');
    }
    
  } catch (error) {
    console.error('❌ DEBUG ERROR:', error);
    console.error('Error code:', error.code);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    res.status(500).json({
      success: false,
      error: 'Debug registration failed',
      details: error.message,
      code: error.code,
      step: 'Check server logs for details'
    });
  }
  
  console.log('=== DEBUG REGISTRATION ENDED ===');
});

// Main registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt started');
    
    const { username, password } = req.body;
    
    // Validate input
    const usernameError = validateUsername(username);
    if (usernameError) {
      console.log('❌ Username validation failed:', usernameError);
      return res.status(400).json({
        success: false,
        error: usernameError
      });
    }
    
    const passwordError = validatePassword(password);
    if (passwordError) {
      console.log('❌ Password validation failed:', passwordError);
      return res.status(400).json({
        success: false,
        error: passwordError
      });
    }
    
    console.log(`🔍 Attempting to register user: ${username}`);
    
    const connection = await pool.getConnection();
    
    try {
      // Check if username exists
      const [existingUsers] = await connection.query(
        'SELECT id FROM users WHERE username = ?',
        [username.trim()]
      );
      
      if (existingUsers.length > 0) {
        console.log('❌ Username already taken:', username);
        return res.status(400).json({
          success: false,
          error: 'Username is already taken. Please choose another.'
        });
      }
      
      // Hash password
      console.log('🔒 Hashing password...');
      const hashedPassword = await bcrypt.hash(password, 12);
      
      // Insert user
      console.log('💾 Saving user to database...');
      const [result] = await connection.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username.trim(), hashedPassword]
      );
      
      // Generate JWT token
      console.log('🎫 Generating authentication token...');
      const token = jwt.sign(
        {
          userId: result.insertId,
          username: username.trim()
        },
        process.env.JWT_SECRET || 'fallback-secret-key-change-in-production',
        { expiresIn: '7d' }
      );
      
      console.log(`✅ User registered successfully! ID: ${result.insertId}, Username: ${username}`);
      
      res.status(201).json({
        success: true,
        message: 'Registration successful!',
        token: token,
        user: {
          id: result.insertId,
          username: username.trim()
        }
      });
      
    } finally {
      connection.release();
    }
    
  } catch (error) {
    console.error('🔥 Registration error:', error);
    
    // Handle specific MySQL errors
    let errorMessage = 'Registration failed. Please try again.';
    let statusCode = 500;
    
    if (error.code === 'ER_DUP_ENTRY') {
      errorMessage = 'Username is already taken.';
      statusCode = 400;
    } else if (error.code === 'ER_NO_SUCH_TABLE') {
      errorMessage = 'Database table not found. Please contact administrator.';
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      errorMessage = 'Database access denied.';
    } else if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      errorMessage = 'Database connection failed. Please try again later.';
    }
    
    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required'
      });
    }
    
    const connection = await pool.getConnection();
    
    try {
      // Find user
      const [users] = await connection.query(
        'SELECT id, username, password FROM users WHERE username = ?',
        [username.trim()]
      );
      
      if (users.length === 0) {
        return res.status(401).json({
          success: false,
          error: 'Invalid username or password'
        });
      }
      
      const user = users[0];
      
      // Verify password
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        return res.status(401).json({
          success: false,
          error: 'Invalid username or password'
        });
      }
      
      // Generate token
      const token = jwt.sign(
        {
          userId: user.id,
          username: user.username
        },
        process.env.JWT_SECRET || 'fallback-secret-key-change-in-production',
        { expiresIn: '7d' }
      );
      
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
      connection.release();
    }
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.'
    });
  }
});

// Check authentication endpoint
app.get('/api/check-auth', (req, res) => {
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
    
    console.error('Auth check error:', error);
    res.json({
      isLoggedIn: false,
      message: 'Authentication check failed'
    });
  }
});

// Get all users (for debugging - remove in production)
app.get('/api/users', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT id, username, created_at FROM users ORDER BY created_at DESC'
    );
    connection.release();
    
    res.json({
      success: true,
      count: users.length,
      users: users
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    availableEndpoints: [
      'GET /',
      'GET /api/test',
      'GET /api/health',
      'GET /api/test-db',
      'POST /api/register',
      'POST /api/login',
      'GET /api/check-auth',
      'POST /api/debug-register'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔥 Global error handler:', err);
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============= START SERVER =============

const startServer = async () => {
  console.log('🚀 Starting server initialization...');
  
  // Initialize database
  const dbInitialized = await initializeDatabase();
  
  if (!dbInitialized) {
    console.error('❌ Failed to initialize database. Server may not work correctly.');
    console.log('💡 Tip: Check Railway MySQL connection variables');
  }
  
  const PORT = process.env.PORT || 10000;
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(60));
    console.log('✅ SERVER STARTED SUCCESSFULLY');
    console.log('='.repeat(60));
    console.log(`🌐 Server URL: http://localhost:${PORT}`);
    console.log(`📡 External URL: https://your-railway-app.up.railway.app`);
    console.log(`⚙️  Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  Database: ${dbInitialized ? 'Connected ✅' : 'Failed ❌'}`);
    console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set ✅' : 'Using fallback ⚠️'}`);
    console.log('='.repeat(60));
    console.log('📋 Available Endpoints:');
    console.log(`   • GET  /              - Server info`);
    console.log(`   • GET  /api/test      - Basic test`);
    console.log(`   • GET  /api/health    - Health check`);
    console.log(`   • GET  /api/test-db   - Database test`);
    console.log(`   • POST /api/register  - Register user`);
    console.log(`   • POST /api/login     - Login user`);
    console.log(`   • POST /api/debug-register - Debug registration`);
    console.log('='.repeat(60));
  });
};

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start the server
startServer();