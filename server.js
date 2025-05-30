// server.js - Complete Express Server for User Registration & Admin Approval System
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files (if needed)
app.use(express.static(path.join(__dirname, 'public')));

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'ai_system',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true
};

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// JWT Secret with fallback
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production_2024';

// Database connection pool
let db;

async function initializeDatabase() {
  try {
    // First, create connection without specifying database to create it
    const tempConfig = { ...dbConfig };
    delete tempConfig.database;
    
    let tempConnection;
    try {
      tempConnection = await mysql.createConnection(tempConfig);
      
      // Create database using regular query (not prepared statement)
      await tempConnection.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
      console.log(`✅ Database '${dbConfig.database}' created/verified`);
      
    } catch (dbError) {
      console.log('ℹ️  Database might already exist or creation failed:', dbError.message);
    } finally {
      if (tempConnection) {
        await tempConnection.end();
      }
    }
    
    // Now create connection pool with the database
    db = mysql.createPool(dbConfig);
    
    // Test connection
    const connection = await db.getConnection();
    console.log('✅ Connected to MySQL database');
    connection.release();
    
    // Create tables
    await createTables();
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    
    // If it's a connection error, provide helpful info
    if (error.code === 'ECONNREFUSED') {
      console.error('💡 Make sure MySQL is running on your system');
      console.error('💡 Check if your MySQL credentials in .env are correct');
    }
    
    process.exit(1);
  }
}

// Create tables (separated from database creation)
async function createTables() {
  try {
    // Create users table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        organization VARCHAR(255),
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        auth_key VARCHAR(255) UNIQUE,
        approval_token VARCHAR(255) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_status (status),
        INDEX idx_approval_token (approval_token)
      ) ENGINE=InnoDB
    `);

    // Create admins table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role ENUM('admin', 'super_admin') DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);

    // Insert default admin if not exists
    const adminPassword = await bcrypt.hash('admin123', 10);
    await db.execute(`
      INSERT IGNORE INTO admins (email, password, name, role) VALUES 
      ('admin@company.com', ?, 'System Admin', 'super_admin')
    `, [adminPassword]);

    console.log('✅ Database tables created/verified successfully');
    
  } catch (error) {
    console.error('❌ Error creating database tables:', error.message);
    throw error;
  }
}

// Utility functions
function generateAuthKey() {
  return crypto.randomBytes(32).toString('hex');
}

function generateApprovalToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Email functions
async function sendAdminApprovalEmail(userData, approvalToken) {
  try {
    const approvalUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/admin/approve/${approvalToken}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || 'admin@company.com',
      subject: '🔔 New User Registration - Approval Required',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">New User Registration</h1>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <p style="font-size: 16px; color: #333;">A new user has registered and requires admin approval:</p>
            
            <table style="width: 100%; background: white; border-radius: 8px; padding: 20px; margin: 20px 0;">
              <tr><td style="padding: 8px; font-weight: bold;">Name:</td><td style="padding: 8px;">${userData.first_name} ${userData.last_name}</td></tr>
              <tr><td style="padding: 8px; font-weight: bold;">Email:</td><td style="padding: 8px;">${userData.email}</td></tr>
              <tr><td style="padding: 8px; font-weight: bold;">Phone:</td><td style="padding: 8px;">${userData.phone || 'N/A'}</td></tr>
              <tr><td style="padding: 8px; font-weight: bold;">Organization:</td><td style="padding: 8px;">${userData.organization || 'N/A'}</td></tr>
              <tr><td style="padding: 8px; font-weight: bold;">Registration Date:</td><td style="padding: 8px;">${new Date().toLocaleString()}</td></tr>
            </table>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${approvalUrl}" 
                 style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                ✅ Approve User
              </a>
            </div>
            
            <p style="font-size: 12px; color: #666; text-align: center;">
              Or copy this link: ${approvalUrl}
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ Admin approval email sent successfully');
    
  } catch (error) {
    console.error('❌ Error sending admin approval email:', error.message);
    // Don't throw error, just log it
  }
}

async function sendUserApprovalNotification(userData) {
  try {
    const loginUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userData.email,
      subject: '🎉 Account Approved - Welcome!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Account Approved! 🎉</h1>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <p style="font-size: 18px; color: #333;">Dear ${userData.first_name},</p>
            <p style="font-size: 16px; color: #333;">Great news! Your account has been approved by the admin. You can now access the system.</p>
            
            <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p style="font-weight: bold; color: #333; margin: 0 0 10px 0;">Your Authentication Key:</p>
              <code style="background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; display: block;">${userData.auth_key}</code>
              <p style="font-size: 12px; color: #666; margin: 10px 0 0 0;">Keep this key secure - you'll need it to access your account.</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${loginUrl}" 
                 style="background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                🚀 Login Now
              </a>
            </div>
            
            <p style="font-size: 14px; color: #666; text-align: center;">Welcome aboard! We're excited to have you.</p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ User approval notification sent successfully');
    
  } catch (error) {
    console.error('❌ Error sending user approval notification:', error.message);
    // Don't throw error, just log it
  }
}

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : null;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please login again.'
      });
    }
    
    res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.code === 'ER_DUP_ENTRY') {
    return res.status(400).json({
      success: false,
      message: 'Email already exists'
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  const connection = await db.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { email, password, first_name, last_name, phone, organization } = req.body;

    // Input validation
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({
        success: false,
        message: 'Email, password, first name, and last name are required'
      });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Password strength validation
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if user already exists
    const [existingUser] = await connection.execute(
      'SELECT id FROM users WHERE email = ?',
      [email.toLowerCase()]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate approval token
    const approvalToken = generateApprovalToken();

    // Insert user into database
    const [result] = await connection.execute(
      `INSERT INTO users (email, password, first_name, last_name, phone, organization, approval_token) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email.toLowerCase(), hashedPassword, first_name, last_name, phone, organization, approvalToken]
    );

    await connection.commit();

    // Send admin approval email (async, don't wait)
    const userData = { email, first_name, last_name, phone, organization };
    sendAdminApprovalEmail(userData, approvalToken).catch(console.error);

    res.status(201).json({
      success: true,
      message: 'Registration successful! Admin approval required. You will receive an email once approved.',
      userId: result.insertId
    });

  } catch (error) {
    await connection.rollback();
    console.error('Registration error:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  } finally {
    connection.release();
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user
    const [users] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email.toLowerCase()]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = users[0];

    // Check if user is approved
    if (user.status !== 'approved') {
      let message = 'Your account is pending admin approval';
      if (user.status === 'rejected') {
        message = 'Your account has been rejected. Please contact admin.';
      }
      
      return res.status(403).json({
        success: false,
        message,
        status: user.status
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const tokenPayload = { 
      userId: user.id, 
      email: user.email,
      authKey: user.auth_key 
    };
    
    const token = jwt.sign(tokenPayload, JWT_SECRET, { 
      expiresIn: '24h',
      issuer: 'user-approval-system'
    });

    // Update last login (optional)
    await db.execute(
      'UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    // Return user data (excluding password)
    const userData = {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      organization: user.organization,
      auth_key: user.auth_key,
      status: user.status,
      created_at: user.created_at
    };

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userData
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
});

// Admin approval endpoint
app.get('/api/admin/approve/:token', async (req, res) => {
  const connection = await db.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Approval token is required'
      });
    }

    // Find user by approval token
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE approval_token = ? AND status = ?',
      [token, 'pending']
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired approval token'
      });
    }

    const user = users[0];

    // Generate auth key
    const authKey = generateAuthKey();

    // Update user status and auth key
    await connection.execute(
      'UPDATE users SET status = ?, auth_key = ?, approval_token = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      ['approved', authKey, user.id]
    );

    await connection.commit();

    // Send approval notification to user (async)
    const userData = {
      email: user.email,
      first_name: user.first_name,
      auth_key: authKey
    };
    
    sendUserApprovalNotification(userData).catch(console.error);

    res.json({
      success: true,
      message: 'User approved successfully! Notification email sent.',
      user: {
        id: user.id,
        email: user.email,
        name: `${user.first_name} ${user.last_name}`,
        approved_at: new Date().toISOString()
      }
    });

  } catch (error) {
    await connection.rollback();
    console.error('Approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Approval failed. Please try again.'
    });
  } finally {
    connection.release();
  }
});

// Get pending users (for admin dashboard)
app.get('/api/admin/pending-users', async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT id, email, first_name, last_name, phone, organization, created_at 
      FROM users 
      WHERE status = ? 
      ORDER BY created_at DESC
    `, ['pending']);

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get pending users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending users'
    });
  }
});

// Get user profile (protected route)
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const [users] = await db.execute(
      'SELECT id, email, first_name, last_name, phone, organization, auth_key, status, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: users[0]
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile'
    });
  }
});

// Get all users (admin only - optional)
app.get('/api/admin/users', async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT id, email, first_name, last_name, phone, organization, status, created_at, updated_at 
      FROM users 
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// Reject user (admin functionality)
app.post('/api/admin/reject/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const [result] = await db.execute(
      'UPDATE users SET status = ?, approval_token = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?',
      ['rejected', userId, 'pending']
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found or already processed'
      });
    }

    res.json({
      success: true,
      message: 'User rejected successfully'
    });
  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject user'
    });
  }
});

// Logout (optional - mainly for client-side token cleanup)
app.post('/api/auth/logout', verifyToken, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.originalUrl
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (db) {
    await db.end();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  if (db) {
    await db.end();
  }
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log('🚀 Server is running on port', PORT);
      console.log('📧 Email configured:', !!process.env.EMAIL_USER);
      console.log('🔑 JWT Secret configured:', !!process.env.JWT_SECRET);
      console.log('🌐 Environment:', process.env.NODE_ENV || 'development');
      console.log('📍 Frontend URL:', process.env.FRONTEND_URL || 'http://localhost:3000');
      console.log('\n📋 Available endpoints:');
      console.log('   POST /api/auth/register - User registration');
      console.log('   POST /api/auth/login - User login');
      console.log('   GET  /api/admin/approve/:token - Admin approval');
      console.log('   GET  /api/user/profile - Get user profile (protected)');
      console.log('   GET  /api/admin/pending-users - Get pending users');
      console.log('   GET  /api/health - Health check');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

// Initialize and start the server
startServer();

module.exports = app;