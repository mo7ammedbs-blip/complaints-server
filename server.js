/**
 * Hawash Academy - Multi-Teacher Enterprise Backend (MySQL edition)
 *
 * Same hardening as the MongoDB version, ported to MySQL via mysql2:
 *  - No hardcoded secrets — fails fast if env vars are missing
 *  - Restricted CORS + Helmet + rate limiting
 *  - Centralized async error handling that never leaks internals
 *  - Input validation on every mutating route (express-validator)
 *  - Role-based authorization helper
 *  - Purchase flow wrapped in a real SQL transaction with row locking
 *    (SELECT ... FOR UPDATE) to prevent double-spend / race conditions
 *  - Complaints endpoint requires auth; student_id comes from the token
 *  - Pagination on list endpoints
 *  - Passwords never returned in API responses
 *  - Teacher approval workflow
 *  - Graceful shutdown
 *
 * Run schema.sql against your MySQL database before starting this server.
 */

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// ================= ENVIRONMENT VALIDATION =================
const REQUIRED_ENV_VARS = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_NAME'];
const missingEnvVars = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

if (missingEnvVars.length > 0) {
  console.error(
    `[FATAL] Missing required environment variables: ${missingEnvVars.join(', ')}. ` +
    `Set them (e.g. via a .env file or your process manager) before starting the server.`
  );
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 5000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);
const BCRYPT_SALT_ROUNDS = 12;

// ================= DATABASE POOL =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  decimalNumbers: true, // return DECIMAL columns as JS numbers, not strings
});

// Fail fast if the DB is unreachable at boot.
pool
  .getConnection()
  .then((conn) => {
    console.log('[DB] Connected to MySQL');
    conn.release();
  })
  .catch((err) => {
    console.error('[DB] Connection error:', err.message);
    process.exit(1);
  });

// ================= APP SETUP =================
const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ================= HELPERS =================

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Validation failed', details: errors.array() });
  }
  next();
};

const paginate = (req) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  return { page, limit, offset: (page - 1) * limit };
};

// ================= MIDDLEWARES =================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded; // { id, role, name }
    next();
  });
};

const authorizeRoles = (...allowedRoles) => (req, res, next) => {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

// ================= AUTH ENDPOINTS =================

app.post(
  '/api/auth/register',
  authLimiter,
  [
    body('name').trim().notEmpty().withMessage('Name is required').isLength({ max: 100 }),
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('phone').trim().notEmpty().withMessage('Phone is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('role').optional().isIn(['student', 'teacher']).withMessage('Invalid role'),
    body('grade').optional().isIn(['1sec', '2sec', '3sec']),
    body('subject').optional().trim(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { name, email, phone, password, role = 'student', grade = null, subject } = req.body;

    const [existingRows] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
    if (existingRows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const isApproved = role === 'teacher' ? false : true;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [result] = await conn.query(
        `INSERT INTO users (name, email, phone, password, role, grade, is_approved)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, email, phone, hashedPassword, role, role === 'student' ? grade : null, isApproved]
      );

      if (role === 'teacher') {
        await conn.query(`INSERT INTO teacher_profiles (user_id, subject) VALUES (?, ?)`, [
          result.insertId,
          subject || 'General',
        ]);
      }

      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    res.status(201).json({
      message:
        role === 'teacher'
          ? 'Teacher account created and pending admin approval.'
          : 'User registered successfully.',
    });
  })
);

app.post(
  '/api/auth/login',
  authLimiter,
  [
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password required'),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const [rows] = await pool.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
    const user = rows[0];

    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account is suspended' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.is_approved) return res.status(403).json({ error: 'Teacher account pending approval' });

    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, {
      expiresIn: '7d',
    });

    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, balance: user.wallet_balance },
    });
  })
);

// ================= COURSES ENDPOINTS =================

app.get(
  '/api/courses',
  [
    query('subject').optional().trim(),
    query('grade').optional().isIn(['1sec', '2sec', '3sec']),
    query('teacherId').optional().isInt(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { subject, grade, teacherId } = req.query;
    const { page, limit, offset } = paginate(req);

    const conditions = [];
    const params = [];
    if (subject) {
      conditions.push('c.subject = ?');
      params.push(subject);
    }
    if (grade) {
      conditions.push('c.grade = ?');
      params.push(grade);
    }
    if (teacherId) {
      conditions.push('c.teacher_id = ?');
      params.push(teacherId);
    }
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [rows] = await pool.query(
      `SELECT c.*, u.name AS teacher_name
       FROM courses c
       JOIN users u ON u.id = c.teacher_id
       ${whereClause}
       ORDER BY c.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM courses c ${whereClause}`,
      params
    );

    res.json({ data: rows, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

app.post(
  '/api/courses',
  authenticateToken,
  authorizeRoles('teacher', 'super_admin'),
  [
    body('title').trim().notEmpty().isLength({ max: 200 }),
    body('subject').trim().notEmpty(),
    body('grade').isIn(['1sec', '2sec', '3sec']),
    body('price').isFloat({ min: 0 }),
    body('videoUrl').trim().isURL().withMessage('Valid video URL required'),
    body('pdfUrl').optional({ checkFalsy: true }).trim().isURL(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { title, subject, grade, price, videoUrl, pdfUrl = '' } = req.body;

    const [result] = await pool.query(
      `INSERT INTO courses (title, subject, grade, price, video_url, pdf_url, teacher_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, subject, grade, price, videoUrl, pdfUrl, req.user.id]
    );

    const [rows] = await pool.query('SELECT * FROM courses WHERE id = ?', [result.insertId]);
    res.status(201).json({ message: 'Course created successfully', course: rows[0] });
  })
);

// ================= WALLET & PURCHASES =================

app.post(
  '/api/student/buy-course',
  authenticateToken,
  authorizeRoles('student'),
  [body('courseId').isInt().withMessage('Valid courseId required')],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { courseId } = req.body;
    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      // Lock the course row and the student row for the duration of the transaction
      // so concurrent purchase attempts can't race each other.
      const [courseRows] = await conn.query('SELECT * FROM courses WHERE id = ? FOR UPDATE', [courseId]);
      const course = courseRows[0];
      if (!course) {
        await conn.rollback();
        return res.status(404).json({ error: 'Course not found' });
      }

      const [existingPurchase] = await conn.query(
        'SELECT id FROM purchases WHERE student_id = ? AND course_id = ? LIMIT 1',
        [req.user.id, courseId]
      );
      if (existingPurchase.length > 0) {
        await conn.rollback();
        return res.status(409).json({ error: 'Course already purchased' });
      }

      const [studentRows] = await conn.query('SELECT * FROM users WHERE id = ? FOR UPDATE', [req.user.id]);
      const student = studentRows[0];
      if (!student || student.wallet_balance < course.price) {
        await conn.rollback();
        return res.status(400).json({ error: 'Insufficient wallet balance' });
      }

      const newBalance = Number((student.wallet_balance - course.price).toFixed(2));
      await conn.query('UPDATE users SET wallet_balance = ? WHERE id = ?', [newBalance, student.id]);

      const [teacherProfileRows] = await conn.query(
        'SELECT * FROM teacher_profiles WHERE user_id = ? FOR UPDATE',
        [course.teacher_id]
      );
      const teacherProfile = teacherProfileRows[0];
      const commRate = teacherProfile ? teacherProfile.platform_commission_rate : 20;
      const platformFee = Number(((course.price * commRate) / 100).toFixed(2));
      const teacherNet = Number((course.price - platformFee).toFixed(2));

      if (teacherProfile) {
        await conn.query('UPDATE teacher_profiles SET total_earnings = total_earnings + ? WHERE user_id = ?', [
          teacherNet,
          course.teacher_id,
        ]);
      }

      await conn.query(
        `INSERT INTO purchases (student_id, course_id, teacher_id, price_paid, platform_fee, teacher_net)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [student.id, course.id, course.teacher_id, course.price, platformFee, teacherNet]
      );

      await conn.commit();
      res.json({ message: 'Purchase successful', remainingBalance: newBalance });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  })
);

app.post(
  '/api/payments/recharge',
  authenticateToken,
  authorizeRoles('student'),
  [
    body('amount').isFloat({ min: 1 }).withMessage('Amount must be greater than 0'),
    body('senderPhone').trim().notEmpty(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { amount, senderPhone } = req.body;
    await pool.query('INSERT INTO payments (student_id, amount, sender_phone) VALUES (?, ?, ?)', [
      req.user.id,
      amount,
      senderPhone,
    ]);
    res.status(201).json({ message: 'Recharge request submitted for review' });
  })
);

// Admin: approve/reject a pending recharge and credit the wallet atomically.
app.put(
  '/api/admin/payments/:id/review',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isInt(), body('decision').isIn(['approved', 'rejected'])],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { decision } = req.body;
    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [rows] = await conn.query('SELECT * FROM payments WHERE id = ? FOR UPDATE', [req.params.id]);
      const payment = rows[0];
      if (!payment) {
        await conn.rollback();
        return res.status(404).json({ error: 'Payment not found' });
      }
      if (payment.status !== 'pending') {
        await conn.rollback();
        return res.status(409).json({ error: 'Payment already reviewed' });
      }

      await conn.query('UPDATE payments SET status = ? WHERE id = ?', [decision, payment.id]);

      if (decision === 'approved') {
        await conn.query('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', [
          payment.amount,
          payment.student_id,
        ]);
      }

      await conn.commit();
      res.json({ message: `Payment ${decision}` });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  })
);

// ================= COMPLAINTS & CHATBOT API =================

app.post(
  '/api/complaints',
  authenticateToken,
  authorizeRoles('student'),
  [
    body('issueType').isIn(['technical', 'academic', 'payment']),
    body('details').trim().notEmpty().isLength({ max: 2000 }),
    body('teacherId').optional().isInt(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { issueType, details, teacherId = null } = req.body;
    await pool.query(
      `INSERT INTO complaints (student_id, issue_type, details, teacher_id) VALUES (?, ?, ?, ?)`,
      [req.user.id, issueType, details, teacherId]
    );
    res.status(201).json({ message: 'Complaint submitted successfully' });
  })
);

app.get(
  '/api/complaints',
  authenticateToken,
  authorizeRoles('teacher', 'super_admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginate(req);
    const isTeacher = req.user.role === 'teacher';
    const whereClause = isTeacher ? 'WHERE co.teacher_id = ?' : '';
    const params = isTeacher ? [req.user.id] : [];

    const [rows] = await pool.query(
      `SELECT co.*, u.name AS student_name, u.email AS student_email
       FROM complaints co
       JOIN users u ON u.id = co.student_id
       ${whereClause}
       ORDER BY co.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM complaints co ${whereClause}`,
      params
    );

    res.json({ data: rows, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

// ================= ANNOUNCEMENTS =================

app.get(
  '/api/announcements',
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginate(req);
    const [rows] = await pool.query(
      'SELECT * FROM announcements ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );
    const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM announcements');

    res.json({ data: rows, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

app.post(
  '/api/announcements',
  authenticateToken,
  authorizeRoles('super_admin', 'teacher'),
  [
    body('title').trim().notEmpty().isLength({ max: 200 }),
    body('content').trim().notEmpty().isLength({ max: 5000 }),
    body('targetAudience').optional().isIn(['all', '1sec', '2sec', '3sec']),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { title, content, targetAudience = 'all' } = req.body;
    await pool.query(
      `INSERT INTO announcements (title, content, target_audience, created_by) VALUES (?, ?, ?, ?)`,
      [title, content, targetAudience, req.user.id]
    );
    res.status(201).json({ message: 'Announcement published' });
  })
);

// ================= SUPER ADMIN CONTROLS =================

app.get(
  '/api/admin/users',
  authenticateToken,
  authorizeRoles('super_admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginate(req);
    const [rows] = await pool.query(
      `SELECT id, name, email, phone, role, grade, wallet_balance, is_approved, is_blocked, created_at
       FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM users');

    res.json({ data: rows, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

app.put(
  '/api/admin/users/block/:id',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isInt()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const [rows] = await pool.query('SELECT id, is_blocked FROM users WHERE id = ?', [req.params.id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newStatus = !user.is_blocked;
    await pool.query('UPDATE users SET is_blocked = ? WHERE id = ?', [newStatus, user.id]);
    res.json({ message: `User block status updated to ${newStatus}` });
  })
);

app.put(
  '/api/admin/teachers/:id/approve',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isInt()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const [rows] = await pool.query('SELECT id FROM users WHERE id = ? AND role = "teacher"', [
      req.params.id,
    ]);
    if (rows.length === 0) return res.status(404).json({ error: 'Teacher not found' });

    await pool.query('UPDATE users SET is_approved = TRUE WHERE id = ?', [req.params.id]);
    res.json({ message: 'Teacher approved' });
  })
);

app.get(
  '/api/admin/stats',
  authenticateToken,
  authorizeRoles('super_admin'),
  asyncHandler(async (req, res) => {
    const [[{ totalStudents }]] = await pool.query(
      `SELECT COUNT(*) AS totalStudents FROM users WHERE role = 'student'`
    );
    const [[{ totalTeachers }]] = await pool.query(
      `SELECT COUNT(*) AS totalTeachers FROM users WHERE role = 'teacher'`
    );
    const [[revenue]] = await pool.query(
      `SELECT COALESCE(SUM(price_paid), 0) AS totalRevenue, COALESCE(SUM(platform_fee), 0) AS platformProfit
       FROM purchases`
    );

    res.json({ totalStudents, totalTeachers, revenue });
  })
);

// ================= 404 + CENTRALIZED ERROR HANDLING =================

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err);

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  // MySQL duplicate-entry / FK / data errors -> safe generic messages.
  if (err.code === 'ER_DUP_ENTRY') {
    return res.status(409).json({ error: 'Duplicate entry' });
  }
  if (err.code === 'ER_NO_REFERENCED_ROW' || err.code === 'ER_NO_REFERENCED_ROW_2') {
    return res.status(400).json({ error: 'Referenced record does not exist' });
  }

  const status = err.status || 500;
  res.status(status).json({
    error: status === 500 ? 'Internal server error' : err.message,
    ...(NODE_ENV === 'development' && { detail: err.message, stack: err.stack }),
  });
});

// ================= SERVER STARTUP & GRACEFUL SHUTDOWN =================

const server = app.listen(PORT, () => console.log(`[SERVER] Running on port ${PORT} (${NODE_ENV})`));

const shutdown = async (signal) => {
  console.log(`[SERVER] Received ${signal}, shutting down gracefully...`);
  server.close(async () => {
    await pool.end();
    console.log('[SERVER] Closed all connections. Exiting.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
