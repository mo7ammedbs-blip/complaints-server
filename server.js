/**
 * Hawash Academy - Enterprise Multi-Teacher Platform Backend
 * (نسخة متطابقة تمامًا مع schema.sql الحقيقي اللي شغال عندك)
 */

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const path = require('path');

// ================= ENVIRONMENT VALIDATION =================
const REQUIRED_ENV_VARS = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_NAME'];
const missingEnvVars = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

if (missingEnvVars.length > 0) {
  console.error(`[FATAL] Missing required environment variables: ${missingEnvVars.join(', ')}.`);
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 5000;
const BCRYPT_SALT_ROUNDS = 12;

// ================= DATABASE POOL =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 15,
  queueLimit: 0,
  decimalNumbers: true,
});

pool.getConnection()
  .then((conn) => { console.log('[DB] Connected to MySQL Database Successfully'); conn.release(); })
  .catch((err) => { console.error('[DB] Connection error:', err.message); process.exit(1); });

// ================= APP SETUP & MIDDLEWARES =================
const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(cors({
  origin: '*',
  credentials: true,
}));

const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 });
app.use('/api/', generalLimiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'محاولات كثيرة جداً، يرجى الانتظار.' } });

// ================= SERVING STATIC FRONTEND ASSETS =================
app.use(express.static(path.join(__dirname)));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// ================= HELPERS & UTILS =================
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });
  next();
};

const paginate = (req) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  return { page, limit, offset: (page - 1) * limit };
};

// Admin Activity Logger — بيكتب في جدول admin_logs لو موجود عندك (اختياري، شوف extra_admin_logs.sql).
// لو الجدول مش موجود، الكتابة هتفشل بهدوء من غير ما توقف أي عملية تانية في الموقع.
const logAdminActivity = async (adminId, action, targetType, targetId, details, ip) => {
  try {
    await pool.query(
      `INSERT INTO admin_logs (admin_id, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
      [adminId, action, targetType, targetId, JSON.stringify(details), ip || '0.0.0.0']
    );
  } catch (err) {
    console.error('[AUDIT LOG ERROR]', err.message);
  }
};

// Authenticate & Role Verification Guards
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required. Unauthorized access.' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = decoded;
    next();
  });
};

// زي authenticateToken بس مش بيرفض الطلب لو مفيش توكن؛ مستخدمة في مسارات عامة زي /api/courses
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return next();
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (!err) req.user = decoded;
    next();
  });
};

const authorizeRoles = (...allowedRoles) => (req, res, next) => {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Forbidden: Insufficient privileges.' });
  }
  next();
};

// ================= AUTHENTICATION APIs =================
app.post('/api/auth/register', authLimiter, [
  body('name').trim().notEmpty().isLength({ max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').trim().notEmpty(),
  body('password').isLength({ min: 8 }),
  body('role').optional().isIn(['student', 'teacher']),
  body('grade').optional().isIn(['1sec', '2sec', '3sec']),
], handleValidation, asyncHandler(async (req, res) => {
  const { name, email, phone, password, role = 'student', grade = null, subject = 'General' } = req.body;

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ? OR phone = ? LIMIT 1', [email, phone]);
  if (existing.length > 0) return res.status(409).json({ error: 'البريد أو الهاتف مسجل بالفعل.' });

  const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
  const isApproved = role === 'student'; // المدرس بيتوقف على موافقة الأدمن، الطالب بيتفعل فورًا

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [result] = await conn.query(
      `INSERT INTO users (name, email, phone, password, role, grade, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, email, phone, hashedPassword, role, role === 'student' ? grade : null, isApproved]
    );

    if (role === 'teacher') {
      await conn.query(
        `INSERT INTO teacher_profiles (user_id, subject) VALUES (?, ?)`, // platform_commission_rate بياخد الافتراضي 20.00 من الجدول
        [result.insertId, subject]
      );
    }
    await conn.commit();
    res.status(201).json({ message: role === 'teacher' ? 'تم إنشاء الحساب في انتظار موافقة الإدارة.' : 'تم التسجيل بنجاح.' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/auth/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], handleValidation, asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة السر غير صحيحة.' });
  }
  if (user.is_blocked) return res.status(403).json({ error: 'تم إيقاف حسابك.' });
  if (!user.is_approved) return res.status(403).json({ error: 'حساب المدرس في انتظار تفعيل الأدمن.' });

  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, role: user.role, wallet: user.wallet_balance } });
}));

// جالب البروفايل الكامل والمحدّث بعد اللوجين ومع أي تحديث للوحة التحكم
app.get('/api/users/me', authenticateToken, asyncHandler(async (req, res) => {
  const [[user]] = await pool.query(
    `SELECT id, name, email, phone, role, grade, wallet_balance, is_approved, is_blocked FROM users WHERE id = ?`,
    [req.user.id]
  );
  if (!user) return res.status(404).json({ error: 'المستخدم غير موجود.' });
  if (user.is_blocked) return res.status(403).json({ error: 'تم إيقاف حسابك.' });

  let profile = null;
  if (user.role === 'teacher') {
    const [[p]] = await pool.query(
      `SELECT subject, total_earnings, platform_commission_rate FROM teacher_profiles WHERE user_id = ?`,
      [req.user.id]
    );
    profile = p || null;
  }
  res.json({ user, profile });
}));

// ================= 1. TEACHERS MANAGEMENT (ADMIN SECURED - لوحة admin.html) =================
app.get('/api/admin/teachers', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT u.id, u.name, u.email, u.phone, u.is_approved, u.is_blocked, 
            tp.subject, tp.bio, tp.platform_commission_rate AS commission_rate, tp.total_earnings,
            (SELECT COUNT(*) FROM courses WHERE teacher_id = u.id) as total_courses,
            (SELECT COUNT(*) FROM purchases WHERE teacher_id = u.id) as total_sales_count
     FROM users u 
     LEFT JOIN teacher_profiles tp ON u.id = tp.user_id 
     WHERE u.role = 'teacher' ORDER BY u.created_at DESC`
  );
  res.json(rows);
}));

// admin.html بيبعت { commission_rate } وبيتوقع يقدر يبعت bio/subject كمان لو احتاج مستقبلاً
app.put('/api/admin/teachers/:id', authenticateToken, authorizeRoles('super_admin'), [
  param('id').isInt(),
  body('commission_rate').optional().isFloat({ min: 0, max: 100 }),
  body('is_blocked').optional().isBoolean(),
  body('is_approved').optional().isBoolean(),
], handleValidation, asyncHandler(async (req, res) => {
  const teacherId = req.params.id;
  const { subject, bio, commission_rate, is_blocked, is_approved } = req.body;

  if (is_blocked !== undefined) {
    await pool.query('UPDATE users SET is_blocked = ? WHERE id = ?', [is_blocked, teacherId]);
  }
  if (is_approved !== undefined) {
    await pool.query('UPDATE users SET is_approved = ? WHERE id = ?', [is_approved, teacherId]);
  }

  await pool.query(
    `UPDATE teacher_profiles SET
       subject = COALESCE(?, subject),
       bio = COALESCE(?, bio),
       platform_commission_rate = COALESCE(?, platform_commission_rate)
     WHERE user_id = ?`,
    [subject, bio, commission_rate, teacherId]
  );

  await logAdminActivity(req.user.id, 'UPDATE_TEACHER', 'teacher', teacherId, req.body, req.ip);
  res.json({ message: 'Teacher profile updated successfully.' });
}));

// موافقة الأدمن على انضمام مدرس جديد (مستخدمة في لوحة index.html الجديدة)
app.put('/api/admin/teachers/:id/approve', authenticateToken, authorizeRoles('super_admin'), [param('id').isInt()], handleValidation, asyncHandler(async (req, res) => {
  const [result] = await pool.query(`UPDATE users SET is_approved = 1 WHERE id = ? AND role = 'teacher'`, [req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'المدرس غير موجود.' });
  await logAdminActivity(req.user.id, 'APPROVE_TEACHER', 'teacher', req.params.id, {}, req.ip);
  res.json({ message: 'تم توثيق حساب المدرس بنجاح.' });
}));

app.delete('/api/admin/teachers/:id', authenticateToken, authorizeRoles('super_admin'), [param('id').isInt()], handleValidation, asyncHandler(async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ? AND role = "teacher"', [req.params.id]);
  await logAdminActivity(req.user.id, 'DELETE_TEACHER', 'teacher', req.params.id, {}, req.ip);
  res.json({ message: 'Teacher removed permanently.' });
}));

// ================= 2. STUDENTS MANAGEMENT (ADMIN SECURED - لوحة admin.html) =================
app.get('/api/admin/students', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const { search } = req.query;
  const { page, limit, offset } = paginate(req);

  let queryStr = `SELECT id, name, email, phone, grade, wallet_balance, is_blocked, created_at FROM users WHERE role = 'student'`;
  const params = [];

  if (search) {
    queryStr += ` AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  queryStr += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const [students] = await pool.query(queryStr, params);
  res.json({ data: students, page, limit });
}));

app.put('/api/admin/students/:id/wallet', authenticateToken, authorizeRoles('super_admin'), [
  param('id').isInt(),
  body('amount').isFloat(),
  body('action').isIn(['add', 'deduct']),
  body('reason').trim().notEmpty(),
], handleValidation, asyncHandler(async (req, res) => {
  const { amount, action, reason } = req.body;
  const studentId = req.params.id;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[student]] = await conn.query('SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE', [studentId]);
    if (!student) { await conn.rollback(); return res.status(404).json({ error: 'Student not found' }); }

    const balanceBefore = student.wallet_balance;
    const balanceAfter = action === 'add' ? balanceBefore + amount : balanceBefore - amount;
    if (balanceAfter < 0) { await conn.rollback(); return res.status(400).json({ error: 'Insufficient balance for deduction.' }); }

    await conn.query('UPDATE users SET wallet_balance = ? WHERE id = ?', [balanceAfter, studentId]);
    // ملحوظة: مفيش جدول transactions في السكيمة الحقيقية عندك، فسجل تعديل الأدمن اليدوي بيتسجل في admin_logs بس
    await conn.commit();
    await logAdminActivity(req.user.id, 'MODIFY_WALLET', 'student', studentId, { action, amount, reason, balanceBefore, balanceAfter }, req.ip);
    res.json({ message: 'Wallet balance updated successfully.', newBalance: balanceAfter });
  } catch (err) {
    await conn.rollback(); throw err;
  } finally { conn.release(); }
}));

// ================= 3. ANALYTICS & AUDIT LOGS (لوحة admin.html) =================
app.get('/api/admin/analytics', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const [[{ sales_today }]] = await pool.query(`SELECT COALESCE(SUM(price_paid), 0) as sales_today FROM purchases WHERE DATE(purchased_at) = CURDATE()`);
  const [[{ sales_month }]] = await pool.query(`SELECT COALESCE(SUM(price_paid), 0) as sales_month FROM purchases WHERE MONTH(purchased_at) = MONTH(CURDATE()) AND YEAR(purchased_at) = YEAR(CURDATE())`);
  const [[{ net_revenue }]] = await pool.query(`SELECT COALESCE(SUM(platform_fee), 0) as net_revenue FROM purchases`);
  const [[{ pending_payouts }]] = await pool.query(`SELECT COALESCE(SUM(teacher_net), 0) as pending_payouts FROM purchases`);

  res.json({ sales_today, sales_month, net_revenue, pending_payouts });
}));

app.get('/api/admin/audit-logs', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const [logs] = await pool.query(
    `SELECT l.*, u.name as admin_name FROM admin_logs l JOIN users u ON l.admin_id = u.id ORDER BY l.created_at DESC LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  res.json(logs);
}));

// ================= 4. COURSES (سوق المحاضرات + إدارة المدرس) =================

// عرض عام للمحاضرات (سوق الطلاب). الطالب/الزائر بيشوف بس المحاضرات المفتوحة (is_locked=0).
// الأدمن (لو باعت توكن صحيح) بيشوف الكل عشان يديرها من لوحته.
app.get('/api/courses', optionalAuth, [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('grade').optional().isIn(['1sec', '2sec', '3sec']),
], handleValidation, asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const { grade, subject, teacherId } = req.query;
  const isAdmin = req.user && req.user.role === 'super_admin';

  let where = isAdmin ? ' WHERE 1=1' : ' WHERE c.is_locked = 0';
  const params = [];

  if (grade) { where += ' AND c.grade = ?'; params.push(grade); }
  if (subject) { where += ' AND c.subject LIKE ?'; params.push(`%${subject}%`); }
  if (teacherId) { where += ' AND c.teacher_id = ?'; params.push(teacherId); }

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) as total FROM courses c ${where}`, params);

  const [rows] = await pool.query(
    `SELECT c.id, c.teacher_id, u.name as teacher_name, c.title, c.subject, c.grade, c.price, c.is_locked AS locked
     FROM courses c JOIN users u ON c.teacher_id = u.id
     ${where} ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );

  res.json({ data: rows, page, totalPages: Math.max(1, Math.ceil(total / limit)) });
}));

// إضافة محاضرة جديدة (المدرس بينشرها لنفسه فقط) — video_url إلزامي حسب السكيمة
app.post('/api/courses', authenticateToken, authorizeRoles('teacher'), [
  body('title').trim().notEmpty().isLength({ max: 200 }),
  body('subject').trim().notEmpty().isLength({ max: 100 }),
  body('grade').isIn(['1sec', '2sec', '3sec']),
  body('price').isFloat({ min: 0 }),
  body('videoUrl').trim().notEmpty().withMessage('رابط الفيديو مطلوب.'),
  body('pdfUrl').optional({ checkFalsy: true }).trim(),
], handleValidation, asyncHandler(async (req, res) => {
  const { title, subject, grade, price, videoUrl, pdfUrl } = req.body;
  const [result] = await pool.query(
    `INSERT INTO courses (teacher_id, title, subject, grade, price, video_url, pdf_url) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.user.id, title, subject, grade, price, videoUrl, pdfUrl || '']
  );
  res.status(201).json({ message: 'تم نشر المحاضرة بنجاح.', id: result.insertId });
}));

// تعديل محاضرة (المدرس صاحبها أو الأدمن)
app.put('/api/courses/:id', authenticateToken, authorizeRoles('teacher', 'super_admin'), [
  param('id').isInt(),
  body('title').optional().trim().notEmpty().isLength({ max: 200 }),
  body('subject').optional().trim().notEmpty().isLength({ max: 100 }),
  body('grade').optional().isIn(['1sec', '2sec', '3sec']),
  body('price').optional().isFloat({ min: 0 }),
], handleValidation, asyncHandler(async (req, res) => {
  const courseId = req.params.id;
  const [[course]] = await pool.query('SELECT teacher_id FROM courses WHERE id = ?', [courseId]);
  if (!course) return res.status(404).json({ error: 'المحاضرة غير موجودة.' });
  if (req.user.role === 'teacher' && course.teacher_id !== req.user.id) {
    return res.status(403).json({ error: 'لا يمكنك تعديل محاضرة مدرس آخر.' });
  }

  const { title, subject, grade, price, videoUrl, pdfUrl } = req.body;
  await pool.query(
    `UPDATE courses SET
      title = COALESCE(?, title), subject = COALESCE(?, subject), grade = COALESCE(?, grade),
      price = COALESCE(?, price), video_url = COALESCE(?, video_url), pdf_url = COALESCE(?, pdf_url)
     WHERE id = ?`,
    [title, subject, grade, price, videoUrl, pdfUrl, courseId]
  );
  res.json({ message: 'تم تحديث المحاضرة بنجاح.' });
}));

// قفل/فتح محاضرة
app.put('/api/courses/:id/lock', authenticateToken, authorizeRoles('teacher', 'super_admin'), [
  param('id').isInt(), body('locked').isBoolean(),
], handleValidation, asyncHandler(async (req, res) => {
  const courseId = req.params.id;
  const [[course]] = await pool.query('SELECT teacher_id FROM courses WHERE id = ?', [courseId]);
  if (!course) return res.status(404).json({ error: 'المحاضرة غير موجودة.' });
  if (req.user.role === 'teacher' && course.teacher_id !== req.user.id) {
    return res.status(403).json({ error: 'لا يمكنك التحكم في محاضرة مدرس آخر.' });
  }
  await pool.query('UPDATE courses SET is_locked = ? WHERE id = ?', [req.body.locked, courseId]);
  res.json({ message: req.body.locked ? 'تم قفل المحاضرة.' : 'تم فتح المحاضرة.' });
}));

// حذف محاضرة
app.delete('/api/courses/:id', authenticateToken, authorizeRoles('teacher', 'super_admin'), [param('id').isInt()], handleValidation, asyncHandler(async (req, res) => {
  const courseId = req.params.id;
  const [[course]] = await pool.query('SELECT teacher_id FROM courses WHERE id = ?', [courseId]);
  if (!course) return res.status(404).json({ error: 'المحاضرة غير موجودة.' });
  if (req.user.role === 'teacher' && course.teacher_id !== req.user.id) {
    return res.status(403).json({ error: 'لا يمكنك حذف محاضرة مدرس آخر.' });
  }
  await pool.query('DELETE FROM courses WHERE id = ?', [courseId]);
  res.json({ message: 'تم حذف المحاضرة.' });
}));

// ================= 5. TEACHER DASHBOARD (محاضراته + إحصائياته) =================
app.get('/api/teacher/courses', authenticateToken, authorizeRoles('teacher'), asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const [[{ total }]] = await pool.query('SELECT COUNT(*) as total FROM courses WHERE teacher_id = ?', [req.user.id]);
  const [rows] = await pool.query(
    `SELECT id, title, subject, grade, price, video_url, pdf_url, is_locked AS locked FROM courses
     WHERE teacher_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [req.user.id, limit, offset]
  );
  res.json({ data: rows, page, totalPages: Math.max(1, Math.ceil(total / limit)) });
}));

app.get('/api/teacher/stats', authenticateToken, authorizeRoles('teacher'), asyncHandler(async (req, res) => {
  const [[profile]] = await pool.query(
    'SELECT subject, total_earnings, platform_commission_rate FROM teacher_profiles WHERE user_id = ?', [req.user.id]
  );
  const [[{ courseCount }]] = await pool.query('SELECT COUNT(*) as courseCount FROM courses WHERE teacher_id = ?', [req.user.id]);
  const [[{ studentCount }]] = await pool.query(
    'SELECT COUNT(DISTINCT student_id) as studentCount FROM purchases WHERE teacher_id = ?', [req.user.id]
  );

  res.json({
    subject: profile ? profile.subject : null,
    totalEarnings: profile ? profile.total_earnings : 0,
    courseCount,
    studentCount,
    commissionRate: profile ? profile.platform_commission_rate : null,
  });
}));

// ================= 6. STUDENT PURCHASES & WALLET =================
app.post('/api/student/buy-course', authenticateToken, authorizeRoles('student'), [
  body('courseId').isInt(),
], handleValidation, asyncHandler(async (req, res) => {
  const { courseId } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[course]] = await conn.query('SELECT id, teacher_id, price, is_locked, title FROM courses WHERE id = ? FOR UPDATE', [courseId]);
    if (!course) { await conn.rollback(); return res.status(404).json({ error: 'المحاضرة غير موجودة.' }); }
    if (course.is_locked) { await conn.rollback(); return res.status(400).json({ error: 'هذه المحاضرة مغلقة حالياً.' }); }

    const [[already]] = await conn.query('SELECT id FROM purchases WHERE student_id = ? AND course_id = ?', [req.user.id, courseId]);
    if (already) { await conn.rollback(); return res.status(409).json({ error: 'تم تفعيل هذه المحاضرة من قبل.' }); }

    const [[student]] = await conn.query('SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE', [req.user.id]);
    const balanceBefore = student.wallet_balance;
    if (balanceBefore < course.price) { await conn.rollback(); return res.status(400).json({ error: 'رصيد محفظتك غير كافٍ، من فضلك اشحن رصيدك أولاً.' }); }

    const balanceAfter = balanceBefore - course.price;
    await conn.query('UPDATE users SET wallet_balance = ? WHERE id = ?', [balanceAfter, req.user.id]);

    // platform_commission_rate = نسبة اللي المنصة بتاخدها (افتراضي 20%)، والباقي صافي للمدرس
    const [[tp]] = await conn.query('SELECT platform_commission_rate FROM teacher_profiles WHERE user_id = ? FOR UPDATE', [course.teacher_id]);
    const platformRate = tp ? tp.platform_commission_rate : 20;
    const platformFee = Number((course.price * platformRate / 100).toFixed(2));
    const teacherNet = Number((course.price - platformFee).toFixed(2));

    await conn.query(
      'INSERT INTO purchases (student_id, course_id, teacher_id, price_paid, platform_fee, teacher_net) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, courseId, course.teacher_id, course.price, platformFee, teacherNet]
    );
    await conn.query(
      'UPDATE teacher_profiles SET total_earnings = total_earnings + ? WHERE user_id = ?',
      [teacherNet, course.teacher_id]
    );

    await conn.commit();
    res.json({ message: 'تم تفعيل المحاضرة بنجاح.', remainingBalance: balanceAfter });
  } catch (err) {
    await conn.rollback(); throw err;
  } finally { conn.release(); }
}));

app.get('/api/student/purchases', authenticateToken, authorizeRoles('student'), asyncHandler(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT p.purchased_at as created_at, c.id as course_id, c.title, c.video_url, c.pdf_url, u.name as teacher_name
     FROM purchases p
     JOIN courses c ON p.course_id = c.id
     JOIN users u ON c.teacher_id = u.id
     WHERE p.student_id = ? ORDER BY p.purchased_at DESC`,
    [req.user.id]
  );
  res.json({ data: rows });
}));

app.post('/api/payments/recharge', authenticateToken, authorizeRoles('student'), [
  body('amount').isFloat({ min: 1 }),
  body('senderPhone').trim().notEmpty(),
], handleValidation, asyncHandler(async (req, res) => {
  const { amount, senderPhone } = req.body;
  await pool.query(
    'INSERT INTO payments (student_id, amount, sender_phone, status) VALUES (?, ?, ?, "pending")',
    [req.user.id, amount, senderPhone]
  );
  res.status(201).json({ message: 'تم إرسال طلب الشحن، هيتم مراجعته من الإدارة قريباً.' });
}));

// ================= 7. COMPLAINTS (شكاوى) =================
app.post('/api/complaints', authenticateToken, authorizeRoles('student'), [
  body('issueType').isIn(['technical', 'academic', 'payment']),
  body('details').trim().notEmpty(),
], handleValidation, asyncHandler(async (req, res) => {
  const { issueType, details } = req.body;
  await pool.query('INSERT INTO complaints (student_id, issue_type, details) VALUES (?, ?, ?)', [req.user.id, issueType, details]);
  res.status(201).json({ message: 'تم استلام شكواك بنجاح.' });
}));

// المدرس بيشوف شكاوى طلابه بس (طلاب اشتروا منه محاضرة على الأقل)، الأدمن بيشوف الكل
app.get('/api/complaints', authenticateToken, authorizeRoles('teacher', 'super_admin'), asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const isAdmin = req.user.role === 'super_admin';

  const where = isAdmin
    ? ''
    : ' WHERE c.student_id IN (SELECT DISTINCT student_id FROM purchases WHERE teacher_id = ?)';
  const params = isAdmin ? [] : [req.user.id];

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) as total FROM complaints c ${where}`, params);
  const [rows] = await pool.query(
    `SELECT c.id, c.issue_type, c.details, c.status, c.created_at, u.name as student_name, u.email as student_email
     FROM complaints c JOIN users u ON c.student_id = u.id
     ${where} ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  res.json({ data: rows, page, totalPages: Math.max(1, Math.ceil(total / limit)) });
}));

// ================= 8. ANNOUNCEMENTS (إعلانات) =================
app.post('/api/announcements', authenticateToken, authorizeRoles('super_admin'), [
  body('title').trim().notEmpty().isLength({ max: 200 }),
  body('content').trim().notEmpty(),
  body('targetAudience').optional().isIn(['all', '1sec', '2sec', '3sec']),
], handleValidation, asyncHandler(async (req, res) => {
  const { title, content, targetAudience = 'all' } = req.body;
  await pool.query(
    'INSERT INTO announcements (title, content, target_audience, created_by) VALUES (?, ?, ?, ?)',
    [title, content, targetAudience, req.user.id]
  );
  await logAdminActivity(req.user.id, 'PUBLISH_ANNOUNCEMENT', 'announcement', null, { title, targetAudience }, req.ip);
  res.status(201).json({ message: 'تم نشر الإعلان بنجاح.' });
}));

app.get('/api/announcements', [query('limit').optional().isInt({ min: 1, max: 50 })], handleValidation, asyncHandler(async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), 50);
  const [rows] = await pool.query('SELECT * FROM announcements ORDER BY created_at DESC LIMIT ?', [limit]);
  res.json({ data: rows });
}));

// ================= 9. ADMIN DASHBOARD الجديدة (index.html) =================
app.get('/api/admin/stats', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const [[{ totalRevenue }]] = await pool.query(`SELECT COALESCE(SUM(price_paid), 0) as totalRevenue FROM purchases`);
  const [[{ platformProfit }]] = await pool.query(`SELECT COALESCE(SUM(platform_fee), 0) as platformProfit FROM purchases`);
  const [[{ totalStudents }]] = await pool.query(`SELECT COUNT(*) as totalStudents FROM users WHERE role = 'student'`);
  const [[{ totalTeachers }]] = await pool.query(`SELECT COUNT(*) as totalTeachers FROM users WHERE role = 'teacher' AND is_approved = 1`);

  res.json({ revenue: { totalRevenue, platformProfit }, totalStudents, totalTeachers });
}));

app.get('/api/admin/users', authenticateToken, authorizeRoles('super_admin'), asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const { search, role, grade, pendingApproval } = req.query;

  let where = ' WHERE 1=1';
  const params = [];
  if (search) { where += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (role) { where += ' AND role = ?'; params.push(role); }
  if (grade) { where += ' AND grade = ?'; params.push(grade); }
  if (pendingApproval === 'true') { where += ' AND role = "teacher" AND is_approved = 0'; }

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) as total FROM users ${where}`, params);
  const [rows] = await pool.query(
    `SELECT id, name, email, phone, role, grade, wallet_balance, is_blocked, is_approved, created_at
     FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );
  res.json({ data: rows, page, totalPages: Math.max(1, Math.ceil(total / limit)) });
}));

app.put('/api/admin/users/block/:id', authenticateToken, authorizeRoles('super_admin'), [param('id').isInt()], handleValidation, asyncHandler(async (req, res) => {
  const [[user]] = await pool.query('SELECT role, is_blocked FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'المستخدم غير موجود.' });
  if (user.role === 'super_admin') return res.status(403).json({ error: 'لا يمكن حظر حساب الإدارة.' });

  await pool.query('UPDATE users SET is_blocked = ? WHERE id = ?', [!user.is_blocked, req.params.id]);
  await logAdminActivity(req.user.id, user.is_blocked ? 'UNBLOCK_USER' : 'BLOCK_USER', 'user', req.params.id, {}, req.ip);
  res.json({ message: !user.is_blocked ? 'تم حظر الحساب.' : 'تم فك الحظر عن الحساب.' });
}));

app.delete('/api/admin/users/:id', authenticateToken, authorizeRoles('super_admin'), [param('id').isInt()], handleValidation, asyncHandler(async (req, res) => {
  const [[user]] = await pool.query('SELECT role FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'المستخدم غير موجود.' });
  if (user.role === 'super_admin') return res.status(403).json({ error: 'لا يمكن حذف حساب الإدارة.' });

  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  await logAdminActivity(req.user.id, 'DELETE_USER', 'user', req.params.id, {}, req.ip);
  res.json({ message: 'تم حذف الحساب بنجاح.' });
}));

app.get('/api/admin/payments', authenticateToken, authorizeRoles('super_admin'), [
  query('status').optional().isIn(['pending', 'approved', 'rejected']),
], handleValidation, asyncHandler(async (req, res) => {
  const { page, limit, offset } = paginate(req);
  const status = req.query.status || 'pending';

  const [[{ total }]] = await pool.query('SELECT COUNT(*) as total FROM payments WHERE status = ?', [status]);
  const [rows] = await pool.query(
    `SELECT p.id, p.amount, p.sender_phone, p.status, p.created_at, u.name as student_name, u.email as student_email
     FROM payments p JOIN users u ON p.student_id = u.id
     WHERE p.status = ? ORDER BY p.created_at ASC LIMIT ? OFFSET ?`,
    [status, limit, offset]
  );
  res.json({ data: rows, page, totalPages: Math.max(1, Math.ceil(total / limit)) });
}));

app.put('/api/admin/payments/:id/review', authenticateToken, authorizeRoles('super_admin'), [
  param('id').isInt(), body('decision').isIn(['approved', 'rejected']),
], handleValidation, asyncHandler(async (req, res) => {
  const { decision } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[pr]] = await conn.query('SELECT * FROM payments WHERE id = ? AND status = "pending" FOR UPDATE', [req.params.id]);
    if (!pr) { await conn.rollback(); return res.status(404).json({ error: 'طلب الشحن غير موجود أو تمت مراجعته بالفعل.' }); }

    if (decision === 'approved') {
      const [[student]] = await conn.query('SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE', [pr.student_id]);
      const balanceAfter = student.wallet_balance + pr.amount;
      await conn.query('UPDATE users SET wallet_balance = ? WHERE id = ?', [balanceAfter, pr.student_id]);
    }

    await conn.query('UPDATE payments SET status = ? WHERE id = ?', [decision, req.params.id]);
    await conn.commit();
    await logAdminActivity(req.user.id, 'REVIEW_PAYMENT', 'payment', req.params.id, { decision }, req.ip);
    res.json({ message: decision === 'approved' ? 'تم قبول طلب الشحن وإضافة الرصيد.' : 'تم رفض طلب الشحن.' });
  } catch (err) {
    await conn.rollback(); throw err;
  } finally { conn.release(); }
}));

// ================= FRONTEND DYNAMIC ROUTING =================
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'مسار الـ API غير موجود' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ================= ERROR HANDLING & SERVER LAUNCH =================
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
  res.status(err.status || 500).json({
    error: NODE_ENV === 'development' ? err.message : 'Internal Server Error'
  });
});

const server = app.listen(PORT, () => {
  console.log(`=========================================`);
  console.log(`🚀 Hawash Enterprise Server Running on Port ${PORT}`);
  console.log(`🎓 Student Platform: http://localhost:${PORT}`);
  console.log(`🛡️ Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`=========================================`);
});

process.on('SIGINT', async () => {
  server.close(async () => { await pool.end(); process.exit(0); });
});

module.exports = app;
