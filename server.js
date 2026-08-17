/**
 * Hawash Academy - Multi-Teacher Enterprise Backend
 * Hardened / production-oriented version.
 *
 * Changes vs. the original draft (see README.md for full list):
 *  - No hardcoded secrets / DB URIs — fails fast if env vars are missing
 *  - Restricted CORS (explicit origin whitelist)
 *  - Helmet security headers + rate limiting on sensitive routes
 *  - Centralized async error handling that never leaks internals to clients
 *  - Input validation on every mutating route (express-validator)
 *  - Role-based authorization helper (authorizeRoles)
 *  - Purchase flow wrapped in a MongoDB transaction (atomic wallet debit + ledger)
 *  - Complaints endpoint requires auth; studentId derived from the token, not the body
 *  - Pagination on list endpoints
 *  - Passwords never selected/returned by default
 *  - Teacher approval workflow exposed to super_admin
 *  - Graceful shutdown
 */

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

// ================= ENVIRONMENT VALIDATION =================
// Fail fast on boot rather than silently running with insecure defaults.
const REQUIRED_ENV_VARS = ['JWT_SECRET', 'MONGO_URI'];
const missingEnvVars = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

if (missingEnvVars.length > 0) {
  console.error(
    `[FATAL] Missing required environment variables: ${missingEnvVars.join(', ')}. ` +
    `Set them (e.g. via a .env file or your process manager) before starting the server.`
  );
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 5000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);
const BCRYPT_SALT_ROUNDS = 12;

// ================= APP SETUP =================
const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow non-browser requests (no origin header) and whitelisted origins only.
      if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);

// Generic rate limiter for the whole API
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Stricter limiter for auth endpoints (brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ================= DATABASE CONNECTION =================
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('[DB] Connected to Multi-Teacher Enterprise DB'))
  .catch((err) => {
    console.error('[DB] Connection error:', err.message);
    process.exit(1);
  });

// ================= SCHEMAS & MODELS =================

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, required: true, trim: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['student', 'teacher', 'super_admin'], default: 'student' },
  grade: { type: String, enum: ['1sec', '2sec', '3sec', null], default: null },
  walletBalance: { type: Number, default: 0, min: 0 },
  isApproved: { type: Boolean, default: true },
  isBlocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

const teacherProfileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  subject: { type: String, required: true, trim: true },
  bio: { type: String, default: '' },
  platformCommissionRate: { type: Number, default: 20, min: 0, max: 100 },
  totalEarnings: { type: Number, default: 0, min: 0 },
});
const TeacherProfile = mongoose.model('TeacherProfile', teacherProfileSchema);

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  subject: { type: String, required: true, trim: true, index: true },
  grade: { type: String, required: true, enum: ['1sec', '2sec', '3sec'], index: true },
  price: { type: Number, required: true, min: 0 },
  videoUrl: { type: String, required: true },
  pdfUrl: { type: String, default: '' },
  teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  isLocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Course = mongoose.model('Course', courseSchema);

const purchaseSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pricePaid: { type: Number, required: true, min: 0 },
  platformFee: { type: Number, required: true, min: 0 },
  teacherNet: { type: Number, required: true, min: 0 },
  purchasedAt: { type: Date, default: Date.now },
});
// A student can only buy the same course once.
purchaseSchema.index({ studentId: 1, courseId: 1 }, { unique: true });
const Purchase = mongoose.model('Purchase', purchaseSchema);

const paymentSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount: { type: Number, required: true, min: 1 },
  senderPhone: { type: String, required: true, trim: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});
const Payment = mongoose.model('Payment', paymentSchema);

const complaintSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  issueType: { type: String, required: true, enum: ['technical', 'academic', 'payment'] },
  teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  details: { type: String, required: true, trim: true, maxlength: 2000 },
  status: { type: String, enum: ['open', 'resolved'], default: 'open' },
  createdAt: { type: Date, default: Date.now },
});
const Complaint = mongoose.model('Complaint', complaintSchema);

const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  content: { type: String, required: true, trim: true },
  targetAudience: { type: String, default: 'all', enum: ['all', '1sec', '2sec', '3sec'] },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
});
const Announcement = mongoose.model('Announcement', announcementSchema);

// ================= HELPERS =================

// Wraps async route handlers so thrown errors reach the centralized error handler
// instead of crashing the process or requiring try/catch in every route.
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Turns express-validator results into a 400 response; place after validation chains.
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
  return { page, limit, skip: (page - 1) * limit };
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
    const { name, email, phone, password, role = 'student', grade, subject } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    // Teachers require manual approval before they can log in.
    const isApproved = role === 'teacher' ? false : true;

    const user = new User({ name, email, phone, password: hashedPassword, role, grade, isApproved });
    await user.save();

    if (role === 'teacher') {
      const teacherProfile = new TeacherProfile({ userId: user._id, subject: subject || 'General' });
      await teacherProfile.save();
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

    // Explicitly select password since the schema excludes it by default.
    const user = await User.findOne({ email }).select('+password');

    // Use a generic message for both "not found" and "wrong password" to avoid
    // leaking which emails are registered.
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.isBlocked) return res.status(403).json({ error: 'Account is suspended' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.isApproved) return res.status(403).json({ error: 'Teacher account pending approval' });

    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, {
      expiresIn: '7d',
    });

    res.json({
      token,
      user: { id: user._id, name: user.name, role: user.role, balance: user.walletBalance },
    });
  })
);

// ================= COURSES ENDPOINTS =================

app.get(
  '/api/courses',
  [
    query('subject').optional().trim(),
    query('grade').optional().isIn(['1sec', '2sec', '3sec']),
    query('teacherId').optional().isMongoId(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { subject, grade, teacherId } = req.query;
    const { page, limit, skip } = paginate(req);

    const filter = {};
    if (subject) filter.subject = subject;
    if (grade) filter.grade = grade;
    if (teacherId) filter.teacherId = teacherId;

    const [courses, total] = await Promise.all([
      Course.find(filter).populate('teacherId', 'name').skip(skip).limit(limit).sort({ createdAt: -1 }),
      Course.countDocuments(filter),
    ]);

    res.json({ data: courses, page, limit, total, totalPages: Math.ceil(total / limit) });
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
    const { title, subject, grade, price, videoUrl, pdfUrl } = req.body;
    const course = new Course({ title, subject, grade, price, videoUrl, pdfUrl, teacherId: req.user.id });
    await course.save();
    res.status(201).json({ message: 'Course created successfully', course });
  })
);

// ================= WALLET & PURCHASES =================

app.post(
  '/api/student/buy-course',
  authenticateToken,
  authorizeRoles('student'),
  [body('courseId').isMongoId().withMessage('Valid courseId required')],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { courseId } = req.body;

    // Wrap the whole debit + ledger + earnings update in a transaction so a
    // failure partway through can never leave the wallet debited without a
    // matching purchase record (or vice versa).
    const session = await mongoose.startSession();
    try {
      let responsePayload;

      await session.withTransaction(async () => {
        const course = await Course.findById(courseId).session(session);
        if (!course) {
          throw Object.assign(new Error('Course not found'), { status: 404 });
        }

        const alreadyOwned = await Purchase.findOne({ studentId: req.user.id, courseId }).session(session);
        if (alreadyOwned) {
          throw Object.assign(new Error('Course already purchased'), { status: 409 });
        }

        // Atomic conditional debit: only succeeds if balance is sufficient,
        // eliminating the race condition of read-then-write.
        const student = await User.findOneAndUpdate(
          { _id: req.user.id, walletBalance: { $gte: course.price } },
          { $inc: { walletBalance: -course.price } },
          { new: true, session }
        );
        if (!student) {
          throw Object.assign(new Error('Insufficient wallet balance'), { status: 400 });
        }

        const teacherProfile = await TeacherProfile.findOne({ userId: course.teacherId }).session(session);
        const commRate = teacherProfile ? teacherProfile.platformCommissionRate : 20;
        const platformFee = Math.round(((course.price * commRate) / 100) * 100) / 100;
        const teacherNet = Math.round((course.price - platformFee) * 100) / 100;

        if (teacherProfile) {
          teacherProfile.totalEarnings += teacherNet;
          await teacherProfile.save({ session });
        }

        await Purchase.create(
          [
            {
              studentId: student._id,
              courseId: course._id,
              teacherId: course.teacherId,
              pricePaid: course.price,
              platformFee,
              teacherNet,
            },
          ],
          { session }
        );

        responsePayload = { message: 'Purchase successful', remainingBalance: student.walletBalance };
      });

      res.json(responsePayload);
    } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message });
      throw err;
    } finally {
      session.endSession();
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
    const payment = new Payment({ studentId: req.user.id, amount, senderPhone });
    await payment.save();
    res.status(201).json({ message: 'Recharge request submitted for review' });
  })
);

// Admin: approve/reject a pending recharge and credit the wallet atomically.
app.put(
  '/api/admin/payments/:id/review',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isMongoId(), body('decision').isIn(['approved', 'rejected'])],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { decision } = req.body;

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const payment = await Payment.findById(req.params.id).session(session);
        if (!payment) throw Object.assign(new Error('Payment not found'), { status: 404 });
        if (payment.status !== 'pending') {
          throw Object.assign(new Error('Payment already reviewed'), { status: 409 });
        }

        payment.status = decision;
        await payment.save({ session });

        if (decision === 'approved') {
          await User.findByIdAndUpdate(
            payment.studentId,
            { $inc: { walletBalance: payment.amount } },
            { session }
          );
        }
      });
      res.json({ message: `Payment ${decision}` });
    } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message });
      throw err;
    } finally {
      session.endSession();
    }
  })
);

// ================= COMPLAINTS & CHATBOT API =================

// Requires auth: studentId always comes from the verified token, never the body,
// so no one can file complaints on another student's behalf.
app.post(
  '/api/complaints',
  authenticateToken,
  authorizeRoles('student'),
  [
    body('issueType').isIn(['technical', 'academic', 'payment']),
    body('details').trim().notEmpty().isLength({ max: 2000 }),
    body('teacherId').optional().isMongoId(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { issueType, details, teacherId } = req.body;
    const complaint = new Complaint({ studentId: req.user.id, issueType, details, teacherId });
    await complaint.save();
    res.status(201).json({ message: 'Complaint submitted successfully' });
  })
);

app.get(
  '/api/complaints',
  authenticateToken,
  authorizeRoles('teacher', 'super_admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = paginate(req);
    const filter = req.user.role === 'teacher' ? { teacherId: req.user.id } : {};

    const [complaints, total] = await Promise.all([
      Complaint.find(filter)
        .populate('studentId', 'name email')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 }),
      Complaint.countDocuments(filter),
    ]);

    res.json({ data: complaints, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

// ================= ANNOUNCEMENTS =================

app.get(
  '/api/announcements',
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = paginate(req);
    const [announcements, total] = await Promise.all([
      Announcement.find().sort({ createdAt: -1 }).skip(skip).limit(limit),
      Announcement.countDocuments(),
    ]);
    res.json({ data: announcements, page, limit, total, totalPages: Math.ceil(total / limit) });
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
    const { title, content, targetAudience } = req.body;
    const announcement = new Announcement({
      title,
      content,
      targetAudience,
      createdBy: req.user.id,
    });
    await announcement.save();
    res.status(201).json({ message: 'Announcement published' });
  })
);

// ================= SUPER ADMIN CONTROLS =================

app.get(
  '/api/admin/users',
  authenticateToken,
  authorizeRoles('super_admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = paginate(req);
    const [users, total] = await Promise.all([
      User.find().skip(skip).limit(limit).sort({ createdAt: -1 }), // password excluded by schema default
      User.countDocuments(),
    ]);
    res.json({ data: users, page, limit, total, totalPages: Math.ceil(total / limit) });
  })
);

app.put(
  '/api/admin/users/block/:id',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isMongoId()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.isBlocked = !user.isBlocked;
    await user.save();
    res.json({ message: `User block status updated to ${user.isBlocked}` });
  })
);

// New: approve a pending teacher account (closes the gap left by the register flow).
app.put(
  '/api/admin/teachers/:id/approve',
  authenticateToken,
  authorizeRoles('super_admin'),
  [param('id').isMongoId()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const user = await User.findOne({ _id: req.params.id, role: 'teacher' });
    if (!user) return res.status(404).json({ error: 'Teacher not found' });

    user.isApproved = true;
    await user.save();
    res.json({ message: 'Teacher approved' });
  })
);

app.get(
  '/api/admin/stats',
  authenticateToken,
  authorizeRoles('super_admin'),
  asyncHandler(async (req, res) => {
    const [totalStudents, totalTeachers, revenueAgg] = await Promise.all([
      User.countDocuments({ role: 'student' }),
      User.countDocuments({ role: 'teacher' }),
      Purchase.aggregate([
        { $group: { _id: null, totalRevenue: { $sum: '$pricePaid' }, platformProfit: { $sum: '$platformFee' } } },
      ]),
    ]);

    res.json({
      totalStudents,
      totalTeachers,
      revenue: revenueAgg[0] || { totalRevenue: 0, platformProfit: 0 },
    });
  })
);

// ================= 404 + CENTRALIZED ERROR HANDLING =================

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Must be declared last, with 4 args, for Express to treat it as an error handler.
// Never leaks stack traces or raw DB error messages to the client.
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: 'Invalid data provided' });
  }
  if (err.code === 11000) {
    return res.status(409).json({ error: 'Duplicate entry' });
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
    await mongoose.connection.close();
    console.log('[SERVER] Closed all connections. Exiting.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
