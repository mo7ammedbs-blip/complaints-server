// /mnt/user-data/outputs/server.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// ✅ Pool للاتصال بقاعدة البيانات
const db = mysql.createPool({
    host: 'reseau.proxy.rlwy.net',
    user: 'root',
    password: 'mVjSESClfSKBoVtUNvNQhgkxPeXdYJEF',
    database: 'railway',
    port: 17918,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ✅ إنشاء وتحديث الجداول عند تشغيل السيرفر
db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        grade VARCHAR(10) NOT NULL,
        wallet_balance DECIMAL(10,2) DEFAULT 0.00,
        is_blocked TINYINT(1) DEFAULT 0,
        last_login TIMESTAMP NULL,
        is_online TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول users:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS complaints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_name VARCHAR(255) NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        complaint_type VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول complaints:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS courses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        video_url TEXT NOT NULL,
        pdf_url TEXT,
        price DECIMAL(10,2) DEFAULT 0.00,
        grade VARCHAR(10) NOT NULL,
        is_locked TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول courses:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS deposit_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        student_name VARCHAR(255) NOT NULL,
        wallet_number VARCHAR(20) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول deposit_requests:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS exams (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        grade VARCHAR(10) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول exams:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS questions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        exam_id INT NOT NULL,
        question_text TEXT NOT NULL,
        option_a VARCHAR(255) NOT NULL,
        option_b VARCHAR(255) NOT NULL,
        option_c VARCHAR(255) NOT NULL,
        option_d VARCHAR(255) NOT NULL,
        correct_option VARCHAR(1) NOT NULL,
        FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول questions:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS exam_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        student_name VARCHAR(255),
        exam_id INT NOT NULL,
        exam_title VARCHAR(255),
        score INT NOT NULL,
        total_questions INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول exam_results:', err); });

db.query(`
    CREATE TABLE IF NOT EXISTS announcements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        target_grade VARCHAR(10) DEFAULT 'all', -- all, 1, 2, 3
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول announcements:', err); });


// ==========================================
// 👤 خدمات الطلاب (Student APIs)
// ==========================================

// تسجيل طالب جديد
app.post('/api/register', (req, res) => {
    const { name, email, password, phone, grade } = req.body;
    if (!name || !email || !password || !grade) return res.status(400).json({ success: false, error: 'جميع الحقول مطلوبة' });

    db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        if (results.length > 0) return res.status(400).json({ success: false, error: 'البريد الإلكتروني مسجل مسبقاً' });

        db.query('INSERT INTO users (name, email, password, phone, grade, is_online, last_login) VALUES (?, ?, ?, ?, ?, 1, NOW())',
            [name, email, password, phone || '', grade], (err, result) => {
                if (err) return res.status(500).json({ success: false, error: 'خطأ في حفظ البيانات' });
                res.status(200).json({ success: true, user: { id: result.insertId, name, email, phone, grade, wallet_balance: 0, is_blocked: 0 } });
            });
    });
});

// تسجيل الدخول تحديث حالة النشاط
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        if (results.length === 0) return res.status(401).json({ success: false, error: 'الإيميل أو كلمة السر غلط' });

        const user = results[0];
        if (user.is_blocked) return res.status(403).json({ success: false, error: 'تم حظر حسابك! تواصل مع الإدارة.' });

        db.query('UPDATE users SET is_online = 1, last_login = NOW() WHERE id = ?', [user.id]);
        res.status(200).json({ success: true, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, grade: user.grade, wallet_balance: user.wallet_balance, is_blocked: user.is_blocked } });
    });
});

// تسجيل خروج الطالب
app.post('/api/logout', (req, res) => {
    const { userId } = req.body;
    db.query('UPDATE users SET is_online = 0 WHERE id = ?', [userId], () => {
        res.json({ success: true });
    });
});

// طلب شحن رصيد من الطالب
app.post('/api/wallet/deposit', (req, res) => {
    const { userId, studentName, walletNumber, amount } = req.body;
    db.query('INSERT INTO deposit_requests (user_id, student_name, wallet_number, amount) VALUES (?, ?, ?, ?)', 
    [userId, studentName, walletNumber, amount], (err) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        res.json({ success: true, message: 'تم إرسال طلب الشحن بنجاح وفي انتظار موافقة المستر!' });
    });
});

// جلب الإعلانات والكورسات والامتحانات الخاصة بصف الطالب
app.get('/api/student/data/:grade/:userId', (req, res) => {
    const { grade, userId } = req.params;
    db.query('SELECT wallet_balance FROM users WHERE id = ?', [userId], (err, userRes) => {
        const balance = userRes[0] ? userRes[0].wallet_balance : 0;
        
        db.query('SELECT * FROM courses WHERE grade = ?', [grade], (err, courses) => {
            db.query('SELECT * FROM exams WHERE grade = ?', [grade], (err, exams) => {
                db.query('SELECT * FROM announcements WHERE target_grade = ? OR target_grade = "all" ORDER BY created_at DESC', [grade], (err, announcements) => {
                    db.query('SELECT * FROM exam_results WHERE user_id = ?', [userId], (err, results) => {
                        res.json({ success: true, wallet_balance: balance, courses, exams, announcements, exam_results: results });
                    });
                });
            });
        });
    });
});

// جلب أسئلة امتحان معين للطالب
app.get('/api/exams/:id/questions', (req, res) => {
    db.query('SELECT id, question_text, option_a, option_b, option_c, option_d FROM questions WHERE exam_id = ?', [req.params.id], (err, results) => {
        res.json({ success: true, questions: results });
    });
});

// تسليم نموذج إجابة الامتحان وحفظ النتيجة
app.post('/api/exams/submit', (req, res) => {
    const { userId, studentName, examId, examTitle, answers } = req.body;
    db.query('SELECT * FROM questions WHERE exam_id = ?', [examId], (err, questions) => {
        let score = 0;
        questions.forEach(q => {
            if (answers[q.id] === q.correct_option) score++;
        });
        db.query('INSERT INTO exam_results (user_id, student_name, exam_id, exam_title, score, total_questions) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, studentName, examId, examTitle, score, questions.length], () => {
            res.json({ success: true, score, total: questions.length });
        });
    });
});

// تقديم شكوى (الشات بوت)
app.post('/api/complaints', (req, res) => {
    const { student_name, phone_number, complaint_type, details } = req.body;
    db.query('INSERT INTO complaints (student_name, phone_number, complaint_type, details) VALUES (?, ?, ?, ?)',
        [student_name, phone_number, complaint_type, details], () => {
            res.status(200).json({ success: true });
        });
});


// ==========================================
// 👑 خدمات لوحة تحكم المستر (Admin APIs)
// ==========================================

const ADMIN_PASS = 'MmAa@2006Rr';
const checkAdmin = (req, res, next) => {
    if (req.headers.password !== ADMIN_PASS) return res.status(401).json({ success: false, error: 'غير مصرح' });
    next();
};

app.post('/api/admin/login', (req, res) => {
    if (req.body.password === ADMIN_PASS) res.json({ success: true });
    else res.status(401).json({ success: false, error: 'كلمة السر غلط!' });
});

// لوحة التحكم الرئيسية: الإحصائيات الشاملة والطلاب والشكاوى
app.get('/api/admin/dashboard', checkAdmin, (req, res) => {
    db.query('SELECT id, name, email, phone, grade, wallet_balance, is_blocked, last_login, is_online FROM users', (err, users) => {
        db.query('SELECT * FROM complaints ORDER BY created_at DESC', (err, complaints) => {
            db.query('SELECT * FROM deposit_requests WHERE status = "pending"', (err, deposits) => {
                db.query('SELECT IFNULL(SUM(amount), 0) as total FROM deposit_requests WHERE status = "approved"', (err, profit) => {
                    res.json({
                        success: true,
                        users,
                        complaints,
                        pending_deposits: deposits,
                        stats: {
                            total_students: users.length,
                            online_students: users.filter(u => u.online).length,
                            total_earnings: profit[0].total,
                            total_complaints: complaints.length
                        }
                    });
                });
            });
        });
    });
});

// التحكم بالطلاب (بلوك، حذف، تعديل بيانات، إضافة/خصم رصيد)
app.post('/api/admin/students/action', checkAdmin, (req, res) => {
    const { action, userId, amount, name, phone, email, password } = req.body;
    if (action === 'block') {
        db.query('UPDATE users SET is_blocked = 1, is_online = 0 WHERE id = ?', [userId]);
    } else if (action === 'unblock') {
        db.query('UPDATE users SET is_blocked = 0 WHERE id = ?', [userId]);
    } else if (action === 'add_balance') {
        db.query('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', [amount, userId]);
    } else if (action === 'sub_balance') {
        db.query('UPDATE users SET wallet_balance = GREATEST(0, wallet_balance - ?) WHERE id = ?', [amount, userId]);
    } else if (action === 'update') {
        db.query('UPDATE users SET name=?, phone=?, email=?, password=? WHERE id=?', [name, phone, email, password, userId]);
    }
    res.json({ success: true, message: 'تم تنفيذ العملية بنجاح' });
});

app.delete('/api/admin/students/:id', checkAdmin, (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], () => res.json({ success: true }));
});

// إدارة طلبات شحن المحفظة (موافقة / رفض)
app.post('/api/admin/deposits/handle', checkAdmin, (req, res) => {
    const { requestId, status } = req.body;
    db.query('SELECT * FROM deposit_requests WHERE id = ?', [requestId], (err, reqRes) => {
        if (!reqRes[0] || reqRes[0].status !== 'pending') return res.json({ success: false, error: 'الطلب معالج مسبقاً' });
        const request = reqRes[0];
        
        db.query('UPDATE deposit_requests SET status = ? WHERE id = ?', [status, requestId], () => {
            if (status === 'approved') {
                db.query('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?', [request.amount, request.user_id], () => {
                    res.json({ success: true, message: 'تمت الموافقة وشحن الحساب!' });
                });
            } else {
                res.json({ success: true, message: 'تم رفض طلب الشحن!' });
            }
        });
    });
});

// إدارة المحاضرات (إضافة، حذف)
app.post('/api/admin/courses', checkAdmin, (req, res) => {
    const { title, video_url, pdf_url, price, grade } = req.body;
    db.query('INSERT INTO courses (title, video_url, pdf_url, price, grade) VALUES (?, ?, ?, ?, ?)', [title, video_url, pdf_url, price, grade], () => {
        res.json({ success: true });
    });
});

app.delete('/api/admin/courses/:id', checkAdmin, (req, res) => {
    db.query('DELETE FROM courses WHERE id = ?', [req.params.id], () => res.json({ success: true }));
});

// إدارة الامتحانات (إنشاء امتحان، إضافة أسئلة، رؤية درجات الطلاب)
app.post('/api/admin/exams', checkAdmin, (req, res) => {
    const { title, grade, questions } = req.body;
    db.query('INSERT INTO exams (title, grade) VALUES (?, ?)', [title, grade], (err, result) => {
        const examId = result.insertId;
        const qQueries = questions.map(q => {
            return new Promise((resolve) => {
                db.query('INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?,?,?,?,?,?,?)',
                [examId, q.text, q.a, q.b, q.c, q.d, q.correct], resolve);
            });
        });
        Promise.all(qQueries).then(() => res.json({ success: true }));
    });
});

app.get('/api/admin/exams/results', checkAdmin, (req, res) => {
    db.query('SELECT * FROM exam_results ORDER BY created_at DESC', (err, results) => {
        res.json({ success: true, results });
    });
});

app.delete('/api/admin/exams/:id', checkAdmin, (req, res) => {
    db.query('DELETE FROM exams WHERE id = ?', [req.params.id], () => res.json({ success: true }));
});

// إدارة الإعلانات
app.post('/api/admin/announcements', checkAdmin, (req, res) => {
    const { title, content, target_grade } = req.body;
    db.query('INSERT INTO announcements (title, content, target_grade) VALUES (?, ?, ?)', [title, content, target_grade], () => {
        res.json({ success: true });
    });
});

app.delete('/api/admin/complaints/:id', checkAdmin, (req, res) => {
    db.query('DELETE FROM complaints WHERE id = ?', [req.params.id], () => res.json({ success: true }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 السيرفر جاهز وشغال بالكامل على بورت ${PORT}`));