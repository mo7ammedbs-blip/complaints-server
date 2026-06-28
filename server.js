const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// ✅ Pool للاتصال بقاعدة بيانات Railway الحقيقية الخاصة بك
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

// ==========================================
// 🏗️ إنشاء الجداول تلقائياً (الطلاب، الشكاوى، المحاضرات، المدفوعات، الإعلانات)
// ==========================================

db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        grade VARCHAR(10) NOT NULL,
        wallet INT DEFAULT 0,
        courses TEXT, 
        scores TEXT,
        is_blocked TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول users:', err); else console.log('✅ جدول users جاهز!'); });

db.query(`
    CREATE TABLE IF NOT EXISTS complaints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_name VARCHAR(255) NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        complaint_type VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول complaints:', err); else console.log('✅ جدول complaints جاهز!'); });

db.query(`
    CREATE TABLE IF NOT EXISTS courses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        price INT DEFAULT 0,
        grade VARCHAR(10) NOT NULL,
        videoUrl TEXT,
        pdfUrl TEXT,
        locked TINYINT(1) DEFAULT 0
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول courses:', err); else console.log('✅ جدول courses جاهز!'); });

db.query(`
    CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        studentId INT NOT NULL,
        studentName VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        amount INT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول payments:', err); else console.log('✅ جدول payments جاهز!'); });

db.query(`
    CREATE TABLE IF NOT EXISTS announcements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        text TEXT NOT NULL,
        target VARCHAR(10) DEFAULT 'all',
        active TINYINT(1) DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => { if (err) console.error('❌ خطأ في جدول announcements:', err); else console.log('✅ جدول announcements جاهز!'); });


// ==========================================
// 👤 بوابة الطلاب (Auth & Management)
// ==========================================

// تسجيل طالب جديد
app.post('/api/auth/register', (req, res) => {
    const { name, email, password, phone, grade } = req.body;
    db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'خطأ في السيرفر' });
        if (results.length > 0) return res.status(400).json({ message: 'البريد الإلكتروني مسجل مسبقاً' });

        db.query(
            'INSERT INTO users (name, email, password, phone, grade, wallet, courses, scores) VALUES (?, ?, ?, ?, ?, 0, "[]", "[]")',
            [name, email, password, phone || '', grade],
            (err, result) => {
                if (err) return res.status(500).json({ message: 'خطأ في حفظ البيانات' });
                res.status(200).json({
                    _id: result.insertId, name, email, phone, grade, wallet: 0, courses: [], scores: [], blocked: 0
                });
            }
        );
    });
});

// تسجيل الدخول
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password], (err, results) => {
        if (err) return res.status(500).json({ message: 'خطأ في السيرفر' });
        if (results.length === 0) return res.status(401).json({ message: 'الإيميل أو كلمة السر خطأ' });

        const user = results[0];
        res.status(200).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            grade: user.grade,
            wallet: user.wallet,
            courses: JSON.parse(user.courses || "[]"),
            scores: JSON.parse(user.scores || "[]"),
            blocked: user.is_blocked
        });
    });
});

app.post('/api/auth/logout', (req, res) => {
    res.status(200).json({ success: true });
});

// ==========================================
// 🎥 بوابة المحاضرات والكورسات
// ==========================================

// جلب كل الكورسات للمنصة
app.get('/api/courses', (req, res) => {
    db.query('SELECT id AS _id, title, price, grade, videoUrl, pdfUrl, locked FROM courses', (err, results) => {
        if (err) return res.status(500).json([]);
        const mapped = results.map(c => ({...c, locked: !!c.locked}));
        res.status(200).json(mapped);
    });
});

// شراء/تفعيل كورس لطالب
app.post('/api/courses/activate', (req, res) => {
    const { studentId, courseId, price } = req.body;
    db.query('SELECT * FROM users WHERE id = ?', [studentId], (err, users) => {
        if (err || users.length === 0) return res.status(404).json({ message: 'الطالب غير موجود' });
        const user = users[0];
        if (user.wallet < price) return res.status(400).json({ message: 'الرصيد غير كافٍ' });

        let currentCourses = JSON.parse(user.courses || "[]");
        if (!currentCourses.includes(courseId)) {
            currentCourses.push(courseId);
        }

        const newWallet = user.wallet - price;
        db.query('UPDATE users SET wallet = ?, courses = ? WHERE id = ?', [newWallet, JSON.stringify(currentCourses), studentId], (err) => {
            if (err) return res.status(500).json({ message: 'خطأ أثناء التفعيل' });
            res.status(200).json({
                _id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                grade: user.grade,
                wallet: newWallet,
                courses: currentCourses,
                scores: JSON.parse(user.scores || "[]"),
                blocked: user.is_blocked
            });
        });
    });
});

// ==========================================
// 💳 بوابة شحن المحفظة (فودافون كاش)
// ==========================================

app.post('/api/payments/deposit', (req, res) => {
    const { studentId, studentName, phone, amount } = req.body;
    db.query('INSERT INTO payments (studentId, studentName, phone, amount, status) VALUES (?, ?, ?, ?, "pending")',
    [studentId, studentName, phone, amount], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// ==========================================
// 📬 بوابة الشكاوى والبلاغات
// ==========================================

app.post('/api/complaints', (req, res) => {
    const { student_name, phone_number, details } = req.body;
    db.query('INSERT INTO complaints (student_name, phone_number, complaint_type, details) VALUES (?, ?, "عامة", ?)',
    [student_name, phone_number, details], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

app.get('/api/complaints', (req, res) => {
    db.query('SELECT id AS _id, student_name, phone_number, details FROM complaints ORDER BY created_at DESC', (err, results) => {
        if (err) return res.status(500).json([]);
        res.status(200).json(results);
    });
});

app.delete('/api/complaints/:id', (req, res) => {
    db.query('DELETE FROM complaints WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// ==========================================
// 📢 بوابة الإعلانات
// ==========================================

app.get('/api/announcements/active', (req, res) => {
    db.query('SELECT text FROM announcements WHERE active = 1 ORDER BY id DESC LIMIT 1', (err, results) => {
        if (err || results.length === 0) return res.status(404).json(null);
        res.status(200).json(results[0]);
    });
});

app.post('/api/announcements', (req, res) => {
    const { text, target } = req.body;
    db.query('UPDATE announcements SET active = 0', () => {
        db.query('INSERT INTO announcements (text, target, active) VALUES (?, ?, 1)', [text, target], (err) => {
            if (err) return res.status(500).json({ success: false });
            res.status(200).json({ success: true });
        });
    });
});

// ==========================================
// 👑 لوحة تحكم المستر أحمد هواش (Admin APIs)
// ==========================================

// الإحصائيات العامة
app.get('/api/admin/stats', (req, res) => {
    db.query('SELECT COUNT(*) AS total FROM users', (err, uRes) => {
        db.query('SELECT SUM(amount) AS total_rev FROM payments WHERE status = "approved"', (err, pRes) => {
            db.query('SELECT COUNT(*) AS total_comp FROM complaints', (err, cRes) => {
                db.query('SELECT grade, COUNT(*) AS count FROM users GROUP BY grade', (err, gRes) => {
                    let stats = {
                        totalStudents: uRes ? uRes[0].total : 0,
                        revenue: (pRes && pRes[0].total_rev) ? pRes[0].total_rev : 0,
                        complaints: cRes ? cRes[0].total_comp : 0,
                        grade1: 0, grade2: 0, grade3: 0
                    };
                    if (gRes) {
                        gRes.forEach(r => {
                            if(r.grade === '1') stats.grade1 = r.count;
                            if(r.grade === '2') stats.grade2 = r.count;
                            if(r.grade === '3') stats.grade3 = r.count;
                        });
                    }
                    res.status(200).json(stats);
                });
            });
        });
    });
});

// جلب كل الطلاب لإدارتهم
app.get('/api/admin/students', (req, res) => {
    db.query('SELECT id AS _id, name, email, phone, grade, wallet, is_blocked AS blocked FROM users', (err, results) => {
        if (err) return res.status(500).json([]);
        res.status(200).json(results);
    });
});

// تعديل محفظة طالب
app.put('/api/admin/students/:id/wallet', (req, res) => {
    db.query('UPDATE users SET wallet = ? WHERE id = ?', [req.body.wallet, req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// حظر / فك حظر طالب
app.put('/api/admin/students/:id/block', (req, res) => {
    db.query('UPDATE users SET is_blocked = ? WHERE id = ?', [req.body.blocked ? 1 : 0, req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// حذف طالب نهائياً
app.delete('/api/admin/students/:id', (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// رفع محاضرة جديدة من المستر
app.post('/api/courses', (req, res) => {
    const { title, price, grade, videoUrl, pdfUrl } = req.body;
    db.query('INSERT INTO courses (title, price, grade, videoUrl, pdfUrl, locked) VALUES (?, ?, ?, ?, ?, 0)',
    [title, price, grade, videoUrl, pdfUrl], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// تعديل سعر حصة
app.put('/api/courses/:id/price', (req, res) => {
    db.query('UPDATE courses SET price = ? WHERE id = ?', [req.body.price, req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// قفل / فتح حصة
app.put('/api/courses/:id/lock', (req, res) => {
    db.query('UPDATE courses SET locked = ? WHERE id = ?', [req.body.locked ? 1 : 0, req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// حذف كورس
app.delete('/api/courses/:id', (req, res) => {
    db.query('DELETE FROM courses WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.status(200).json({ success: true });
    });
});

// جلب طلبات شحن المحفظة المعلقة
app.get('/api/admin/payments/pending', (req, res) => {
    db.query('SELECT id AS _id, studentName, phone, amount FROM payments WHERE status = "pending"', (err, results) => {
        if (err) return res.status(500).json([]);
        res.status(200).json(results);
    });
});

// قبول أو رفض طلبات شحن الرصيد
app.post('/api/admin/payments/:id/decision', (req, res) => {
    const { approve } = req.body;
    const status = approve ? 'approved' : 'rejected';
    
    db.query('SELECT * FROM payments WHERE id = ?', [req.params.id], (err, pRes) => {
        if (err || pRes.length === 0) return res.status(404).json({ success: false });
        const payment = pRes[0];

        db.query('UPDATE payments SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
            if (!approve) return res.status(200).json({ success: true });

            // إذا تمت الموافقة، نزود رصيد محفظة الطالب مباشرة في الـ Database
            db.query('UPDATE users SET wallet = wallet + ? WHERE id = ?', [payment.amount, payment.studentId], (err) => {
                res.status(200).json({ success: true });
            });
        });
    });
});

// إنشاء اختبار سريع
app.post('/api/admin/exams', (req, res) => {
    res.status(200).json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 السيرفر المطور شغال بكفاءة ومتوافق تماماً على المنفذ: ${PORT}`);
});