cat > /mnt/user-data/outputs/server.js << 'ENDOFFILE'
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

// ✅ إنشاء الجداول عند تشغيل السيرفر
db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        grade VARCHAR(10) NOT NULL,
        is_blocked TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => {
    if (err) console.error('❌ خطأ في إنشاء جدول users:', err);
    else console.log('✅ جدول users جاهز!');
});

db.query(`
    CREATE TABLE IF NOT EXISTS complaints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_name VARCHAR(255) NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        complaint_type VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`, (err) => {
    if (err) console.error('❌ خطأ في إنشاء جدول complaints:', err);
    else console.log('✅ جدول complaints جاهز!');
});

// =============================
// 👤 APIs الطلاب
// =============================

// تسجيل طالب جديد
app.post('/api/register', (req, res) => {
    const { name, email, password, phone, grade } = req.body;

    if (!name || !email || !password || !grade) {
        return res.status(400).json({ success: false, error: 'جميع الحقول مطلوبة' });
    }

    db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        if (results.length > 0) return res.status(400).json({ success: false, error: 'البريد الإلكتروني مسجل مسبقاً' });

        db.query(
            'INSERT INTO users (name, email, password, phone, grade) VALUES (?, ?, ?, ?, ?)',
            [name, email, password, phone || '', grade],
            (err, result) => {
                if (err) return res.status(500).json({ success: false, error: 'خطأ في حفظ البيانات' });
                res.status(200).json({
                    success: true,
                    message: 'تم التسجيل بنجاح!',
                    user: { id: result.insertId, name, email, phone, grade, is_blocked: 0 }
                });
            }
        );
    });
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'ادخل الإيميل وكلمة السر' });
    }

    db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, password], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        if (results.length === 0) return res.status(401).json({ success: false, error: 'الإيميل أو كلمة السر غلط' });

        const user = results[0];
        if (user.is_blocked) return res.status(403).json({ success: false, error: 'تم حظر حسابك! تواصل مع الإدارة.' });

        res.status(200).json({
            success: true,
            user: { id: user.id, name: user.name, email: user.email, phone: user.phone, grade: user.grade, is_blocked: user.is_blocked }
        });
    });
});

// =============================
// 📢 API الشكاوى
// =============================

app.post('/api/complaints', (req, res) => {
    const { student_name, phone_number, complaint_type, details } = req.body;

    if (!student_name || !phone_number || !complaint_type || !details) {
        return res.status(400).json({ success: false, error: 'جميع الحقول مطلوبة' });
    }

    db.query(
        'INSERT INTO complaints (student_name, phone_number, complaint_type, details) VALUES (?, ?, ?, ?)',
        [student_name, phone_number, complaint_type, details],
        (err, result) => {
            if (err) {
                console.error('❌ خطأ في حفظ الشكوى:', err);
                return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
            }
            console.log('✅ تم حفظ الشكوى!');
            res.status(200).json({ success: true, message: 'تم حفظ الشكوى بنجاح!' });
        }
    );
});

// =============================
// 👑 APIs المستر (لوحة التحكم)
// =============================

// التحقق من كلمة سر المستر
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === 'MmAa@2006Rr') {
        res.status(200).json({ success: true, message: 'أهلاً يا مستر! 👑' });
    } else {
        res.status(401).json({ success: false, error: 'كلمة السر غلط!' });
    }
});

// جلب كل الطلاب مقسمين على الصفوف
app.get('/api/admin/users', (req, res) => {
    const { password } = req.headers;
    if (password !== 'MmAa@2006Rr') return res.status(401).json({ success: false, error: 'غير مصرح' });

    db.query('SELECT id, name, email, phone, grade, is_blocked, created_at FROM users ORDER BY grade, name', (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });

        const grade1 = results.filter(u => u.grade === '1');
        const grade2 = results.filter(u => u.grade === '2');
        const grade3 = results.filter(u => u.grade === '3');

        res.status(200).json({ success: true, grade1, grade2, grade3, total: results.length });
    });
});

// جلب كل الشكاوى
app.get('/api/admin/complaints', (req, res) => {
    const { password } = req.headers;
    if (password !== 'MmAa@2006Rr') return res.status(401).json({ success: false, error: 'غير مصرح' });

    db.query('SELECT * FROM complaints ORDER BY created_at DESC', (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        res.status(200).json({ success: true, complaints: results });
    });
});

// بلوك / فك بلوك طالب
app.post('/api/admin/block', (req, res) => {
    const { password } = req.headers;
    if (password !== 'MmAa@2006Rr') return res.status(401).json({ success: false, error: 'غير مصرح' });

    const { userId, block } = req.body;
    db.query('UPDATE users SET is_blocked = ? WHERE id = ?', [block ? 1 : 0, userId], (err) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        res.status(200).json({ success: true, message: block ? 'تم حظر الطالب!' : 'تم فك الحظر!' });
    });
});

// حذف طالب
app.delete('/api/admin/user/:id', (req, res) => {
    const { password } = req.headers;
    if (password !== 'MmAa@2006Rr') return res.status(401).json({ success: false, error: 'غير مصرح' });

    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        res.status(200).json({ success: true, message: 'تم حذف الطالب!' });
    });
});

// حذف شكوى
app.delete('/api/admin/complaint/:id', (req, res) => {
    const { password } = req.headers;
    if (password !== 'MmAa@2006Rr') return res.status(401).json({ success: false, error: 'غير مصرح' });

    db.query('DELETE FROM complaints WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false, error: 'خطأ في السيرفر' });
        res.status(200).json({ success: true, message: 'تم حذف الشكوى!' });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 السيرفر شغال على http://localhost:${PORT}`);
});
ENDOFFILE