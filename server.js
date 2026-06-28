const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

// تفعيل الـ CORS والـ JSON لاستقبال البيانات من المتصفح بدون مشاكل
app.use(cors());
app.use(express.json());

// ✅ استخدام Pool بدل Connection عشان يتعامل مع انقطاع الاتصال أحسن
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

// إنشاء الجدول لو مش موجود
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
    if (err) {
        console.error('❌ خطأ أثناء إنشاء الجدول:', err);
    } else {
        console.log('✅ جدول الشكاوى جاهز في السحاب!');
    }
});

// استقبال الشكاوى من الشات بوت وحفظها في السحاب
app.post('/api/complaints', (req, res) => {
    const { student_name, phone_number, complaint_type, details } = req.body;

    if (!student_name || !phone_number || !complaint_type || !details) {
        return res.status(400).json({ success: false, error: 'جميع الحقول مطلوبة' });
    }

    const query = `INSERT INTO complaints (student_name, phone_number, complaint_type, details) VALUES (?, ?, ?, ?)`;

    db.query(query, [student_name, phone_number, complaint_type, details], (err, result) => {
        if (err) {
            console.error('❌ خطأ أثناء إدخال البيانات في السحاب:', err);
            return res.status(500).json({ success: false, error: 'حدث خطأ في السيرفر السحابي' });
        }
        console.log('✅ تم حفظ الشكوى بنجاح!');
        res.status(200).json({ success: true, message: 'تم حفظ الشكوى في قاعدة البيانات السحابية بنجاح!' });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 السيرفر شغال دلوقتي على http://localhost:${PORT}`);
});
