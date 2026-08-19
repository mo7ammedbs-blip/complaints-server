require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function createAdmin() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME,
  });

  const email = 'admin@hawash.com';
  const plainPassword = 'adminpassword123'; // دي كلمة السر اللي هتدخل بيها
  const hashedPassword = await bcrypt.hash(plainPassword, 12);

  // حذف الحساب القديم لو موجود عشان نجدده
  await connection.query('DELETE FROM users WHERE email = ?', [email]);

  // إنشاء حساب الأدمن الجديد
  await connection.query(
    `INSERT INTO users (name, email, phone, password, role, is_approved, is_blocked) 
     VALUES (?, ?, ?, ?, 'super_admin', 1, 0)`,
    ['Super Admin', email, '01000000000', hashedPassword]
  );

  console.log('✅ تم إنشاء حساب الأدمن بنجاح!');
  console.log('📧 البريد:', email);
  console.log('🔑 كلمة السر:', plainPassword);

  await connection.end();
}

createAdmin().catch(console.error);