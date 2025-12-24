// File: src/server.js (COMPLETE - PostgreSQL ready, legacy expiry removed, Aziman branding)
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const xlsx = require('xlsx');
const multer = require('multer');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend.onrender.com'] 
    : 'http://localhost:3000',
  credentials: true
}));

// PostgreSQL Connection (Render uses DATABASE_URL)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

(async () => {
  try {
    await db.connect();
    console.log('✅ PostgreSQL Connected Successfully');
  } catch (err) {
    console.error('❌ PostgreSQL Connection Failed:', err);
    process.exit(1);
  }
})();

const upload = multer({ dest: 'uploads/' });

// === MIDDLEWARE ===
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Invalid/expired token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin access required' });
  next();
};

// === LOGIN ===
app.post('/login', [
  body('username').trim().notEmpty(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ msg: 'Invalid input' });

  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ msg: 'Invalid credentials' });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: user.role });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// === CHANGE PASSWORD ===
app.post('/change-password', auth, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 4 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ msg: 'Invalid input' });

  const { currentPassword, newPassword } = req.body;
  try {
    const result = await db.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(400).json({ msg: 'User not found' });

    const isMatch = await bcrypt.compare(currentPassword, result.rows[0].password);
    if (!isMatch) return res.status(400).json({ msg: 'Current password incorrect' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, req.user.id]);
    res.json({ msg: 'Password updated successfully' });
  } catch (err) {
    console.error('CHANGE PASSWORD ERROR:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// === GET ITEMS (by reminder_type) ===
app.get('/items', auth, async (req, res) => {
  const { type } = req.query;
  let query = `
    SELECT 
      id, item_name, type, subtype, category, serial, firmware, estimating_costing,
      for_by, pic, pic_contact, pic_email,
      last_renewal_date, next_due_date, reminder_type
    FROM items
  `;
  const params = [];
  if (type) {
    query += ' WHERE reminder_type = $1';
    params.push(type);
  }
  query += ' ORDER BY next_due_date ASC';

  try {
    const result = await db.query(query, params);
    const items = result.rows.map(calculateDerivedFields);
    res.json(items);
  } catch (err) {
    console.error('GET ITEMS ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

// === CREATE ITEM ===
app.post('/items', [auth, adminOnly], [
  body('item_name').trim().notEmpty(),
  body('reminder_type').isIn(['calibration', 'license']),
  body('next_due_date').isDate().withMessage('Invalid due date')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const item = req.body;
  const today = new Date().toISOString().split('T')[0];

  const newItem = {
    item_name: item.item_name.trim(),
    type: item.type || '',
    subtype: item.subtype || '',
    category: item.category || '',
    serial: item.serial || '',
    firmware: item.firmware || '',
    estimating_costing: parseFloat(item.estimating_costing) || 0,
    for_by: item.for_by || '',
    pic: item.pic || '',
    pic_contact: item.pic_contact || '',
    pic_email: item.pic_email || '',
    last_renewal_date: today,
    next_due_date: item.next_due_date,
    reminder_type: item.reminder_type
  };

  try {
    const keys = Object.keys(newItem);
    const values = Object.values(newItem);
    const placeholders = keys.map((_, i) => `$${i+1}`).join(', ');
    const queryText = `INSERT INTO items (${keys.join(', ')}) VALUES (${placeholders}) RETURNING id`;

    const result = await db.query(queryText, values);
    const insertId = result.rows[0].id;

    console.log('✅ Created item ID:', insertId);
    res.json({ id: insertId, msg: 'Item created successfully!' });
  } catch (err) {
    console.error('CREATE ITEM ERROR:', err);
    res.status(500).json({ error: 'Failed to create item', details: err.message });
  }
});

// === UPDATE ITEM ===
app.put('/items/:id', [auth, adminOnly], async (req, res) => {
  const id = parseInt(req.params.id);
  const item = req.body;

  const updatedItem = {
    item_name: item.item_name?.trim() || 'Unknown Item',
    type: item.type || '',
    subtype: item.subtype || '',
    category: item.category || '',
    serial: item.serial || '',
    firmware: item.firmware || '',
    estimating_costing: parseFloat(item.estimating_costing) || 0,
    for_by: item.for_by || '',
    pic: item.pic || '',
    pic_contact: item.pic_contact || '',
    pic_email: item.pic_email || '',
    last_renewal_date: item.last_renewal_date 
      ? new Date(item.last_renewal_date).toISOString().split('T')[0] 
      : new Date().toISOString().split('T')[0],
    next_due_date: item.next_due_date,
    reminder_type: item.reminder_type || 'calibration'
  };

  try {
    const keys = Object.keys(updatedItem);
    const values = Object.values(updatedItem);
    const setClause = keys.map((k, i) => `${k} = $${i+1}`).join(', ');
    const queryText = `UPDATE items SET ${setClause} WHERE id = $${keys.length + 1} RETURNING id`;

    const result = await db.query(queryText, [...values, id]);

    if (result.rowCount === 0) return res.status(404).json({ error: 'Item not found' });

    console.log('✅ Updated item ID:', id);
    res.json({ msg: 'Item updated successfully!', id });
  } catch (err) {
    console.error('UPDATE ITEM ERROR:', err);
    res.status(500).json({ error: 'Failed to update', details: err.message });
  }
});

// === DELETE ITEM ===
app.delete('/items/:id', [auth, adminOnly], async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    await db.query('DELETE FROM item_reminders WHERE item_id = $1', [id]);
    const result = await db.query('DELETE FROM items WHERE id = $1', [id]);

    if (result.rowCount === 0) return res.status(404).json({ error: 'Item not found' });

    console.log('✅ Deleted item ID:', id);
    res.json({ msg: 'Item deleted successfully' });
  } catch (err) {
    console.error('DELETE ERROR:', err);
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// === SEND REMINDER NOW ===
app.post('/send-now/:id', [auth, adminOnly], async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const result = await db.query(`
      SELECT id, item_name, type, serial, pic_email, next_due_date, reminder_type
      FROM items WHERE id = $1
    `, [id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
    const item = result.rows[0];

    const emails = (item.pic_email || '').split(',').map(e => e.trim()).filter(Boolean);
    if (emails.length === 0) return res.status(400).json({ error: 'No valid emails found' });

    const typeLabel = item.reminder_type === 'license' ? 'License' : 'Calibration';
    const message = `
🚨 Aziman ${typeLabel} REMINDER ALERT 🚨

📋 Item: ${item.item_name}
🔢 Serial: ${item.serial || 'N/A'}
🏷️ Type: ${item.type || 'N/A'}

📅 Due Date: ${item.next_due_date}

⚠️ Action Required: Please renew this ${typeLabel.toLowerCase()} before the due date.

Thank you!
👨‍💼 Aziman Reminder System
    `.trim();

    await transporter.sendMail({
      from: `"Aziman Reminder System" <${process.env.EMAIL_USER}>`,
      to: emails.join(','),
      subject: `🚨 ${typeLabel} REMINDER: ${item.item_name} - Due ${item.next_due_date}`,
      text: message,
      html: message.replace(/\n/g, '<br>')
    });

    console.log(`✅ MANUAL EMAIL sent to ${emails.length} recipients for item ${item.item_name} (ID: ${id})`);
    res.json({ msg: `Email sent to ${emails.length} recipient(s)!` });
  } catch (err) {
    console.error('SEND-NOW EMAIL ERROR:', err);
    res.status(500).json({ error: 'Failed to send email', details: err.message });
  }
});

// === GET ITEM REMINDERS ===
app.get('/item-reminders/:itemId', auth, async (req, res) => {
  const itemId = parseInt(req.params.itemId);
  try {
    const result = await db.query(
      'SELECT * FROM item_reminders WHERE item_id = $1 ORDER BY remind_date, remind_time',
      [itemId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET REMINDERS ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

// === SAVE REMINDERS ===
app.post('/save-reminders/:itemId', [auth, adminOnly], async (req, res) => {
  const itemId = parseInt(req.params.itemId);
  const { reminders } = req.body;

  if (!Array.isArray(reminders)) {
    return res.status(400).json({ error: 'reminders must be an array' });
  }

  try {
    await db.query('DELETE FROM item_reminders WHERE item_id = $1', [itemId]);

    let savedCount = 0;

    for (const rem of reminders) {
      if (rem.date && rem.time) {
        let cleanDate = rem.date;
        if (typeof cleanDate === 'string' && cleanDate.includes('T')) {
          cleanDate = cleanDate.split('T')[0];
        }

        if (!/^\d{4}-\d{2}-\d{2}$/.test(cleanDate)) {
          console.warn(`Invalid date skipped: ${rem.date}`);
          continue;
        }

        if (!/^\d{2}:\d{2}$/.test(rem.time)) {
          console.warn(`Invalid time skipped: ${rem.time}`);
          continue;
        }

        await db.query(
          'INSERT INTO item_reminders (item_id, remind_date, remind_time, email_sent) VALUES ($1, $2, $3, FALSE)',
          [itemId, cleanDate, rem.time]
        );
        savedCount++;
      }
    }

    console.log(`✅ Saved ${savedCount} reminders for item ${itemId}`);
    res.json({ msg: 'Reminders saved successfully', count: savedCount });
  } catch (err) {
    console.error('SAVE REMINDERS ERROR:', err);
    res.status(500).json({ error: err.message || 'Database insert failed' });
  }
});

// === EXCEL UPLOAD ===
app.post('/upload-excel', [auth, adminOnly], upload.single('file'), async (req, res) => {
  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(sheet);
    const today = new Date().toISOString().split('T')[0];

    let inserted = 0;
    for (const row of rows) {
      const item = {
        item_name: row['Item / Equipment / Instrument'] || row['Item'] || 'Unknown',
        type: row['Type'] || '',
        subtype: row['Subtype'] || '',
        category: row['Category'] || '',
        serial: row['Serial'] || '',
        firmware: row['Firmware'] || '',
        estimating_costing: parseFloat(row['Estimating Costing']) || 0,
        for_by: row['For / By'] || '',
        pic: row['PIC'] || '',
        pic_contact: row['PIC Contact #'] || '',
        pic_email: row['PIC Email'] || '',
        last_renewal_date: today,
        next_due_date: row['Next Due Date'] 
          ? new Date(row['Next Due Date']).toISOString().split('T')[0] 
          : today,
        reminder_type: row['Reminder Type'] || 'calibration'
      };

      await db.query('INSERT INTO items (item_name, type, subtype, category, serial, firmware, estimating_costing, for_by, pic, pic_contact, pic_email, last_renewal_date, next_due_date, reminder_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)', 
        [item.item_name, item.type, item.subtype, item.category, item.serial, item.firmware, item.estimating_costing, item.for_by, item.pic, item.pic_contact, item.pic_email, item.last_renewal_date, item.next_due_date, item.reminder_type]);

      inserted++;
    }

    fs.unlinkSync(req.file.path);
    console.log(`✅ Excel upload: ${inserted} items imported`);
    res.json({ msg: `Excel uploaded! ${inserted} items imported.` });
  } catch (err) {
    console.error('EXCEL UPLOAD ERROR:', err);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: err.message });
  }
});

// === COMPUTED FIELDS HELPER (Frontend only) ===
function calculateDerivedFields(item) {
  const now = new Date();
  const due = new Date(item.next_due_date);
  const diffDays = Math.ceil((due - now) / (1000 * 60 * 60 * 24));

  const years = Math.floor(diffDays / 365);
  const months = Math.floor((diffDays % 365) / 30);
  const days = diffDays % 30;

  let status = 'green';
  if (diffDays <= 30) status = 'red';
  else if (diffDays <= 180) status = 'yellow';

  return {
    ...item,
    due_in_days: diffDays,
    due_in: `${years}y ${months}m ${days > 0 ? days + 'd' : ''}`.trim(),
    status
  };
}

// === EMAIL TRANSPORTER ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify email on startup
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ EMAIL SETUP FAILED:', error);
  } else {
    console.log('✅ Email transporter ready');
  }
});

// === CRON JOB ===
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const malaysiaNow = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Kuala_Lumpur' }));
  const today = malaysiaNow.toISOString().split('T')[0];
  const currentTime = malaysiaNow.toTimeString().slice(0, 5);

  try {
    const result = await db.query(`
      SELECT ir.*, i.item_name, i.serial, i.type, i.pic_email, i.next_due_date,
             COALESCE(i.reminder_type, 'calibration') AS reminder_type
      FROM item_reminders ir
      JOIN items i ON ir.item_id = i.id
      WHERE ir.remind_date = $1 
        AND ir.remind_time = $2 
        AND ir.email_sent = FALSE 
        AND i.pic_email IS NOT NULL 
        AND i.pic_email != ''
    `, [today, currentTime]);

    for (const row of result.rows) {
      try {
        const emails = row.pic_email.split(',').map(e => e.trim()).filter(Boolean);
        if (emails.length === 0) continue;

        const typeLabel = row.reminder_type === 'license' ? 'License' : 'Calibration';
        const message = `
📅 Aziman ${typeLabel} REMINDER

📋 Item: ${row.item_name}
🔢 Serial: ${row.serial || 'N/A'}
🏷️ Type: ${row.type || 'N/A'}

📅 Due Date: ${row.next_due_date}

⏰ Scheduled reminder at ${currentTime}

Thank you!
👨‍💼 Aziman Reminder System
        `.trim();

        await transporter.sendMail({
          from: `"Aziman Reminder System" <${process.env.EMAIL_USER}>`,
          to: emails.join(','),
          subject: `📅 ${typeLabel} Reminder: ${row.item_name}`,
          text: message,
          html: message.replace(/\n/g, '<br>')
        });

        await db.query('UPDATE item_reminders SET email_sent = TRUE WHERE id = $1', [row.id]);
        console.log(`✅ CRON: Reminder sent for ${row.item_name} → ${emails.length} emails`);
      } catch (emailErr) {
        console.error(`Email send failed for item ${row.item_name}:`, emailErr);
      }
    }
  } catch (err) {
    console.error('CRON JOB ERROR:', err);
  }
}, { timezone: "Asia/Kuala_Lumpur" });

app.listen(process.env.PORT || 5000, () => {
  console.log('🚀 Backend running on port', process.env.PORT || 5000);
  console.log('📧 Aziman Reminder System ready');
});
