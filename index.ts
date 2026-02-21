import 'dotenv/config';
import express, { Request } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { pool } from './shared/db.js';
import accountRouter from './routes/account.js';
import { encrypt, decrypt } from './shared/crypto.js';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import multer, { FileFilterCallback } from 'multer';
import { fileURLToPath } from 'url';


interface MulterRequest extends Request {
  file: Express.Multer.File;
}

// In-memory store for captchas (for simplicity, in a real app use Redis or similar)
const captchas: { [key: string]: { value: string; expires: number } } = {};

// 3. CAPTCHA Cleanup
setInterval(() => {
    const now = Date.now();
    for (const key in captchas) {
        if (captchas[key].expires < now) {
            delete captchas[key];
        }
    }
}, 60 * 1000); // Clean up every minute

// Remove __dirname / __filename polyfills for CommonJS as they are built-in
// But since we are using TS with CommonJS output, we can use __dirname directly if @types/node is correct
// Or just let tsc handle it.

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { 
      origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      credentials: true
  }
});

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' })); // Increased limit for bulk imports
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/api', accountRouter);

// Serve uploads directory
const uploadsPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../uploads');
// Ensure directory exists
(async () => {
    try {
        await fs.mkdir(uploadsPath, { recursive: true });
    } catch (e) {
        console.error('Failed to create uploads dir:', e);
    }
})();

app.use('/uploads', express.static(uploadsPath));

// Configure multer for file uploads
const upload = multer({
  dest: uploadsPath,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  storage: multer.diskStorage({
      destination: (_req, _file, cb) => {
          cb(null, uploadsPath);
      },
      filename: (_req, file, cb) => {
          const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
          const ext = path.extname(file.originalname);
          cb(null, file.fieldname + '-' + uniqueSuffix + ext);
      }
  }),
  fileFilter: (_req: any, file: Express.Multer.File, cb: FileFilterCallback) => {
    // Allow images, PDFs, CSVs, and JSON files
    if (
        file.mimetype.startsWith('image/') || 
        file.mimetype === 'application/pdf' ||
        file.mimetype === 'text/csv' ||
        file.mimetype === 'application/vnd.ms-excel' || // CSV often detected as this
        file.mimetype === 'application/json' ||
        file.originalname.match(/\.(jpg|jpeg|png|gif|pdf|csv|json|txt)$/i)
    ) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed. Supported: Images, PDF, CSV, JSON'));
    }
  }
});

const DB_ENV = {
  host: process.env.DB_HOST || 'localhost',
  port: +(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'massmail',
  password: process.env.DB_PASSWORD || 'massmailPassword',
  database: process.env.DB_NAME || 'massmail',
};



const SCAN_DIR = process.env.ACCOUNTS_SCAN_DIR || '/data/accounts';

async function loadAccountsFromDir(dir: string) {
  const jsonFiles: string[] = [];
  async function walk(d: string) {
    let entries: any[] = [];
    try {
      entries = await fs.readdir(d, { withFileTypes: true } as any);
    } catch {
      return;
    }
    for (const ent of entries) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) await walk(full);
      else if (ent.isFile() && ent.name.toLowerCase().endsWith('.json')) jsonFiles.push(full);
    }
  }
  await walk(dir);

  const rows: Array<{ phone: string; token_cipher: Buffer; proxy_url: string; system_type: string }> = [];
  for (const f of jsonFiles) {
    try {
      const text = await fs.readFile(f, 'utf8');
      const obj = JSON.parse(text);
      if (!obj.phone || !obj.token || !obj.proxy_url) continue;
      const sys = String(obj.system_type || 'other').toLowerCase();
      const system_type = sys === 'android' ? 'Android' : sys === 'ios' ? 'iOS' : 'Other';
      rows.push({
        phone: String(obj.phone),
        token_cipher: encrypt(String(obj.token)),
        proxy_url: String(obj.proxy_url),
        system_type
      });
    } catch {
    }
  }
  if (!rows.length) return { inserted: 0, updated: 0, scanned: jsonFiles.length };

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let inserted = 0;
    let updated = 0;
    for (const r of rows) {
      const [res]: any = await conn.execute(
        `INSERT INTO accounts (phone, token_cipher, proxy_url, system_type, status, last_used_at)
         VALUES (?, ?, ?, ?, 'Ready', NOW(3))
         ON DUPLICATE KEY UPDATE
           token_cipher = VALUES(token_cipher),
           proxy_url = VALUES(proxy_url),
           system_type = VALUES(system_type),
           updated_at = CURRENT_TIMESTAMP(3)`,
        [r.phone, r.token_cipher, r.proxy_url, r.system_type]
      );
      if (res.affectedRows === 1) inserted++;
      else if (res.affectedRows === 2) updated++;
    }
    await conn.commit();
    return { inserted, updated, scanned: jsonFiles.length };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

app.get('/health', (_req, res) => res.json({ ok: true, env: { database: DB_ENV.database } }));
app.get('/healthz', (_req, res) => res.json({ ok: true, env: { database: DB_ENV.database } }));

app.get('/api/captcha', (req, res) => {
  const captchaId = crypto.randomBytes(16).toString('hex');
  const captchaValue = String(Math.floor(1000 + Math.random() * 9000)); // 4-digit number
  const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiration

  captchas[captchaId] = { value: captchaValue, expires };

  // Generate SVG Captcha
  const svg = `
    <svg width="120" height="50" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f0f2f5"/>
      <text x="50%" y="50%" font-family="Arial" font-size="24" font-weight="bold" fill="#1677ff" dominant-baseline="middle" text-anchor="middle" letter-spacing="4">${captchaValue}</text>
      <line x1="10" y1="10" x2="110" y2="40" stroke="#ccc" stroke-width="2"/>
      <line x1="10" y1="40" x2="110" y2="10" stroke="#ccc" stroke-width="2"/>
    </svg>
  `;
  const image = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;

  // Return ID and Image (NOT the value)
  res.json({ captchaId, image });
});

const loginHandler = async (req: express.Request, res: express.Response) => {
  const { username, password, captcha, captchaId } = req.body;

  // Verify Captcha
  if (!captchaId || !captchas[captchaId]) {
      return res.status(400).json({ error: 'Invalid or expired captcha' });
  }
  const storedCaptcha = captchas[captchaId];
  if (Date.now() > storedCaptcha.expires) {
      delete captchas[captchaId];
      return res.status(400).json({ error: 'Captcha expired' });
  }
  if (storedCaptcha.value !== captcha) {
      return res.status(400).json({ error: 'Incorrect captcha' });
  }
  // Clear used captcha
  delete captchas[captchaId];

  const conn = await pool.getConnection();
  try {
      const [rows]: any = await conn.execute(
          'SELECT * FROM users WHERE username = ?',
          [username]
      );

      if (rows.length === 0) {
          return res.status(401).json({ error: 'Invalid username or password' });
      }

      const user = rows[0];
      let match = false;

      // Check if password is hashed (bcrypt hashes start with $2a$ or $2b$)
      if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
          match = await bcrypt.compare(password, user.password);
      } else {
          // Fallback to plain text check
          if (user.password === password) {
              match = true;
              // Upgrade to hash
              const hashed = await bcrypt.hash(password, 10);
              await conn.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id]);
          }
      }

      if (!match) {
          return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Generate a simple token (in production use JWT)
      const token = crypto.randomBytes(32).toString('hex');
      
      // Return token and user info
      res.json({ 
          token,
          user: {
              id: user.id,
              username: user.username,
              role: 'admin' // Hardcoded for now
          }
      });
  } catch (err: any) {
      res.status(500).json({ error: 'Login failed', detail: err.message });
  } finally {
      conn.release();
  }
};

app.post('/api/login', loginHandler);
app.post('/api/auth/login', loginHandler);

app.post('/api/messages', async (req, res) => {
  try {
    const { targets, content, media_url, accountId } = req.body ?? {};
    if (!Array.isArray(targets) || !targets.length) {
      return res.status(400).json({ error: 'targets required' });
    }
    if (typeof content !== 'string' || !content.trim()) {
      return res.status(400).json({ error: 'content required' });
    }
    const phones = Array.from(
      new Set(targets.map((t: any) => String(t).trim()).filter(Boolean))
    );
    if (!phones.length) return res.status(400).json({ error: 'no valid targets' });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const batch = 500;
      for (let i = 0; i < phones.length; i += batch) {
        const chunk = phones.slice(i, i + batch);
        const placeholders = chunk.map(() => '(?, ?, ?, ?, "Pending", NOW(3))').join(',');
        const values = [];
        for (const p of chunk) {
          values.push(p, content, media_url || null, accountId || null);
        }
        await conn.execute(
          `INSERT INTO message_tasks (target_phone, content, media_url, account_id, status, created_at)
           VALUES ${placeholders}`,
          values
        );

        // Update session status to active
        if (accountId) {
             const phonePlaceholders = chunk.map(() => '?').join(',');
             await conn.execute(
                 `UPDATE chat_sessions SET status = 'active', last_message_at = NOW(3) 
                  WHERE tn_account_id = ? AND customer_phone IN (${phonePlaceholders})`,
                 [accountId, ...chunk]
             );
        }
      }
      await conn.commit();
      res.json({ accepted: phones.length });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to enqueue', detail: String(err?.message || err) });
  }
});

app.get('/api/tasks', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;
    const status = req.query.status as string;
    const accountId = req.query.accountId ? parseInt(req.query.accountId as string) : null;

    let whereClause = 'WHERE 1=1';
    const queryParams: any[] = [];
    
    if (status && status !== 'All') {
      whereClause += ' AND status = ?';
      queryParams.push(status);
    }
    
    if (accountId) {
      whereClause += ' AND account_id = ?';
      queryParams.push(accountId);
    }

    const [countRows]: any = await conn.execute(
      `SELECT COUNT(*) as total FROM message_tasks ${whereClause}`,
      queryParams
    );
    const total = countRows[0].total;

    const [rows]: any = await conn.query(
      `SELECT * FROM message_tasks ${whereClause} 
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`,
      [...queryParams, limit, offset]
    );

    res.json({
      items: rows,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch tasks', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/tasks/retry-failed', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [result]: any = await conn.query(
      "UPDATE message_tasks SET status='Pending', attempts=0, next_retry_at=NULL, error_message=NULL, error_code=NULL WHERE status='Failed'"
    );
    res.json({ updated: result.affectedRows });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retry tasks', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/tasks/:id/pause', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [result]: any = await conn.execute(
      "UPDATE message_tasks SET status='Paused' WHERE id = ? AND status IN ('Pending', 'Retry')",
      [req.params.id]
    );
    res.json({ updated: result.affectedRows });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to pause task', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/tasks/:id/resume', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [result]: any = await conn.execute(
      "UPDATE message_tasks SET status='Pending', next_retry_at=NULL WHERE id = ? AND status='Paused'",
      [req.params.id]
    );
    res.json({ updated: result.affectedRows });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to resume task', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.delete('/api/tasks/:id', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [result]: any = await conn.execute(
      'DELETE FROM message_tasks WHERE id = ?',
      [req.params.id]
    );
    res.json({ deleted: result.affectedRows });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete task', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.get('/api/inbound-messages', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;
    const accountId = req.query.account_id ? parseInt(req.query.account_id as string) : null;

    let whereClause = '';
    const params: any[] = [];
    if (accountId) {
      whereClause = 'WHERE i.account_id = ?';
      params.push(accountId);
    }

    // Get total count
    const [countRows]: any = await conn.execute(
      `SELECT COUNT(*) as total FROM inbound_messages i ${whereClause}`,
      params
    );
    const total = countRows[0].total;

    // Get paginated items
    const [rows]: any = await conn.query(
      `SELECT i.*, a.phone as account_phone 
       FROM inbound_messages i 
       JOIN accounts a ON i.account_id = a.id 
       ${whereClause}
       ORDER BY i.received_at DESC 
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({
      items: rows,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch inbound messages', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/test/inbound', async (req, res) => {
  const { account_id, sender_phone, content } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.execute(
      'INSERT INTO inbound_messages (account_id, sender_phone, content, received_at, is_read) VALUES (?, ?, ?, NOW(3), 0)',
      [account_id, sender_phone, content]
    );
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

app.get('/api/conversations', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;
    const subAccountId = req.query.subAccountId ? parseInt(req.query.subAccountId as string) : null;
    const status = req.query.status as string;
    const search = req.query.search as string;

    let whereClause = 'WHERE 1=1';
    const params: any[] = [];
    
    if (subAccountId) {
      whereClause += ' AND s.sub_account_id = ?';
      params.push(subAccountId);
    }
    if (status) {
        whereClause += ' AND s.status = ?';
        params.push(status);
    }
    if (search) {
        whereClause += ' AND (s.customer_phone LIKE ? OR a.phone LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    // Sync sessions from inbound messages (Lazy sync)
    await conn.execute(`
        INSERT IGNORE INTO chat_sessions (tn_account_id, customer_phone, last_message_at, status, sub_account_id)
        SELECT i.account_id, i.sender_phone, MAX(i.received_at), 'waiting',
               (SELECT sub_account_id FROM account_assignments WHERE tn_account_id = i.account_id LIMIT 1)
        FROM inbound_messages i
        GROUP BY i.account_id, i.sender_phone
    `);

    // Update status to 'waiting' if there are unread messages
    await conn.execute(`
        UPDATE chat_sessions s
        JOIN (
            SELECT account_id, sender_phone, MAX(received_at) as last_inbound
            FROM inbound_messages 
            WHERE is_read = 0 
            GROUP BY account_id, sender_phone
        ) i ON s.tn_account_id = i.account_id AND s.customer_phone = i.sender_phone
        SET s.status = 'waiting', 
            s.last_message_at = GREATEST(COALESCE(s.last_message_at, '1970-01-01'), i.last_inbound)
    `);

    // Sync from outbound (ensure active status for sent messages)
    await conn.execute(`
        INSERT IGNORE INTO chat_sessions (tn_account_id, customer_phone, last_message_at, status, sub_account_id)
        SELECT t.account_id, t.target_phone, MAX(t.created_at), 'active',
               (SELECT sub_account_id FROM account_assignments WHERE tn_account_id = t.account_id LIMIT 1)
        FROM message_tasks t
        WHERE t.status = 'Sent'
        GROUP BY t.account_id, t.target_phone
    `);
    
    // Update last_message_at from outbound
    await conn.execute(`
        UPDATE chat_sessions s
        JOIN (
            SELECT account_id, target_phone, MAX(created_at) as last_outbound
            FROM message_tasks 
            WHERE status = 'Sent'
            GROUP BY account_id, target_phone
        ) t ON s.tn_account_id = t.account_id AND s.customer_phone = t.target_phone
        SET s.last_message_at = GREATEST(COALESCE(s.last_message_at, '1970-01-01'), t.last_outbound)
    `);

    const [rows]: any = await conn.query(`
      SELECT 
        s.id,
        s.tn_account_id,
        s.customer_phone,
        s.status,
        s.sub_account_id,
        s.last_message_at,
        a.phone as account_phone,
        sa.name as sub_account_name,
        (SELECT COUNT(*) FROM inbound_messages m WHERE m.account_id = s.tn_account_id AND m.sender_phone = s.customer_phone AND m.is_read = 0) as unread_count
      FROM chat_sessions s
      JOIN accounts a ON s.tn_account_id = a.id
      LEFT JOIN sub_accounts sa ON s.sub_account_id = sa.id
      ${whereClause}
      ORDER BY s.last_message_at DESC
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

    const [countRows]: any = await conn.query(`
      SELECT COUNT(*) as total 
      FROM chat_sessions s 
      JOIN accounts a ON s.tn_account_id = a.id
      ${whereClause}
    `, params);
    const total = countRows[0].total;

    res.json({
      items: rows,
      pagination: { total, page, limit, totalPages: Math.ceil(total / limit) }
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch conversations', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/sessions/:id/transfer', async (req, res) => {
    const { targetSubAccountId, userId } = req.body;
    const sessionId = req.params.id;
    const conn = await pool.getConnection();
    try {
        await conn.execute(
            'UPDATE chat_sessions SET sub_account_id = ? WHERE id = ?',
            [targetSubAccountId, sessionId]
        );
        // Audit
        await conn.execute(
            'INSERT INTO audit_logs (user_id, action, resource_type, resource_id, payload) VALUES (?, ?, ?, ?, ?)',
            [userId || null, 'TRANSFER_SESSION', 'CHAT_SESSION', sessionId, JSON.stringify({ to: targetSubAccountId })]
        );
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    } finally {
        conn.release();
    }
});

app.post('/api/sessions/:id/close', async (req, res) => {
    const { userId } = req.body;
    const sessionId = req.params.id;
    const conn = await pool.getConnection();
    try {
        await conn.execute(
            'UPDATE chat_sessions SET status = "closed" WHERE id = ?',
            [sessionId]
        );
        res.json({ success: true });
    } finally {
        conn.release();
    }
});

app.post('/api/conversations/:accountId/:phone/read', async (req, res) => {
  const { accountId, phone } = req.params;
  const conn = await pool.getConnection();
  try {
    await conn.execute(
      'UPDATE inbound_messages SET is_read = 1 WHERE account_id = ? AND sender_phone = ?',
      [accountId, phone]
    );
    // Also update session status to active if it was waiting?
    // Or just let the unread count drop to 0, which stops the 'waiting' force-update in GET.
    // But we might want to explicitly set it to 'active' if it was 'waiting'.
    await conn.execute(
        'UPDATE chat_sessions SET status = "active" WHERE tn_account_id = ? AND customer_phone = ? AND status = "waiting"',
        [accountId, phone]
    );
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to mark conversation as read', detail: err.message });
  } finally {
    conn.release();
  }
});

app.get('/api/conversations/:accountId/:phone/messages', async (req, res) => {
  const { accountId, phone } = req.params;
  const conn = await pool.getConnection();
  try {
    const [inbound]: any = await conn.query(
      `SELECT id, content, media_url, received_at as created_at, 'inbound' as direction, is_read 
       FROM inbound_messages 
       WHERE account_id = ? AND sender_phone = ?`,
      [accountId, phone]
    );

    const [outbound]: any = await conn.query(
      `SELECT id, content, media_url, created_at, 'outbound' as direction, status
       FROM message_tasks 
       WHERE account_id = ? AND target_phone = ?`,
      [accountId, phone]
    );

    const messages = [...inbound, ...outbound].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    res.json({ items: messages });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch messages', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/inbound-messages/:id/read', async (req, res) => {
  try {
    const id = req.params.id;
    const [result]: any = await pool.execute(
      'UPDATE inbound_messages SET is_read = 1 WHERE id = ?',
      [id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to mark message as read', detail: String(err?.message || err) });
  }
});

app.get('/api/metrics', async (_req, res) => {
  const conn = await pool.getConnection();
  try {
    const [taskStats]: any = await conn.query(
      "SELECT status, COUNT(*) as count FROM message_tasks GROUP BY status"
    );
    const [accountStats]: any = await conn.query(
      "SELECT status, COUNT(*) as count FROM accounts GROUP BY status"
    );
    const [messageStats]: any = await conn.query(
      "SELECT COUNT(*) as unread FROM inbound_messages WHERE is_read = 0"
    );
    const [activeConvs]: any = await conn.query(
      "SELECT COUNT(DISTINCT sender_phone) as active FROM inbound_messages WHERE received_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
    );
    
    const metrics = {
      tasks: taskStats.reduce((acc: any, row: any) => {
        acc[row.status] = row.count;
        return acc;
      }, {}),
      accounts: accountStats.reduce((acc: any, row: any) => {
        acc[row.status] = row.count;
        return acc;
      }, {}),
      messages: {
        unread: messageStats[0]?.unread || 0,
        active: activeConvs[0]?.active || 0
      }
    };
    
    res.json(metrics);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch metrics', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.get('/api/stats', async (_req, res) => {
  try {
    const [accRows] = await pool.query('SELECT status, COUNT(*) as count FROM accounts GROUP BY status');
    const [taskRows] = await pool.query('SELECT status, COUNT(*) as count FROM message_tasks GROUP BY status');
    res.json({
      accounts: accRows,
      tasks: taskRows
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch stats', detail: String(err?.message || err) });
  }
});



app.get('/api/accounts', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const page = Math.max(1, parseInt(req.query.page as string) || 1);
        const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
        const offset = (page - 1) * limit;
        const status = req.query.status as string;
        const search = req.query.search as string;

        let whereClause = 'WHERE 1=1';
        const queryParams: any[] = [];

        if (status) {
            whereClause += ' AND status = ?';
            queryParams.push(status);
        }
        if (search) {
            whereClause += ' AND phone LIKE ?';
            queryParams.push(`%${search}%`);
        }

        const [countRows]: any = await conn.execute(
            `SELECT COUNT(*) as total FROM accounts ${whereClause}`,
            queryParams
        );
        const total = countRows[0].total;

        const [rows]: any = await conn.query(
            `SELECT id, phone, status, system_type, proxy_url, last_used_at, updated_at,
             CASE WHEN tn_session_id IS NOT NULL THEN 1 ELSE 0 END as tn_ready
             FROM accounts ${whereClause}
             ORDER BY updated_at DESC
             LIMIT ? OFFSET ?`,
            [...queryParams, limit, offset]
        );

        res.json({
            items: rows,
            pagination: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to fetch accounts', detail: String(err?.message || err) });
    } finally {
        conn.release();
    }
});

app.delete('/api/accounts/:id', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const [result]: any = await conn.execute(
            'DELETE FROM accounts WHERE id = ?',
            [req.params.id]
        );
        res.json({ deleted: result.affectedRows });
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to delete account', detail: String(err?.message || err) });
    } finally {
        conn.release();
    }
});

// Initialize database tables
async function initDB() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        phone VARCHAR(32) NOT NULL UNIQUE,
        token_cipher LONGBLOB,
        proxy_url TEXT,
        system_type VARCHAR(20) DEFAULT 'Android',
        status ENUM('Ready', 'Dead', 'Busy') DEFAULT 'Ready',
        tn_session_id VARCHAR(255),
        tn_client_id VARCHAR(255),
        tn_device_model VARCHAR(100),
        tn_os VARCHAR(50),
        tn_os_version VARCHAR(50),
        tn_user_agent TEXT,
        tn_type VARCHAR(50),
        tn_uuid VARCHAR(100),
        tn_vid VARCHAR(100),
        tn_session_token_cipher LONGBLOB,
        last_used_at DATETIME(3),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS message_tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        target_phone VARCHAR(32) NOT NULL,
        content TEXT,
        media_url TEXT,
        account_id BIGINT UNSIGNED,
        status ENUM('Pending', 'Sent', 'Failed', 'Paused', 'Retry') DEFAULT 'Pending',
        attempts INT DEFAULT 0,
        last_attempt_at DATETIME,
        next_retry_at DATETIME,
        error_message TEXT,
        error_code VARCHAR(50),
        created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS compliance_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        entity_name VARCHAR(255) NOT NULL,
        tax_id VARCHAR(50) NOT NULL,
        address TEXT,
        document_type VARCHAR(50) NOT NULL,
        file_path VARCHAR(255) NOT NULL,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    await conn.query(`
      CREATE TABLE IF NOT EXISTS inbound_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        account_id BIGINT UNSIGNED NOT NULL,
        sender_phone VARCHAR(32) NOT NULL,
        content TEXT,
        media_url TEXT,
        received_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
        is_read BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS sub_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        parent_user_id INT NOT NULL,
        name VARCHAR(64) NOT NULL,
        password VARCHAR(255),
        status ENUM('ACTIVE','DISABLED') DEFAULT 'ACTIVE',
        quota_limit INT DEFAULT 10,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (parent_user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS account_assignments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tn_account_id BIGINT UNSIGNED NOT NULL,
        sub_account_id INT NOT NULL,
        assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_assigned (tn_account_id, sub_account_id),
        FOREIGN KEY (tn_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
        FOREIGN KEY (sub_account_id) REFERENCES sub_accounts(id) ON DELETE CASCADE
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS import_jobs (
        id VARCHAR(36) PRIMARY KEY,
        status ENUM('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED') DEFAULT 'PENDING',
        progress INT DEFAULT 0,
        total INT DEFAULT 0,
        processed INT DEFAULT 0,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tn_account_id BIGINT UNSIGNED NOT NULL,
        customer_phone VARCHAR(32) NOT NULL,
        sub_account_id INT,
        status ENUM('waiting', 'active', 'closed') DEFAULT 'waiting',
        last_message_at DATETIME(3),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_session (tn_account_id, customer_phone),
        FOREIGN KEY (tn_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
        FOREIGN KEY (sub_account_id) REFERENCES sub_accounts(id) ON DELETE SET NULL
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        action VARCHAR(64) NOT NULL,
        resource_type VARCHAR(64) NOT NULL,
        resource_id BIGINT,
        payload JSON,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Add indexes for performance
    try {
        await conn.query('CREATE INDEX idx_inbound_lookup ON inbound_messages(account_id, sender_phone, is_read)');
    } catch {}
    try {
        await conn.query('CREATE INDEX idx_outbound_lookup ON message_tasks(account_id, target_phone, status)');
    } catch {}

    await conn.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        priority ENUM('low', 'medium', 'high') DEFAULT 'medium',
        status ENUM('pending', 'assigned', 'in_progress', 'completed', 'cancelled') DEFAULT 'pending',
        tn_account_id BIGINT UNSIGNED,
        sub_account_id INT,
        deadline_at DATETIME,
        version INT DEFAULT 1,
        min_interval INT DEFAULT 300,
        max_interval INT DEFAULT 480,
        message_type VARCHAR(20) DEFAULT 'text',
        message_content TEXT,
        phones TEXT,
        tn_account_ids JSON,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (tn_account_id) REFERENCES accounts(id) ON DELETE SET NULL,
        FOREIGN KEY (sub_account_id) REFERENCES sub_accounts(id) ON DELETE SET NULL
      )
    `);
    
    // Patch existing table if columns missing
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN min_interval INT DEFAULT 300");
    } catch {}
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN max_interval INT DEFAULT 480");
    } catch {}
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN message_type VARCHAR(20) DEFAULT 'text'");
    } catch {}
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN message_content TEXT");
    } catch {}
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN phones TEXT");
    } catch {}
    try {
        await conn.query("ALTER TABLE tasks ADD COLUMN tn_account_ids JSON");
    } catch {}

    // --- New Schema for Replenishment & Status ---
    try {
        await conn.query("ALTER TABLE sub_accounts ADD COLUMN password VARCHAR(255)");
    } catch {}
    try {
        await conn.query("ALTER TABLE sub_accounts ADD COLUMN target_count INT DEFAULT 10");
    } catch {}
    try {
        await conn.query("ALTER TABLE account_assignments ADD COLUMN status ENUM('ACTIVE', 'DEAD', 'REPLACED') DEFAULT 'ACTIVE'");
    } catch {}
    try {
        await conn.query("ALTER TABLE account_assignments ADD COLUMN task_id INT");
    } catch {}
    try {
        await conn.query("ALTER TABLE account_assignments ADD COLUMN failure_reason VARCHAR(255)");
    } catch {}
    try {
        await conn.query("ALTER TABLE account_assignments ADD COLUMN replaced_by_id INT");
    } catch {}

    // --- New Schema for Full Account Details ---
    try { await conn.query("ALTER TABLE accounts ADD COLUMN email VARCHAR(255)"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN username VARCHAR(255)"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN password_cipher LONGBLOB"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN signature TEXT"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN app_version VARCHAR(50)"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN brand VARCHAR(50)"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN language VARCHAR(20)"); } catch {}
    try { await conn.query("ALTER TABLE accounts ADD COLUMN fp TEXT"); } catch {}

    await conn.query(`
      CREATE TABLE IF NOT EXISTS task_sub_account_stats (
        task_id INT NOT NULL,
        sub_account_id INT NOT NULL,
        replenishment_count INT DEFAULT 0,
        last_replenished_at DATETIME,
        PRIMARY KEY (task_id, sub_account_id),
        FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY (sub_account_id) REFERENCES sub_accounts(id) ON DELETE CASCADE
      )
    `);

    // Seed default admin user
    const [rows]: any = await conn.query("SELECT * FROM users WHERE username = 'admin'");
    if (rows.length === 0) {
      const hashed = await bcrypt.hash('admin123', 10);
      await conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', hashed]);
      console.log('Default admin user created');
    } else {
      // Check if password is plain text (not starting with $2b$) and upgrade it
      const admin = rows[0];
      if (!admin.password.startsWith('$2b$')) {
        console.log('Upgrading admin password to bcrypt hash...');
        const hashed = await bcrypt.hash('admin123', 10); // Assume default was admin123
        await conn.execute("UPDATE users SET password = ? WHERE id = ?", [hashed, admin.id]);
      }
    }

    // Seed customer service staff accounts
    // const [staff1]: any = await conn.query("SELECT * FROM users WHERE username = 'staff_sarah'");
    // if (staff1.length === 0) {
    //   await conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ['staff_sarah', 'sarah2026']);
    //   console.log('Staff Sarah user created');
    // }

    // const [staff2]: any = await conn.query("SELECT * FROM users WHERE username = 'staff_mike'");
    // if (staff2.length === 0) {
    //   await conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ['staff_mike', 'mike2026']);
    //   console.log('Staff Mike user created');
    // }

    console.log('Database tables initialized');
  } catch (err) {
    console.error('Failed to init DB:', err);
  } finally {
    conn.release();
  }
}

initDB();

// --- Sub-account Management ---

app.post('/api/subaccounts', async (req, res) => {
  const { name, password, parent_user_id, quota_limit } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (!password) return res.status(400).json({ error: 'Password is required' });

  const conn = await pool.getConnection();
  try {
    // Check name conflict
    const [existing]: any = await conn.query("SELECT id FROM sub_accounts WHERE name = ?", [name]);
    if (existing.length > 0) {
        return res.status(409).json({ error: 'Sub-account name already exists' });
    }

    // Check if parent user exists (default to admin if not provided)
    let parentId = parent_user_id;
    if (!parentId) {
        const [users]: any = await conn.query("SELECT id FROM users WHERE username='admin' LIMIT 1");
        if (users.length) parentId = users[0].id;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result]: any = await conn.execute(
      'INSERT INTO sub_accounts (name, password, parent_user_id, quota_limit) VALUES (?, ?, ?, ?)',
      [name, hashedPassword, parentId, quota_limit || 10]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to create subaccount', detail: err.message });
  } finally {
    conn.release();
  }
});

app.post('/api/subaccounts/batch', async (req, res) => {
  const { baseName, password, count, quota_limit } = req.body;
  if (!baseName || !password || !count) {
    return res.status(400).json({ error: 'baseName, password and count are required' });
  }

  const conn = await pool.getConnection();
  try {
    // 1. Generate candidate names
    const candidates: string[] = [];
    const n = Math.max(1, Number(count));
    for (let i = 1; i <= n; i++) {
      candidates.push(`${baseName}${i}`);
    }

    // 2. Check conflicts
    const placeholders = candidates.map(() => '?').join(',');
    const [existing]: any = await conn.query(
      `SELECT name FROM sub_accounts WHERE name IN (${placeholders})`,
      candidates
    );

    if (existing.length > 0) {
      const existingNames = existing.map((r: any) => r.name);
      return res.status(409).json({ 
        error: `Some usernames already exist: ${existingNames.join(', ')}`,
        existing: existingNames
      });
    }

    // 3. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Transaction & Bulk Create
    await conn.beginTransaction();

    let parentId = null;
    const [users]: any = await conn.query("SELECT id FROM users WHERE username='admin' LIMIT 1");
    if (users.length) parentId = users[0].id;
    
    if (!parentId) throw new Error("Parent user not found");

    const insertValues: string[] = [];
    const insertParams: any[] = [];
    for (const name of candidates) {
      insertValues.push('(?, ?, ?, ?)');
      insertParams.push(name, hashedPassword, parentId, quota_limit || 10);
    }

    await conn.execute(
      `INSERT INTO sub_accounts (name, password, parent_user_id, quota_limit) VALUES ${insertValues.join(',')}`,
      insertParams
    );

    await conn.commit();
    res.json({ success: true, created: candidates.length, names: candidates });
  } catch (err: any) {
    await conn.rollback();
    res.status(500).json({ error: 'Failed to create subaccounts', detail: err.message });
  } finally {
    conn.release();
  }
});

app.get('/api/subaccounts', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows]: any = await conn.query(`
      SELECT s.*, 
             u.username as parent_username,
             (SELECT COUNT(*) FROM account_assignments aa WHERE aa.sub_account_id = s.id) as assigned_count
      FROM sub_accounts s
      LEFT JOIN users u ON s.parent_user_id = u.id
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch subaccounts', detail: err.message });
  } finally {
    conn.release();
  }
});

app.post('/api/subaccounts/:id/quota', async (req, res) => {
    const { quota } = req.body;
    const subAccountId = req.params.id;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        // Update quota
        await conn.execute('UPDATE sub_accounts SET quota_limit = ? WHERE id = ?', [quota, subAccountId]);

        // Check if we need to release assignments (Recycle)
        const [rows]: any = await conn.query('SELECT COUNT(*) as count FROM account_assignments WHERE sub_account_id = ?', [subAccountId]);
        const currentCount = rows[0].count;

        if (currentCount > quota) {
            const toRelease = currentCount - quota;
            // Delete oldest assignments first or random? Let's do random/latest to keep it simple.
            // MySQL DELETE LIMIT works.
            await conn.execute(
                `DELETE FROM account_assignments WHERE sub_account_id = ? ORDER BY assigned_at DESC LIMIT ?`,
                [subAccountId, toRelease]
            );
            await createAuditLog('RECYCLE', 'TN_ACCOUNT', { subAccountId, released: toRelease, newQuota: quota });
        }

        await conn.commit();
        res.json({ success: true, message: 'Quota updated' });
    } catch (e: any) {
        await conn.rollback();
        res.status(500).json({ error: 'Failed to update quota', detail: e.message });
    } finally {
        conn.release();
    }
});


// --- Job System & Async Processing ---

async function updateJobProgress(jobId: string, progress: number, status: string, details?: string) {
    const conn = await pool.getConnection();
    try {
        await conn.execute(
            'UPDATE import_jobs SET progress = ?, status = ?, details = ? WHERE id = ?',
            [progress, status, details || null, jobId]
        );
    } catch (e) {
        console.error('Failed to update job:', e);
    } finally {
        conn.release();
    }
}

async function createAuditLog(action: string, type: string, payload: any, userId?: number) {
    const conn = await pool.getConnection();
    try {
        await conn.execute(
            'INSERT INTO audit_logs (user_id, action, resource_type, payload) VALUES (?, ?, ?, ?)',
            [userId || null, action, type, JSON.stringify(payload)]
        );
    } catch (e) {
        console.error('Audit log failed:', e);
    } finally {
        conn.release();
    }
}

// Import Processor
async function processImportJob(jobId: string, fileBuffer: Buffer, userId?: number) {
    try {
        const content = fileBuffer.toString('utf-8');
        const lines = content.split(/\r?\n/).filter(line => line.trim() !== '');
        
        // Simple CSV parser (assumes header row)
        // Expected headers: account_name, password, status, tags
        // Mapping: account_name -> phone, password -> token (encrypted)
        
        const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
        const dataRows = lines.slice(1);
        const total = dataRows.length;

        const conn = await pool.getConnection();
        await conn.execute('UPDATE import_jobs SET total = ?, status = "PROCESSING" WHERE id = ?', [total, jobId]);
        conn.release();

        let processed = 0;
        let success = 0;
        let failed = 0;
        let skipped = 0;

        // Process in chunks
        const BATCH_SIZE = 100;
        for (let i = 0; i < total; i += BATCH_SIZE) {
            const chunk = dataRows.slice(i, i + BATCH_SIZE);
            const values = [];
            
            for (const rowStr of chunk) {
                const cols = rowStr.split(',').map(c => c.trim());
                const row: any = {};
                headers.forEach((h, idx) => row[h] = cols[idx]);

                // Map fields
                const phone = row['account_name'] || row['phone'] || row['username'];
                const rawPass = row['password'] || row['token'];
                const status = row['status'] || 'Ready';
                const systemType = row['system_type'] || 'Android'; // Default
                
                if (!phone || !rawPass) {
                    failed++;
                    continue;
                }

                const tokenCipher = encrypt(rawPass); // Encrypt password/token
                values.push(phone, tokenCipher, systemType, status);
            }

            if (values.length > 0) {
                const placeholders = values.map((_, idx) => idx % 4 === 0 ? '(?, ?, ?, ?, NOW(3))' : '').filter(Boolean).join(',');
                const conn = await pool.getConnection();
                try {
                    // Use INSERT IGNORE to skip duplicates (Strict de-duplication)
                    const [res]: any = await conn.query(
                        `INSERT IGNORE INTO accounts (phone, token_cipher, system_type, status, updated_at) 
                         VALUES ${placeholders}`,
                        values
                    );
                    const insertedCount = res.affectedRows;
                    success += insertedCount;
                    // Calculate skipped (total attempted in this batch - actually inserted)
                    // Note: This is an approximation if batch has internal duplicates, but good enough for bulk
                    skipped += (values.length / 4) - insertedCount;
                } catch (e) {
                    console.error('Batch import failed', e);
                    failed += (values.length / 4);
                } finally {
                    conn.release();
                }
            }

            processed += chunk.length;
            await updateJobProgress(jobId, Math.floor((processed / total) * 100), 'PROCESSING');
            // Yield to event loop
            await new Promise(resolve => setTimeout(resolve, 0));
        }

        const msg = `Success: ${success}, Skipped (Duplicate): ${skipped}, Failed (Format): ${failed}`;
        await updateJobProgress(jobId, 100, 'COMPLETED', msg);
        await createAuditLog('IMPORT', 'TN_ACCOUNT', { jobId, total, success, skipped, failed }, userId);

    } catch (e: any) {
        console.error('Import job failed', e);
        await updateJobProgress(jobId, 0, 'FAILED', e.message);
    }
}

// Distribution Processor
async function processDistributionJob(jobId: string, perSubAccount: number, userId?: number) {
    const conn = await pool.getConnection();
    try {
        await updateJobProgress(jobId, 0, 'PROCESSING', 'Fetching accounts...');
        
        const totalLimit = 10000;

        // 1. Get active sub-accounts
        const [subAccounts]: any = await conn.query("SELECT * FROM sub_accounts WHERE status = 'ACTIVE'");
        if (!subAccounts.length) {
            await updateJobProgress(jobId, 100, 'FAILED', 'No active sub-accounts found');
            return;
        }

        // 2. Get unassigned accounts
        const [unassigned]: any = await conn.query(`
            SELECT a.id FROM accounts a 
            LEFT JOIN account_assignments aa ON a.id = aa.tn_account_id 
            WHERE aa.id IS NULL AND a.status = 'Ready'
            LIMIT ?
        `, [totalLimit]);
        
        let unassignedPool = unassigned.map((r: any) => r.id);
        const totalAvailable = unassignedPool.length;
        let assignedTotal = 0;

        await updateJobProgress(jobId, 10, 'PROCESSING', `Found ${totalAvailable} available accounts`);

        // 3. Distribute
        for (const sa of subAccounts) {
            if (unassignedPool.length === 0) break;

            // Check current assignment count
            // We want to fill up to quota_limit (or perSubAccount default)
            // Count ACTIVE assignments
            const [rows]: any = await conn.query("SELECT COUNT(*) as count FROM account_assignments WHERE sub_account_id = ? AND status = 'ACTIVE'", [sa.id]);
            const currentCount = rows[0].count;
            const limit = sa.quota_limit > 0 ? sa.quota_limit : perSubAccount;
            
            const needed = Math.max(0, limit - currentCount);
            if (needed <= 0) continue;

            const batch = unassignedPool.splice(0, needed);
            if (batch.length > 0) {
                // MySQL2 bulk insert requires flattened array
                const values = batch.map((aid: any) => [aid, sa.id, 'ACTIVE']);
                const placeholders = batch.map(() => '(?, ?, ?)').join(',');
                const flatValues = [];
                for (const pair of values) { flatValues.push(pair[0], pair[1], pair[2]); }

                await conn.execute(
                    `INSERT INTO account_assignments (tn_account_id, sub_account_id, status) VALUES ${placeholders}`,
                    flatValues
                );
                assignedTotal += batch.length;
            }
        }

        await updateJobProgress(jobId, 100, 'COMPLETED', `Assigned ${assignedTotal} accounts`);
        await createAuditLog('AUTO_ASSIGN', 'TN_ACCOUNT', { jobId, assignedTotal, totalAvailable }, userId);

    } catch (e: any) {
        console.error('Distribution job failed', e);
        await updateJobProgress(jobId, 0, 'FAILED', e.message);
    } finally {
        conn.release();
    }
}


app.post('/api/accounts/import-file', upload.single('file') as any, async (req, res) => {
    const file = (req as MulterRequest).file;
    if (!file) return res.status(400).json({ error: 'No file' });

    // Lock check: Is there any running job?
    const conn = await pool.getConnection();
    const [running]: any = await conn.query("SELECT id FROM import_jobs WHERE status IN ('PENDING', 'PROCESSING') LIMIT 1");
    if (running.length > 0) {
        conn.release();
        return res.status(409).json({ error: 'System is busy with another import/distribution task. Please try again later.' });
    }

    const jobId = crypto.randomUUID();
    const userId = req.body.user_id ? parseInt(req.body.user_id) : undefined;

    await conn.execute(
        'INSERT INTO import_jobs (id, status, created_at) VALUES (?, "PENDING", NOW())',
        [jobId]
    );
    conn.release();

    // Start async processing
    fs.readFile(file.path).then(buffer => {
        processImportJob(jobId, buffer, userId);
        // Clean up file
        fs.unlink(file.path).catch(() => {}); 
    });

    res.json({ success: true, jobId });
});

app.get('/api/jobs/:id', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const [rows]: any = await conn.execute('SELECT * FROM import_jobs WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Job not found' });
        res.json(rows[0]);
    } finally {
        conn.release();
    }
});

app.post('/api/distribution/auto', async (req, res) => {
    const { per_sub_account } = req.body;
    const jobId = crypto.randomUUID();
    
    const conn = await pool.getConnection();
    await conn.execute(
        'INSERT INTO import_jobs (id, status, details, created_at) VALUES (?, "PENDING", "Distribution Job", NOW())',
        [jobId]
    );
    conn.release();

    processDistributionJob(jobId, per_sub_account || 10);

    res.json({ success: true, jobId });
});

app.post('/api/distribution/replenish', async (req, res) => {
    const { subAccountId, taskId, deadAccountIds, force } = req.body; // deadAccountIds is array of tn_account_id
    if (!subAccountId || !taskId || !Array.isArray(deadAccountIds) || deadAccountIds.length === 0) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        // 1. Check Replenishment Limit
        const [stats]: any = await conn.query(
            'SELECT replenishment_count FROM task_sub_account_stats WHERE task_id = ? AND sub_account_id = ?',
            [taskId, subAccountId]
        );
        const currentCount = stats[0]?.replenishment_count || 0;
        
        if (currentCount >= 3 && !force) {
            await conn.rollback();
            return res.status(403).json({ error: 'Replenishment limit reached (Max 3). Use force=true to override.' });
        }

        // 2. Mark Accounts as DEAD
        const placeholders = deadAccountIds.map(() => '?').join(',');
        await conn.execute(
            `UPDATE accounts SET status = 'Dead', updated_at = NOW(3) WHERE id IN (${placeholders})`,
            deadAccountIds
        );

        // 3. Update Assignments to DEAD
        await conn.execute(
            `UPDATE account_assignments SET status = 'DEAD', failure_reason = 'Manual Replenishment' 
             WHERE sub_account_id = ? AND tn_account_id IN (${placeholders}) AND status = 'ACTIVE'`,
            [subAccountId, ...deadAccountIds]
        );

        // 4. Find Replacements
        const needed = deadAccountIds.length;
        const [replacements]: any = await conn.query(
            `SELECT id FROM accounts 
             WHERE status = 'Ready' 
             AND id NOT IN (SELECT tn_account_id FROM account_assignments WHERE status = 'ACTIVE')
             LIMIT ?`,
            [needed]
        );

        if (replacements.length < needed) {
            // Option: Fail or Partial? Let's do partial but warn.
            // For now, proceed with what we have.
        }

        // 5. Assign New Accounts
        if (replacements.length > 0) {
            const values = replacements.map((r: any) => [r.id, subAccountId, taskId, 'ACTIVE']);
            const insertPlaceholders = values.map(() => '(?, ?, ?, ?)').join(',');
            const flatValues = values.flat();

            await conn.execute(
                `INSERT INTO account_assignments (tn_account_id, sub_account_id, task_id, status) VALUES ${insertPlaceholders}`,
                flatValues
            );
        }

        // 6. Update Stats
        await conn.execute(
            `INSERT INTO task_sub_account_stats (task_id, sub_account_id, replenishment_count, last_replenished_at)
             VALUES (?, ?, 1, NOW())
             ON DUPLICATE KEY UPDATE replenishment_count = replenishment_count + 1, last_replenished_at = NOW()`,
            [taskId, subAccountId]
        );

        // 7. Audit Log
        await createAuditLog('REPLENISH', 'SUB_ACCOUNT', {
            subAccountId, taskId, deadCount: deadAccountIds.length, replenishedCount: replacements.length, force
        }, req.body.userId);

        await conn.commit();
        res.json({ 
            success: true, 
            replenished: replacements.length, 
            new_count: currentCount + 1 
        });

    } catch (e: any) {
        await conn.rollback();
        res.status(500).json({ error: 'Replenishment failed', detail: e.message });
    } finally {
        conn.release();
    }
});

app.get('/api/subaccounts/:id/accounts', async (req, res) => {
    const subAccountId = req.params.id;
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;

    const conn = await pool.getConnection();
    try {
        const [rows]: any = await conn.query(`
            SELECT a.id, a.phone, a.status as account_status, a.system_type, aa.assigned_at, aa.status as assignment_status
            FROM accounts a
            JOIN account_assignments aa ON a.id = aa.tn_account_id
            WHERE aa.sub_account_id = ?
            ORDER BY aa.assigned_at DESC
            LIMIT ? OFFSET ?
        `, [subAccountId, limit, offset]);

        const [count]: any = await conn.query(
            'SELECT COUNT(*) as total FROM account_assignments WHERE sub_account_id = ?',
            [subAccountId]
        );

        // Map status for frontend compatibility if needed
        const items = rows.map((r: any) => ({
            ...r,
            status: r.assignment_status === 'ACTIVE' ? r.account_status : 'Dead' // Show as Dead if assignment is Dead/Replaced
        }));

        res.json({
            items: items,
            pagination: {
                total: count[0].total,
                page,
                limit,
                totalPages: Math.ceil(count[0].total / limit)
            }
        });
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to fetch assigned accounts', detail: err.message });
    } finally {
        conn.release();
    }
});

// --- End New Features ---

// --- Work Tasks Management (Board) ---

app.get('/api/work-tasks', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const status = req.query.status as string;
        const priority = req.query.priority as string;
        const subAccountId = req.query.subAccountId;
        const search = req.query.search as string;

        let where = 'WHERE 1=1';
        const params: any[] = [];

        if (status && status !== 'all') { where += ' AND t.status = ?'; params.push(status); }
        if (priority && priority !== 'all') { where += ' AND t.priority = ?'; params.push(priority); }
        if (subAccountId) { where += ' AND t.sub_account_id = ?'; params.push(subAccountId); }
        if (search) { where += ' AND (t.title LIKE ? OR t.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

        const [rows]: any = await conn.query(`
            SELECT t.*, sa.name as assignee_name, a.phone as tn_account_phone 
            FROM tasks t
            LEFT JOIN sub_accounts sa ON t.sub_account_id = sa.id
            LEFT JOIN accounts a ON t.tn_account_id = a.id
            ${where}
            ORDER BY t.created_at DESC
        `, params);
        res.json(rows);
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    } finally {
        conn.release();
    }
});

app.post('/api/work-tasks', async (req, res) => {
    const { 
        title, description, priority, tn_account_id, deadline_at,
        min_interval, max_interval, message_type, message_content, phones, tn_account_ids
    } = req.body;
    
    const conn = await pool.getConnection();
    try {
        await conn.execute(
            `INSERT INTO tasks (
                title, description, priority, tn_account_id, deadline_at,
                min_interval, max_interval, message_type, message_content, phones, tn_account_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                title, description, priority || 'medium', tn_account_id || null, deadline_at || null,
                min_interval || 300, max_interval || 480, message_type || 'text', message_content || '', 
                phones || '', tn_account_ids ? JSON.stringify(tn_account_ids) : null
            ]
        );
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    } finally {
        conn.release();
    }
});

app.patch('/api/work-tasks/:id', async (req, res) => {
    const { status, sub_account_id } = req.body;
    const id = req.params.id;
    const conn = await pool.getConnection();
    try {
        const updates: string[] = [];
        const params: any[] = [];
        
        if (status) { updates.push('status = ?'); params.push(status); }
        if (sub_account_id !== undefined) { updates.push('sub_account_id = ?'); params.push(sub_account_id); }
        
        if (updates.length > 0) {
            params.push(id);
            await conn.execute(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ?`, params);
            
            if (status === 'completed') {
                await conn.execute('INSERT INTO audit_logs (action, resource_type, resource_id, payload) VALUES (?, ?, ?, ?)',
                    ['COMPLETE_TASK', 'TASK', id, JSON.stringify({ status })]);
            }

            io.emit('task_updated', { id, status, sub_account_id });
        }
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    } finally {
        conn.release();
    }
});

// --- End Work Tasks ---

// --- Dashboard Stats API ---
app.get('/api/dashboard/stats', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        // 1. Task Stats
        const [taskRows]: any = await conn.query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'RUNNING' THEN 1 ELSE 0 END) as running,
                SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed
            FROM tasks
        `);
        const taskStats = taskRows[0];
        const completionRate = taskStats.total > 0 
            ? Math.round((taskStats.completed / taskStats.total) * 100) 
            : 0;

        // 2. Account Stats
        const [accRows]: any = await conn.query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'Ready' OR status = 'Online' THEN 1 ELSE 0 END) as online,
                SUM(CASE WHEN status = 'Cooldown' THEN 1 ELSE 0 END) as cooldown
            FROM accounts
        `);
        const accStats = accRows[0];

        // 3. Message Stats (Today)
        const [todayRows]: any = await conn.query(`
            SELECT 
                COUNT(*) as sent,
                0 as failed -- Placeholder until we have message level logs
            FROM tasks 
            WHERE created_at >= CURDATE()
        `);
        
        res.json({
            task: {
                totalTasks: taskStats.total,
                runningTasks: taskStats.running,
                completionRate: completionRate,
                failedTasks: taskStats.failed
            },
            account: {
                totalAccounts: accStats.total,
                onlineAccounts: accStats.online,
                cooldownAccounts: accStats.cooldown,
                todaySent: todayRows[0].sent,
                todayFailed: todayRows[0].failed
            }
        });

    } catch (e: any) {
        console.error(e);
        res.status(500).json({ error: 'Failed to fetch stats' });
    } finally {
        conn.release();
    }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, captchaId, captcha } = req.body;
    if (!username || !password || !captchaId || !captcha) {
      return res.status(400).json({ error: 'Username, password, captchaId, and captcha are required' });
    }

    // Validate captcha
    const storedCaptcha = captchas[captchaId];
    if (!storedCaptcha || storedCaptcha.value !== captcha || storedCaptcha.expires < Date.now()) {
      delete captchas[captchaId]; // Invalidate used or expired captcha
      return res.status(400).json({ error: 'Invalid or expired captcha' });
    }
    delete captchas[captchaId]; // Captcha is valid, delete to prevent reuse

    const conn = await pool.getConnection();
    try {
      const [rows]: any = await conn.query(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        [username, password]
      );
      if (rows.length > 0) {
        res.json({ success: true, user: { username: rows[0].username } });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } finally {
      conn.release();
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Login failed', detail: String(err?.message || err) });
  }
});

app.post('/api/upload', upload.single('file') as any, async (req, res) => {
    try {
        const file = (req as MulterRequest).file;
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Return public URL (assuming backend is proxied via nginx at /api or direct access)
        // If via Nginx proxy_pass, we need to handle the path correctly.
        // In this setup, static files are served at /uploads
        const publicUrl = `/uploads/${file.filename}`;
        
        res.json({ success: true, url: publicUrl });
    } catch (err: any) {
        res.status(500).json({ error: 'Upload failed', detail: err.message });
    }
});

app.post('/api/privacy/status', async (req, res) => {
  const { status, userId } = req.body; // status: 'accepted' | 'rejected'
  const conn = await pool.getConnection();
  try {
      // In a real app, update user table or privacy_status table
      // Here we just log it for audit
      await conn.execute(
          'INSERT INTO audit_logs (user_id, action, resource_type, payload) VALUES (?, ?, "PRIVACY", ?)',
          [userId || null, 'PRIVACY_CONSENT', JSON.stringify({ status })]
      );
      res.json({ success: true });
  } finally {
      conn.release();
  }
});

app.get('/api/privacy/status', async (req, res) => {
    // Return mock status or fetch from DB
    res.json({ status: 'unknown' });
});

app.post('/api/audit/privacy', async (req, res) => {
  const { action, userId } = req.body; // action: 'enable_privacy' | 'disable_privacy'
  const conn = await pool.getConnection();
  try {
      await conn.execute(
          'INSERT INTO audit_logs (user_id, action, resource_type, payload) VALUES (?, ?, "TAX_REPORT", ?)',
          [userId || null, action, JSON.stringify({ timestamp: new Date() })]
      );
      res.json({ success: true });
  } finally {
      conn.release();
  }
});

// Compliance endpoints
app.post('/api/compliance/upload', upload.single('files') as any, async (req, res) => {
  const sandboxMode = req.headers['x-sandbox-mode'];
  if (sandboxMode !== 'true') {
    return res.status(403).json({ error: 'Module not available' });
  }

  const multerReq = req as MulterRequest;
  try {
    const { entityName, taxId, address, documentType } = multerReq.body;
    const file = multerReq.file;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.execute(
        `INSERT INTO compliance_requests (entity_name, tax_id, address, document_type, file_path)
         VALUES (?, ?, ?, ?, ?)`,
        [entityName, taxId, address, documentType || 'Other', file.path]
      );
      res.json({ success: true, message: 'Documents uploaded successfully' });
    } finally {
      conn.release();
    }
  } catch (err: any) {
    res.status(500).json({ error: 'Upload failed', detail: String(err?.message || err) });
  }
});

app.get('/api/compliance/status', async (req, res) => {
  const sandboxMode = req.headers['x-sandbox-mode'];
  if (sandboxMode !== 'true') {
    return res.status(403).json({ error: 'Module not available' });
  }

  const conn = await pool.getConnection();
  try {
    // For now, just return the latest request. In a real app, you'd filter by user/account.
    const [rows]: any = await conn.query(
      'SELECT * FROM compliance_requests ORDER BY created_at DESC LIMIT 1'
    );
    
    if (rows.length === 0) {
      return res.json({ status: 'none', message: 'No compliance requests found' });
    }
    
    const req = rows[0];
    res.json({ 
      status: req.status, 
      message: req.status === 'pending' ? 'Review in progress' : 
               req.status === 'approved' ? 'Compliance verified' : 'Request rejected',
      details: req
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch status', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.post('/api/accounts/import', async (req, res) => {
  const { accounts } = req.body;
  if (!accounts || !Array.isArray(accounts)) {
    // If no body, try directory scan fallback
    try {
        const result = await loadAccountsFromDir(SCAN_DIR);
        return res.json({ triggered: true, method: 'directory', ...result });
    } catch (e) {
        return res.status(400).json({ error: 'Invalid payload and directory scan failed' });
    }
  }

  const rows: Array<{ phone: string; token_cipher: Buffer; proxy_url: string; system_type: string }> = [];

  for (const acc of accounts) {
    try {
      let token = '';
      let phone = '';
      let systemType = 'Other';
      
      // Always stringify the full account object to preserve all business fields
      // (email, password, clientId, signature, appVersion, userAgent, etc.)
      // unless it's a legacy format where we only have a token string.
      
      phone = acc.phone || acc.username || '';
      
      // Default values for optional fields
      if (!acc.platform) acc.platform = 'web';
      if (!acc.appVersion) acc.appVersion = 'latest';
      
      // Construct systemType based on platform or heuristics
      if (acc.platform) {
          systemType = acc.platform === 'ios' ? 'iOS' : (acc.platform === 'android' ? 'Android' : 'Web');
      } else {
          // Fallback detection if platform is missing (though we set default above, this covers legacy/mixed)
          if (acc.Cookie || acc.cookie) systemType = 'iOS';
          else if (acc.brand || acc.fp) systemType = 'Android';
      }

      // Store EVERYTHING in token_cipher as JSON
      token = JSON.stringify(acc);

      if (!phone) continue;

      // Use a default proxy if not provided in JSON (or handle rotation logic elsewhere)
      const proxyUrl = acc.proxy_url || process.env.DEFAULT_PROXY_URL || '';

      rows.push({
        phone: String(phone).replace(/\D/g, ''),
        token_cipher: encrypt(token),
        proxy_url: proxyUrl,
        system_type: systemType
      });
    } catch (e) {
      console.warn('Skipping invalid account entry', e);
    }
  }

  if (!rows.length) return res.json({ inserted: 0, updated: 0 });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let inserted = 0;
    let updated = 0;
    
    // Batch insert for performance (e.g. 500 at a time)
    const BATCH_SIZE = 500;
    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        const chunk = rows.slice(i, i + BATCH_SIZE);
        
        // Prepare bulk insert query
        // ON DUPLICATE KEY UPDATE is complex with bulk insert in MySQL driver with placeholders
        // So we use a simpler approach: Insert Ignore or Replace, or loop inside transaction but faster?
        // Actually, for maximum speed with updates, we can use "INSERT ... ON DUPLICATE KEY UPDATE"
        // but we need to construct the values string dynamically.
        
        const values: any[] = [];
        const placeholders = chunk.map(() => '(?, ?, ?, ?, "Ready", NOW(3))').join(',');
        
        for (const r of chunk) {
            values.push(r.phone, r.token_cipher, r.proxy_url, r.system_type);
        }
        
        const [result]: any = await conn.execute(
            `INSERT INTO accounts (phone, token_cipher, proxy_url, system_type, status, last_used_at)
             VALUES ${placeholders}
             ON DUPLICATE KEY UPDATE
               token_cipher = VALUES(token_cipher),
               proxy_url = VALUES(proxy_url),
               system_type = VALUES(system_type),
               status = 'Ready',
               updated_at = CURRENT_TIMESTAMP(3)`,
            values
        );
        // Approximation of inserted/updated count is hard with bulk, but we can assume success
        // affectedRows: 1 per insert, 2 per update. 
        // We can just track total processed.
        inserted += chunk.length; 
    }

    await conn.commit();
    res.json({ inserted, updated, count: rows.length, message: 'Bulk import successful' });
  } catch (e: any) {
    await conn.rollback();
    res.status(500).json({ error: 'Database error', detail: e.message });
  } finally {
    conn.release();
  }
});

app.get('/api/accounts/export', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const [rows]: any = await conn.query(
            "SELECT phone, token_cipher, proxy_url, system_type FROM accounts"
        );
        
        const exportData = rows.map((r: any) => {
            let tokenStr = '';
            try {
                tokenStr = decrypt(r.token_cipher);
            } catch (e) {
                // If decryption fails, tokenStr remains empty
            }

            // Try to parse if it's JSON (iOS headers format)
            try {
                if (tokenStr.startsWith('{')) {
                    const parsed = JSON.parse(tokenStr);
                    return { ...parsed, phone: r.phone, proxy_url: r.proxy_url };
                }
            } catch {}
            
            // Fallback for simple Android token
            return {
                phone: r.phone,
                token: tokenStr,
                proxy_url: r.proxy_url,
                system_type: r.system_type
            };
        });
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=accounts_export.json');
        res.json(exportData);
    } catch (err: any) {
        res.status(500).json({ error: 'Export failed', detail: err.message });
    } finally {
        conn.release();
    }
});

app.get('/api/v2/get-individual-whatsapp-list', async (req, res) => {
    const conn = await pool.getConnection();
    try {
        const page = Math.max(1, parseInt(req.query.page as string) || 1);
        const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
        const offset = (page - 1) * limit;
        const status = req.query.status as string;
        const search = req.query.search as string;

        let whereClause = 'WHERE 1=1';
        const queryParams: any[] = [];

        if (status) {
            whereClause += ' AND status = ?';
            queryParams.push(status);
        }
        if (search) {
            whereClause += ' AND phone LIKE ?';
            queryParams.push(`%${search}%`);
        }

        const [countRows]: any = await conn.execute(
            `SELECT COUNT(*) as total FROM accounts ${whereClause}`,
            queryParams
        );
        const total = countRows[0].total;

        const [rows]: any = await conn.query(
            `SELECT id, phone, status, system_type, proxy_url, last_used_at, updated_at,
             CASE WHEN tn_session_id IS NOT NULL THEN 1 ELSE 0 END as tn_ready
             FROM accounts ${whereClause}
             ORDER BY updated_at DESC
             LIMIT ? OFFSET ?`,
            [...queryParams, limit, offset]
        );

        res.json({
            items: rows,
            pagination: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to fetch accounts', detail: String(err?.message || err) });
    } finally {
        conn.release();
    }
});

app.get('/api/v2/get-contact-list', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;
    const subAccountId = req.query.subAccountId ? parseInt(req.query.subAccountId as string) : null;
    const status = req.query.status as string;
    const search = req.query.search as string;

    let whereClause = 'WHERE 1=1';
    const params: any[] = [];
    
    if (subAccountId) {
      whereClause += ' AND s.sub_account_id = ?';
      params.push(subAccountId);
    }
    if (status) {
        whereClause += ' AND s.status = ?';
        params.push(status);
    }
    if (search) {
        whereClause += ' AND (s.customer_phone LIKE ? OR a.phone LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    await conn.execute(`
        INSERT IGNORE INTO chat_sessions (tn_account_id, customer_phone, last_message_at, status, sub_account_id)
        SELECT i.account_id, i.sender_phone, MAX(i.received_at), 'waiting',
               (SELECT sub_account_id FROM account_assignments WHERE tn_account_id = i.account_id LIMIT 1)
        FROM inbound_messages i
        GROUP BY i.account_id, i.sender_phone
    `);

    await conn.execute(`
        UPDATE chat_sessions s
        JOIN (
            SELECT account_id, sender_phone, MAX(received_at) as last_inbound
            FROM inbound_messages 
            WHERE is_read = 0 
            GROUP BY account_id, sender_phone
        ) i ON s.tn_account_id = i.account_id AND s.customer_phone = i.sender_phone
        SET s.status = 'waiting', 
            s.last_message_at = GREATEST(COALESCE(s.last_message_at, '1970-01-01'), i.last_inbound)
    `);

    await conn.execute(`
        INSERT IGNORE INTO chat_sessions (tn_account_id, customer_phone, last_message_at, status, sub_account_id)
        SELECT t.account_id, t.target_phone, MAX(t.created_at), 'active',
               (SELECT sub_account_id FROM account_assignments WHERE tn_account_id = t.account_id LIMIT 1)
        FROM message_tasks t
        WHERE t.status = 'Sent'
        GROUP BY t.account_id, t.target_phone
    `);
    
    await conn.execute(`
        UPDATE chat_sessions s
        JOIN (
            SELECT account_id, target_phone, MAX(created_at) as last_outbound
            FROM message_tasks 
            WHERE status = 'Sent'
            GROUP BY account_id, target_phone
        ) t ON s.tn_account_id = t.account_id AND s.customer_phone = t.target_phone
        SET s.last_message_at = GREATEST(COALESCE(s.last_message_at, '1970-01-01'), t.last_outbound)
    `);

    const [rows]: any = await conn.query(`
      SELECT 
        s.id,
        s.tn_account_id,
        s.customer_phone,
        s.status,
        s.sub_account_id,
        s.last_message_at,
        a.phone as account_phone,
        sa.name as sub_account_name,
        (SELECT COUNT(*) FROM inbound_messages m WHERE m.account_id = s.tn_account_id AND m.sender_phone = s.customer_phone AND m.is_read = 0) as unread_count
      FROM chat_sessions s
      JOIN accounts a ON s.tn_account_id = a.id
      LEFT JOIN sub_accounts sa ON s.sub_account_id = sa.id
      ${whereClause}
      ORDER BY s.last_message_at DESC
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

    const [countRows]: any = await conn.query(`
      SELECT COUNT(*) as total 
      FROM chat_sessions s 
      JOIN accounts a ON s.tn_account_id = a.id
      ${whereClause}
    `, params);
    const total = countRows[0].total;

    res.json({
      items: rows,
      pagination: { total, page, limit, totalPages: Math.ceil(total / limit) }
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch contacts', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

app.get('/api/v2/get-message-list', async (req, res) => {
  const accountId = req.query.accountId ? parseInt(req.query.accountId as string) : null;
  const phone = req.query.phone as string;
  if (!accountId || !phone) {
    return res.status(400).json({ error: 'accountId and phone are required' });
  }
  const conn = await pool.getConnection();
  try {
    const [inbound]: any = await conn.query(
      `SELECT id, content, media_url, received_at as created_at, 'inbound' as direction, is_read 
       FROM inbound_messages 
       WHERE account_id = ? AND sender_phone = ?`,
      [accountId, phone]
    );

    const [outbound]: any = await conn.query(
      `SELECT id, content, media_url, created_at, 'outbound' as direction, status
       FROM message_tasks 
       WHERE account_id = ? AND target_phone = ?`,
      [accountId, phone]
    );

    const messages = [...inbound, ...outbound].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    res.json({ items: messages });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch messages', detail: String(err?.message || err) });
  } finally {
    conn.release();
  }
});

// Serve Frontend Static Files
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendPath = path.join(__dirname, '../../frontend/dist');
console.log('Serving frontend from:', frontendPath);
app.use(express.static(frontendPath));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Not Found' });
  }
  const indexHtml = path.join(frontendPath, 'index.html');
  console.log('Serving index.html from:', indexHtml);
  res.sendFile(indexHtml, (err) => {
    if (err) {
      console.error('Failed to send index.html:', err);
      res.status(500).send('Error loading frontend');
    }
  });
});

const port = +(process.env.PORT || 3001);
server.listen(port, () => {
  console.log(`API listening on http://0.0.0.0:${port}`);
});
