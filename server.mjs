import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GoogleGenAI } from '@google/genai';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const STORE_FILE = path.join(DATA_DIR, 'store.json');

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('Set JWT_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}

if (!ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 characters).');
  process.exit(1);
}

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

let store = { users: [], contributions: [] };

try {
  if (fs.existsSync(STORE_FILE)) {
    store = {
      ...store,
      ...JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'))
    };
  }
} catch (error) {
  console.error('Could not read data store:', error.message);
  process.exit(1);
}

function saveStore() {
  const temp = STORE_FILE + '.tmp';

  fs.writeFileSync(
    temp,
    JSON.stringify(store, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(temp, STORE_FILE);
}

app.disable('x-powered-by');

app.use(cors({
  origin: (origin, callback) => {
    const allowed = (
      process.env.ALLOWED_ORIGINS ||
      'https://krishna692006.github.io,http://localhost:3000,http://127.0.0.1:3000'
    )
      .split(',')
      .map(x => x.trim())
      .filter(Boolean);

    if (!origin || allowed.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS'));
  },

  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '150kb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', apiLimiter);

const otpStore = new Map();

const transporter =
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || 'false') === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      })
    : null;

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: payload.role === 'admin' ? '8h' : '7d',
    issuer: 'herbal-plant-explorer'
  });
}

function auth(requiredRole = 'member') {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

    if (!token) {
      return res.status(401).json({
        error: 'Please sign in first.'
      });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        issuer: 'herbal-plant-explorer'
      });

      if (requiredRole && decoded.role !== requiredRole) {
        return res.status(403).json({
          error: 'Not authorised.'
        });
      }

      req.user = decoded;
      next();

    } catch {
      return res.status(401).json({
        error: 'Your session has expired. Please sign in again.'
      });
    }
  };
}

function cleanText(value, max) {
  return typeof value === 'string'
    ? value.trim().slice(0, max)
    : '';
}

function safeFileName(name) {
  return String(name || 'attachment')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 100);
}

const allowedMimes = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'image/png',
  'image/jpeg',
  'image/webp'
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },

  filename: (_req, file, cb) => {
    cb(
      null,
      `${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${safeFileName(file.originalname)}`
    );
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 8 * 1024 * 1024,
    files: 1
  },

  fileFilter: (_req, file, cb) => {
    if (!allowedMimes.has(file.mimetype)) {
      return cb(
        new Error('Only PDF, DOC, DOCX, TXT, PNG, JPG and WEBP files are allowed.')
      );
    }

    cb(null, true);
  }
});

// HEALTH CHECK

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'Herbal Plant Explorer Knowledge Hub'
  });
});

// EMAIL OTP REQUEST

app.post('/api/auth/request-otp', otpLimiter, async (req, res) => {
  const email = cleanText(req.body?.email, 180).toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: 'Enter a valid email address.'
    });
  }

  if (!transporter || !process.env.MAIL_FROM) {
    return res.status(503).json({
      error: 'Email OTP is not configured yet. Add SMTP settings and MAIL_FROM to the backend environment.'
    });
  }

  const otp = String(crypto.randomInt(100000, 1000000));

  otpStore.set(email, {
    hash: crypto.createHash('sha256').update(otp).digest('hex'),
    expires: Date.now() + 5 * 60 * 1000,
    attempts: 0
  });

  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: 'Your Herbal Plant Explorer verification code',
      text: `Your verification code is ${otp}. It expires in 5 minutes. If you did not request this, ignore this email.`
    });

    res.json({
      ok: true,
      message: 'A 6-digit OTP has been sent to your email. It expires in 5 minutes.'
    });

  } catch (error) {
    otpStore.delete(email);

    console.error('OTP email failed:', error.message);

    res.status(502).json({
      error: 'Could not send verification email. Check SMTP settings.'
    });
  }
});

// VERIFY OTP

app.post('/api/auth/verify-otp', otpLimiter, (req, res) => {
  const email = cleanText(req.body?.email, 180).toLowerCase();
  const otp = cleanText(req.body?.otp, 6);

  const saved = otpStore.get(email);

  if (
    !saved ||
    saved.expires < Date.now() ||
    saved.attempts >= 5
  ) {
    otpStore.delete(email);

    return res.status(400).json({
      error: 'OTP expired or not requested. Request a new OTP.'
    });
  }

  saved.attempts += 1;

  const hash = crypto.createHash('sha256')
    .update(otp)
    .digest('hex');

  if (!/^\d{6}$/.test(otp) || hash !== saved.hash) {
    return res.status(400).json({
      error: 'Incorrect OTP.'
    });
  }

  otpStore.delete(email);

  let user = store.users.find(u => u.email === email);

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      createdAt: new Date().toISOString(),
      role: 'member'
    };

    store.users.push(user);
    saveStore();
  }

  res.json({
    ok: true,
    token: signToken({
      sub: user.id,
      email: user.email,
      role: 'member'
    }),
    user: {
      id: user.id,
      email: user.email
    }
  });
});

// MEMBER CONTRIBUTIONS

app.post('/api/contributions', auth('member'), (req, res) => {
  upload.single('attachment')(req, res, error => {
    if (error) {
      return res.status(400).json({
        error: error.message || 'File upload failed.'
      });
    }

    const category = cleanText(req.body?.category, 60);
    const title = cleanText(req.body?.title, 140);
    const content = cleanText(req.body?.content, 12000);

    if (!category || !title || !content) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }

      return res.status(400).json({
        error: 'Section, title and contribution text are required.'
      });
    }

    const item = {
      id: crypto.randomUUID(),
      userId: req.user.sub,
      email: req.user.email,
      category,
      title,
      content,
      status: 'pending',

      attachmentUrl: req.file
        ? `/api/attachments/${path.basename(req.file.filename)}`
        : null,

      attachmentName: req.file
        ? safeFileName(req.file.originalname)
        : null,

      createdAt: new Date().toISOString(),
      reviewedAt: null,
      reviewNote: ''
    };

    store.contributions.unshift(item);
    saveStore();

    res.status(201).json({
      ok: true,
      id: item.id,
      status: item.status
    });
  });
});

// MEMBER'S OWN CONTRIBUTIONS

app.get('/api/my/contributions', auth('member'), (req, res) => {
  const items = store.contributions
    .filter(x => x.userId === req.user.sub)
    .map(({ id, category, title, status, createdAt }) => ({
      id,
      category,
      title,
      status,
      createdAt
    }));

  res.json({ items });
});

// PRIVATE ATTACHMENTS

app.get('/api/attachments/:filename', (req, res) => {
  const item = store.contributions.find(
    x => x.attachmentUrl === `/api/attachments/${req.params.filename}`
  );

  if (!item) {
    return res.status(404).json({
      error: 'Attachment not found.'
    });
  }

  if (item.status !== 'approved') {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

    if (!token) {
      return res.status(404).json({
        error: 'Attachment not found.'
      });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        issuer: 'herbal-plant-explorer'
      });

      if (
        decoded.role !== 'admin' &&
        decoded.sub !== item.userId
      ) {
        return res.status(404).json({
          error: 'Attachment not found.'
        });
      }

    } catch {
      return res.status(404).json({
        error: 'Attachment not found.'
      });
    }
  }

  const filename = path.basename(req.params.filename);
  const filePath = path.join(UPLOAD_DIR, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      error: 'Attachment not found.'
    });
  }

  res.download(filePath, item.attachmentName || filename);
});

// PUBLIC APPROVED CONTRIBUTIONS

app.get('/api/contributions', (req, res) => {
  const category = cleanText(req.query.category, 60);

  const items = store.contributions
    .filter(x =>
      x.status === 'approved' &&
      (!category || x.category === category)
    )
    .map(({
      id,
      category,
      title,
      content,
      attachmentUrl,
      attachmentName,
      createdAt
    }) => ({
      id,
      category,
      title,
      content,
      attachmentUrl,
      attachmentName,
      createdAt
    }));

  res.json({ items });
});

// ADMIN LOGIN

app.post('/api/admin/login', otpLimiter, (req, res) => {
  const email = cleanText(req.body?.email, 180).toLowerCase();

  const password =
    typeof req.body?.password === 'string'
      ? req.body.password
      : '';

  const a = Buffer.from(email);
  const b = Buffer.from(ADMIN_EMAIL);

  const p = Buffer.from(password);
  const q = Buffer.from(ADMIN_PASSWORD);

  const emailOK =
    a.length === b.length &&
    crypto.timingSafeEqual(a, b);

  const passwordOK =
    p.length === q.length &&
    crypto.timingSafeEqual(p, q);

  if (!emailOK || !passwordOK) {
    return res.status(401).json({
      error: 'Incorrect administrator credentials.'
    });
  }

  res.json({
    ok: true,
    token: signToken({
      sub: 'site-admin',
      email: ADMIN_EMAIL,
      role: 'admin'
    })
  });
});

// ADMIN CONTRIBUTION REVIEW

app.get('/api/admin/contributions', auth('admin'), (req, res) => {
  const status = [
    'pending',
    'approved',
    'rejected'
  ].includes(req.query.status)
    ? req.query.status
    : 'pending';

  const items = store.contributions
    .filter(x => x.status === status)
    .map(x => ({ ...x }));

  res.json({ items });
});

app.post('/api/admin/contributions/:id/review', auth('admin'), (req, res) => {
  const decision = req.body?.decision;

  if (!['approve', 'reject'].includes(decision)) {
    return res.status(400).json({
      error: 'Decision must be approve or reject.'
    });
  }

  const item = store.contributions.find(
    x => x.id === req.params.id
  );

  if (!item) {
    return res.status(404).json({
      error: 'Submission not found.'
    });
  }

  item.status = decision === 'approve'
    ? 'approved'
    : 'rejected';

  item.reviewedAt = new Date().toISOString();
  item.reviewNote = cleanText(req.body?.note, 500);

  saveStore();

  res.json({
    ok: true,
    id: item.id,
    status: item.status
  });
});

// ADVANCED AI CHAT

const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY
    })
  : null;

const systemInstructions = `
You are HPE Knowledge Assistant for Herbal Plant Explorer.

Your role is to be a capable, friendly educational research assistant.

You can help with:

1. Botany and plant identification concepts.
2. Medicinal plants and their botanical families.
3. Ayurveda history and concepts.
4. Pharmacognosy.
5. Plant chemistry.
6. Herbal cultivation and conservation.
7. Human anatomy education.
8. Scientific research literacy.
9. Reading and understanding research papers.
10. Evidence-based discussions about medicinal plants.

LANGUAGE:
Reply in the language and style used by the user.
Support natural Hindi and Hinglish.

ANSWER STYLE:
Use clear headings and useful bullet points.
Explain difficult scientific terms in simple language.
Give examples when useful.
Avoid unnecessary repetition.

RESEARCH RULES:
First use supplied website data.
Clearly distinguish website data, established general knowledge,
traditional claims and scientific research evidence.

Never invent citations, papers, authors, study results,
plant constituents, safety facts or references.

If evidence is uncertain or unavailable,
say so honestly.

FOR PLANT QUESTIONS:
When relevant explain:
- Botanical identity
- Plant family
- Identifying features
- Parts studied
- Constituents only when supported
- Traditional uses labelled as traditional
- Modern research evidence
- Research limitations
- Safety concerns
- Conservation status when known

CONVERSATION:
Maintain continuity using supplied recent chat history.
Ask one focused clarifying question only when needed.

HEALTH SAFETY:
For personal symptoms, diagnosis, treatment decisions,
medicine selection or dosage, do not diagnose,
prescribe or give dosing.
Provide general educational context and recommend
a qualified healthcare professional.

Never present Ayurveda or any remedy as a guaranteed cure.
`;

app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    if (!ai) {
      return res.status(503).json({
        error: 'AI chat is not configured. Add GEMINI_API_KEY to the backend environment.'
      });
    }

    const message = cleanText(req.body?.message, 4000);

    if (!message) {
      return res.status(400).json({
        error: 'Message is required.'
      });
    }

    const websiteContext = cleanText(
      req.body?.websiteContext,
      60000
    );

    const history = Array.isArray(req.body?.history)
      ? req.body.history
          .slice(-10)
          .map(item => ({
            role: item?.role === 'assistant'
              ? 'assistant'
              : 'user',
            text: cleanText(item?.text, 3000)
          }))
          .filter(item => item.text)
      : [];

    const conversation = history
      .map(item =>
        `${item.role === 'assistant' ? 'ASSISTANT' : 'USER'}: ${item.text}`
      )
      .join('\n');

    const response = await ai.models.generateContent({
      model: process.env.GEMINI_MODEL || 'gemini-3.5-flash',

      contents: `
${systemInstructions}

WEBSITE DATA:
${websiteContext || 'No website data supplied.'}

RECENT CONVERSATION:
${conversation || 'No previous messages.'}

CURRENT USER MESSAGE:
${message}
`
    });

    res.json({
      answer: (response.text || '').trim() ||
        'Sorry, I could not generate a response.'
    });

  } catch (error) {
    console.error('AI chat error:', error.message);

    res.status(500).json({
      error: 'The AI service is temporarily unavailable.'
    });
  }
});

// ERROR HANDLER

app.use((error, _req, res, _next) => {
  console.error('Request error:', error.message);

  if (res.headersSent) return;

  res.status(500).json({
    error: 'The service could not complete this request.'
  });
});

// START SERVER

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Herbal Plant Explorer Knowledge Hub API listening on port ${PORT}`
  );
});
