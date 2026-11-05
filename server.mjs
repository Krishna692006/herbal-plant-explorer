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

let store = {
  users: [],
  contributions: []
};

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

  methods: ['GET', 'POST' , 'PUT'],
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

// ============================================
// ACCOUNT SECURITY & OTP FUNCTIONS
// ============================================

function normalizeEmail(value) {
  return cleanText(value, 160).toLowerCase();
}

function normalizePhone(value) {
  return cleanText(value, 20).replace(/[^\d+]/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^\+[1-9]\d{7,14}$/.test(phone);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto.scryptSync(
    password,
    salt,
    64
  ).toString('hex');

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  try {
    const [salt, originalHash] = storedHash.split(':');

    if (!salt || !originalHash) return false;

    const calculated = crypto.scryptSync(
      password,
      salt,
      64
    );

    const original = Buffer.from(originalHash, 'hex');

    return (
      calculated.length === original.length &&
      crypto.timingSafeEqual(calculated, original)
    );

  } catch {
    return false;
  }
}

function generateOTP() {
  return String(
    crypto.randomInt(100000, 1000000)
  );
}

function otpHash(otp) {
  return crypto
    .createHash('sha256')
    .update(String(otp))
    .digest('hex');
}


// ============================================
// EMAIL OTP SENDER
// ============================================

async function sendEmailOTP(email, otp) {
  if (!transporter) {
    throw new Error(
      'Email service is not configured on the server.'
    );
  }

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,

    to: email,

    subject: 'Herbal Plant Explorer - Verification Code',

    text: `Your verification code is ${otp}. It is valid for 10 minutes. Do not share this code with anyone.`,

    html: `
      <div style="
        font-family:Arial,sans-serif;
        max-width:500px;
        margin:auto;
        padding:25px;
        background:#f4f8f1;
        border-radius:12px;
      ">
        <h2 style="color:#174d2b;">
          Herbal Plant Explorer
        </h2>

        <p>Your account verification code is:</p>

        <div style="
          font-size:32px;
          font-weight:bold;
          letter-spacing:8px;
          color:#174d2b;
          padding:15px;
          background:#ffffff;
          text-align:center;
          border-radius:8px;
        ">
          ${otp}
        </div>

        <p>This code expires in 10 minutes.</p>

        <p style="color:#777;">
          Never share this code with anyone.
        </p>
      </div>
    `
  });
}


// ============================================
// MOBILE SMS OTP SENDER - TWILIO
// ============================================

async function sendMobileOTP(phone, otp) {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioNumber = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !twilioNumber) {
    throw new Error(
      'SMS service is not configured on the server.'
    );
  }

  const url =
    `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;

  const body = new URLSearchParams({
    From: twilioNumber,
    To: phone,
    Body: `Your Herbal Plant Explorer verification code is ${otp}. Valid for 10 minutes. Do not share it.`
  });

  const response = await fetch(url, {
    method: 'POST',

    headers: {
      Authorization:
        'Basic ' +
        Buffer.from(
          `${accountSid}:${authToken}`
        ).toString('base64'),

      'Content-Type': 'application/x-www-form-urlencoded'
    },

    body
  });

  if (!response.ok) {
    const errorText = await response.text();

    console.error('Twilio SMS error:', errorText);

    throw new Error(
      'Could not send SMS. Please check the mobile number or SMS service.'
    );
  }

  return true;
}


// ============================================
// OTP RECORD MANAGEMENT
// ============================================

function saveOTPRecord(email, phone, emailOTP, mobileOTP, pendingUser) {
  const key = email.toLowerCase();

  otpStore.set(key, {
    emailHash: otpHash(emailOTP),
    mobileHash: otpHash(mobileOTP),

    phone,

    pendingUser,

    expiresAt: Date.now() + 10 * 60 * 1000,

    attempts: 0
  });
}


// ============================================
// REGISTRATION - REQUEST OTP
// ============================================

app.post(
  '/api/auth/register/request-otp',
  otpLimiter,

  async (req, res) => {
    try {
      const body = req.body || {};

      const name = cleanText(body.name, 100);
      const email = normalizeEmail(body.email);
      const phone = normalizePhone(body.phone);
      const password = String(body.password || '');

      if (!name || !email || !phone || !password) {
        return res.status(400).json({
          error: 'Please fill all required registration fields.'
        });
      }

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error: 'Please enter a valid email address.'
        });
      }

      if (!isValidPhone(phone)) {
        return res.status(400).json({
          error: 'Enter mobile number with country code, e.g. +919876543210.'
        });
      }

      if (password.length < 8 || password.length > 128) {
        return res.status(400).json({
          error: 'Password must contain 8 to 128 characters.'
        });
      }

      const existingUser = store.users.find(user =>
        normalizeEmail(user.email) === email ||
        normalizePhone(user.phone) === phone
      );

      if (existingUser) {
        return res.status(409).json({
          error: 'An account with this email or mobile number already exists. Please sign in.'
        });
      }

      const emailOTP = generateOTP();
      const mobileOTP = generateOTP();

      const pendingUser = {
        id: crypto.randomUUID(),

        name,

        email,

        phone,

        passwordHash: hashPassword(password),

        role: 'member',

        createdAt: new Date().toISOString(),

        profile: {
          name,

          email,

          phone,

          accountType: cleanText(body.accountType, 50) || 'Student',

          photo: '',

          bio: '',

          country: cleanText(body.country, 80),

          state: cleanText(body.state, 80),

          city: cleanText(body.city, 80),

          course: cleanText(body.course, 100),

          institution: cleanText(body.institution, 150),

          designation: cleanText(body.designation, 100),

          department: cleanText(body.department, 100),

          studyYear: cleanText(body.studyYear, 50),

          experience: cleanText(body.experience, 50),

          researchInterests: cleanText(body.researchInterests, 1000),

          publications: cleanText(body.publications, 1500),

          skills: cleanText(body.skills, 1000),

          languages: cleanText(body.languages, 300),

          website: cleanText(body.website, 250),

          orcid: cleanText(body.orcid, 100),

          privacy: {
            name: 'public',
            photo: 'public',
            bio: 'public',
            accountType: 'public',
            location: 'private',
            education: 'private',
            professional: 'private',
            research: 'private',
            publications: 'private',
            skills: 'private',
            contact: 'private'
          }
        }
      };

      // Save OTP before sending so both codes remain linked.
      saveOTPRecord(
        email,
        phone,
        emailOTP,
        mobileOTP,
        pendingUser
      );

      try {
        await sendEmailOTP(email, emailOTP);

        await sendMobileOTP(phone, mobileOTP);

      } catch (sendError) {
        otpStore.delete(email);

        console.error(
          'OTP delivery failed:',
          sendError.message
        );

        return res.status(503).json({
          error: sendError.message ||
            'OTP delivery failed. Please try again.'
        });
      }

      return res.json({
        ok: true,

        message: 'Verification codes sent to your email and mobile number.',

        email: email.replace(
          /^(.{2}).*(@.*)$/,
          '$1***$2'
        ),

        phone: phone.slice(0, 4) + '******' + phone.slice(-2),

        expiresIn: 600
      });

    } catch (error) {
      console.error('Registration OTP error:', error);

      return res.status(500).json({
        error: 'Could not start registration. Please try again.'
      });
    }
  }
);


// ============================================
// REGISTRATION - VERIFY BOTH OTPs
// ============================================

app.post(
  '/api/auth/register/verify-otp',
  otpLimiter,

  (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);

      const emailOTP = cleanText(
        req.body?.emailOTP,
        10
      );

      const mobileOTP = cleanText(
        req.body?.mobileOTP,
        10
      );

      if (!email || !emailOTP || !mobileOTP) {
        return res.status(400).json({
          error: 'Email and both verification codes are required.'
        });
      }

      const record = otpStore.get(email);

      if (!record) {
        return res.status(400).json({
          error: 'Verification request not found. Please request new OTPs.'
        });
      }

      if (Date.now() > record.expiresAt) {
        otpStore.delete(email);

        return res.status(400).json({
          error: 'Verification codes have expired. Please request new ones.'
        });
      }

      record.attempts += 1;

      if (record.attempts > 5) {
        otpStore.delete(email);

        return res.status(429).json({
          error: 'Too many incorrect attempts. Please request new OTPs.'
        });
      }

      const emailValid =
        otpHash(emailOTP) === record.emailHash;

      const mobileValid =
        otpHash(mobileOTP) === record.mobileHash;

      if (!emailValid || !mobileValid) {
        return res.status(400).json({
          error: 'Incorrect email or mobile verification code.'
        });
      }

      const pendingUser = record.pendingUser;

      const duplicate = store.users.some(user =>
        normalizeEmail(user.email) === email ||
        normalizePhone(user.phone) === record.phone
      );

      if (duplicate) {
        otpStore.delete(email);

        return res.status(409).json({
          error: 'An account with this email or mobile number already exists.'
        });
      }

      pendingUser.emailVerified = true;
      pendingUser.phoneVerified = true;

      pendingUser.verifiedAt = new Date().toISOString();

      store.users.push(pendingUser);

      saveStore();

      otpStore.delete(email);

      const token = signToken({
        id: pendingUser.id,
        email: pendingUser.email,
        role: 'member'
      });

      return res.status(201).json({
        ok: true,

        message: 'Your account has been created successfully.',

        token,

        user: {
          id: pendingUser.id,
          name: pendingUser.name,
          email: pendingUser.email,
          role: pendingUser.role
        }
      });

    } catch (error) {
      console.error('OTP verification error:', error);

      return res.status(500).json({
        error: 'Account verification failed. Please try again.'
      });
    }
  }
);


// ============================================
// SEPARATE MEMBER LOGIN
// ============================================

app.post(
  '/api/auth/login',
  otpLimiter,

  (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);

      const password = String(
        req.body?.password || ''
      );

      if (!email || !password) {
        return res.status(400).json({
          error: 'Email and password are required.'
        });
      }

      const user = store.users.find(item =>
        normalizeEmail(item.email) === email
      );

      if (!user || !user.passwordHash) {
        return res.status(401).json({
          error: 'Invalid email or password. Please check your details.'
        });
      }

      if (!verifyPassword(password, user.passwordHash)) {
        return res.status(401).json({
          error: 'Invalid email or password. Please check your details.'
        });
      }

      if (user.emailVerified === false ||
          user.phoneVerified === false) {
        return res.status(403).json({
          error: 'Please complete email and mobile verification.'
        });
      }

      const token = signToken({
        id: user.id,
        email: user.email,
        role: user.role || 'member'
      });

      return res.json({
        ok: true,

        message: 'Login successful.',

        token,

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role || 'member'
        }
      });

    } catch (error) {
      console.error('Login error:', error);

      return res.status(500).json({
        error: 'Login failed. Please try again.'
      });
    }
  }
);

// ============================================
// USER PROFILE HELPERS
// ============================================

function findUserById(id) {
  return store.users.find(user => user.id === id);
}

function getSafeProfile(user) {
  if (!user) return null;

  const profile = user.profile || {};

  return {
    id: user.id,

    name: user.name,

    email: user.email,

    role: user.role || 'member',

    createdAt: user.createdAt,

    profile: {
      ...profile,

      // Private contact details are never sent
      // through this profile response.
      email: undefined,
      phone: undefined
    }
  };
}

function getProfileInput(body = {}) {
  const fields = [
    'name',
    'accountType',
    'bio',
    'photo',
    'country',
    'state',
    'city',
    'course',
    'institution',
    'designation',
    'department',
    'studyYear',
    'experience',
    'researchInterests',
    'publications',
    'skills',
    'languages',
    'website',
    'orcid'
  ];

  const limits = {
    name: 100,
    accountType: 50,
    bio: 1500,
    photo: 500,
    country: 80,
    state: 80,
    city: 80,
    course: 100,
    institution: 150,
    designation: 100,
    department: 100,
    studyYear: 50,
    experience: 50,
    researchInterests: 1000,
    publications: 1500,
    skills: 1000,
    languages: 300,
    website: 250,
    orcid: 100
  };

  const result = {};

  for (const field of fields) {
    if (body[field] !== undefined) {
      result[field] = cleanText(
        body[field],
        limits[field]
      );
    }
  }

  return result;
}

const allowedPrivacyLevels = new Set([
  'public',
  'members',
  'private'
]);

const allowedPrivacyFields = [
  'name',
  'photo',
  'bio',
  'accountType',
  'location',
  'education',
  'professional',
  'research',
  'publications',
  'skills',
  'contact'
];

function cleanPrivacyInput(input = {}) {
  const result = {};

  for (const field of allowedPrivacyFields) {
    const value = input[field];

    if (allowedPrivacyLevels.has(value)) {
      result[field] = value;
    }
  }

  return result;
}


// ============================================
// GET MY PROFILE
// ============================================

app.get(
  '/api/me/profile',
  auth('member'),

  (req, res) => {
    const user = findUserById(req.user.id);

    if (!user) {
      return res.status(404).json({
        error: 'Account not found.'
      });
    }

    return res.json({
      ok: true,
      user: getSafeProfile(user)
    });
  }
);


// ============================================
// UPDATE MY PERSONAL & PROFESSIONAL PROFILE
// ============================================

app.put(
  '/api/me/profile',
  auth('member'),

  (req, res) => {
    try {
      const user = findUserById(req.user.id);

      if (!user) {
        return res.status(404).json({
          error: 'Account not found.'
        });
      }

      if (!user.profile) {
        user.profile = {};
      }

      const updates = getProfileInput(req.body);

      // Name is maintained in both places.
      if (updates.name !== undefined) {
        if (!updates.name) {
          return res.status(400).json({
            error: 'Name cannot be empty.'
          });
        }

        user.name = updates.name;
      }

      Object.assign(user.profile, updates);

      // Never accept email or phone changes here.
      user.profile.email = user.email;
      user.profile.phone = user.phone;

      user.profileUpdatedAt = new Date().toISOString();

      saveStore();

      return res.json({
        ok: true,
        message: 'Profile updated successfully.',
        user: getSafeProfile(user)
      });

    } catch (error) {
      console.error('Profile update error:', error);

      return res.status(500).json({
        error: 'Could not update profile.'
      });
    }
  }
);


// ============================================
// UPDATE PROFILE PRIVACY SETTINGS
// ============================================

app.put(
  '/api/me/profile/privacy',
  auth('member'),

  (req, res) => {
    try {
      const user = findUserById(req.user.id);

      if (!user) {
        return res.status(404).json({
          error: 'Account not found.'
        });
      }

      if (!user.profile) {
        user.profile = {};
      }

      if (!user.profile.privacy) {
        user.profile.privacy = {};
      }

      const privacyUpdates = cleanPrivacyInput(
        req.body?.privacy || req.body
      );

      Object.assign(
        user.profile.privacy,
        privacyUpdates
      );

      saveStore();

      return res.json({
        ok: true,

        message: 'Privacy settings updated.',

        privacy: user.profile.privacy
      });

    } catch (error) {
      console.error('Privacy update error:', error);

      return res.status(500).json({
        error: 'Could not update privacy settings.'
      });
    }
  }
);


// ============================================
// PUBLIC MEMBER DIRECTORY
// Only public information is displayed.
// Email and phone are never included.
// ============================================

app.get(
  '/api/directory',

  (req, res) => {
    try {
      const search = cleanText(
        req.query.search,
        100
      ).toLowerCase();

      const accountType = cleanText(
        req.query.type,
        50
      ).toLowerCase();

      const results = store.users
        .filter(user => {
          const profile = user.profile || {};

          const privacy = profile.privacy || {};

          const type = cleanText(
            profile.accountType,
            50
          ).toLowerCase();

          if (accountType && type !== accountType) {
            return false;
          }

          const searchable = [
            user.name,
            profile.accountType,
            profile.bio,
            profile.institution,
            profile.designation,
            profile.department,
            profile.researchInterests,
            profile.skills
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();

          if (search && !searchable.includes(search)) {
            return false;
          }

          return true;
        })

        .map(user => {
          const profile = user.profile || {};

          const privacy = profile.privacy || {};

          const publicProfile = {
            id: user.id
          };

          if (privacy.name === 'public') {
            publicProfile.name = user.name;
          }

          if (privacy.photo === 'public') {
            publicProfile.photo = profile.photo || '';
          }

          if (privacy.bio === 'public') {
            publicProfile.bio = profile.bio || '';
          }

          if (privacy.accountType === 'public') {
            publicProfile.accountType =
              profile.accountType || '';
          }

          if (privacy.location === 'public') {
            publicProfile.country = profile.country || '';
            publicProfile.state = profile.state || '';
            publicProfile.city = profile.city || '';
          }

          if (privacy.education === 'public') {
            publicProfile.course = profile.course || '';
            publicProfile.institution =
              profile.institution || '';
            publicProfile.studyYear =
              profile.studyYear || '';
          }

          if (privacy.professional === 'public') {
            publicProfile.designation =
              profile.designation || '';
            publicProfile.department =
              profile.department || '';
            publicProfile.experience =
              profile.experience || '';
          }

          if (privacy.research === 'public') {
            publicProfile.researchInterests =
              profile.researchInterests || '';
          }

          if (privacy.publications === 'public') {
            publicProfile.publications =
              profile.publications || '';
          }

          if (privacy.skills === 'public') {
            publicProfile.skills =
              profile.skills || '';
            publicProfile.languages =
              profile.languages || '';
          }

          // Email and mobile are deliberately excluded.
          return publicProfile;
        });

      return res.json({
        ok: true,
        count: results.length,
        members: results
      });

    } catch (error) {
      console.error('Directory error:', error);

      return res.status(500).json({
        error: 'Could not load member directory.'
      });
    }
  }
);


// ============================================
// VIEW A PUBLIC MEMBER PROFILE
// ============================================

app.get(
  '/api/directory/:id',

  (req, res) => {
    try {
      const user = findUserById(req.params.id);

      if (!user) {
        return res.status(404).json({
          error: 'Member not found.'
        });
      }

      const profile = user.profile || {};

      const privacy = profile.privacy || {};

      const result = {
        id: user.id
      };

      if (privacy.name === 'public') {
        result.name = user.name;
      }

      if (privacy.photo === 'public') {
        result.photo = profile.photo || '';
      }

      if (privacy.bio === 'public') {
        result.bio = profile.bio || '';
      }

      if (privacy.accountType === 'public') {
        result.accountType = profile.accountType || '';
      }

      if (privacy.location === 'public') {
        result.country = profile.country || '';
        result.state = profile.state || '';
        result.city = profile.city || '';
      }

      if (privacy.education === 'public') {
        result.course = profile.course || '';
        result.institution = profile.institution || '';
        result.studyYear = profile.studyYear || '';
      }

      if (privacy.professional === 'public') {
        result.designation = profile.designation || '';
        result.department = profile.department || '';
        result.experience = profile.experience || '';
      }

      if (privacy.research === 'public') {
        result.researchInterests =
          profile.researchInterests || '';
      }

      if (privacy.publications === 'public') {
        result.publications = profile.publications || '';
      }

      if (privacy.skills === 'public') {
        result.skills = profile.skills || '';
        result.languages = profile.languages || '';
      }

      return res.json({
        ok: true,
        member: result
      });

    } catch (error) {
      console.error('Public profile error:', error);

      return res.status(500).json({
        error: 'Could not load member profile.'
      });
    }
  }
);
// ============================================
// GEMINI AI CONFIGURATION
// ============================================

const genAI = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY
    })
  : null;


// ============================================
// AI KNOWLEDGE CHAT
// ============================================

app.post(
  '/api/chat',
  chatLimiter,

  async (req, res) => {
    try {
      if (!genAI) {
        return res.status(503).json({
          error: 'AI service is not configured.'
        });
      }

      const message = cleanText(
        req.body?.message,
        5000
      );

      const language = cleanText(
        req.body?.language,
        30
      ) || 'English';

      if (!message) {
        return res.status(400).json({
          error: 'Please enter a message.'
        });
      }

      const prompt = `
You are Herbal Plant Explorer AI,
an educational assistant focused on:

- Medicinal plants
- Ayurveda
- Herbal knowledge
- Botany
- Plant identification
- Traditional knowledge
- Modern scientific research
- Phytochemistry
- Plant physiology
- Herbal cultivation

Answer in ${language}.

Important rules:
1. Give educational and evidence-aware answers.
2. Clearly distinguish traditional claims from scientifically established evidence.
3. Never invent research papers or references.
4. Do not present yourself as a doctor.
5. Do not recommend stopping prescribed medicines.
6. For serious health problems, recommend consulting a qualified healthcare professional.
7. Keep explanations clear and useful.

User question:
${message}
`;

      const response = await genAI.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt
      });

      const answer =
        response.text ||
        'Sorry, I could not generate an answer.';

      return res.json({
        ok: true,
        answer
      });

    } catch (error) {
      console.error('AI chat error:', error);

      return res.status(500).json({
        error: 'AI response could not be generated. Please try again.'
      });
    }
  }
);


// ============================================
// SUBMIT RESEARCH / PLANT CONTRIBUTION
// ============================================

app.post(
  '/api/contributions',
  auth('member'),
  upload.single('file'),

  (req, res) => {
    try {
      const user = findUserById(req.user.id);

      if (!user) {
        return res.status(404).json({
          error: 'User account not found.'
        });
      }

      const title = cleanText(
        req.body?.title,
        200
      );

      const category = cleanText(
        req.body?.category,
        80
      );

      const description = cleanText(
        req.body?.description,
        5000
      );

      if (!title || !category || !description) {
        return res.status(400).json({
          error: 'Title, category and description are required.'
        });
      }

      const contribution = {
        id: crypto.randomUUID(),

        userId: user.id,

        userName: user.name,

        title,

        category,

        description,

        file: req.file
          ? {
              name: req.file.originalname,
              storedName: req.file.filename,
              mimeType: req.file.mimetype,
              size: req.file.size
            }
          : null,

        status: 'pending',

        adminNote: '',

        createdAt: new Date().toISOString(),

        updatedAt: new Date().toISOString()
      };

      store.contributions.push(contribution);

      saveStore();

      return res.status(201).json({
        ok: true,

        message: 'Your contribution has been submitted for review.',

        contribution: {
          id: contribution.id,
          title: contribution.title,
          category: contribution.category,
          status: contribution.status
        }
      });

    } catch (error) {
      console.error('Contribution error:', error);

      return res.status(500).json({
        error: 'Could not submit contribution.'
      });
    }
  }
);


// ============================================
// MY CONTRIBUTIONS
// ============================================

app.get(
  '/api/me/contributions',
  auth('member'),

  (req, res) => {
    const contributions = store.contributions
      .filter(item => item.userId === req.user.id)
      .map(item => ({
        id: item.id,
        title: item.title,
        category: item.category,
        description: item.description,
        status: item.status,
        adminNote: item.adminNote || '',
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
        file: item.file
          ? {
              name: item.file.name,
              size: item.file.size
            }
          : null
      }));

    return res.json({
      ok: true,
      contributions
    });
  }
);


// ============================================
// ADMIN LOGIN
// ============================================

app.post(
  '/api/admin/login',
  otpLimiter,

  (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);

      const password = String(
        req.body?.password || ''
      );

      if (
        email !== ADMIN_EMAIL ||
        password !== ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          error: 'Invalid administrator credentials.'
        });
      }

      const token = signToken({
        id: 'admin',
        email: ADMIN_EMAIL,
        role: 'admin'
      });

      return res.json({
        ok: true,
        message: 'Administrator login successful.',
        token,
        user: {
          email: ADMIN_EMAIL,
          role: 'admin'
        }
      });

    } catch (error) {
      console.error('Admin login error:', error);

      return res.status(500).json({
        error: 'Admin login failed.'
      });
    }
  }
);


// ============================================
// ADMIN - VIEW ALL CONTRIBUTIONS
// ============================================

app.get(
  '/api/admin/contributions',
  auth('admin'),

  (_req, res) => {
    return res.json({
      ok: true,
      contributions: store.contributions
    });
  }
);


// ============================================
// ADMIN - APPROVE / REJECT CONTRIBUTION
// ============================================

app.put(
  '/api/admin/contributions/:id',
  auth('admin'),

  (req, res) => {
    try {
      const contribution = store.contributions.find(
        item => item.id === req.params.id
      );

      if (!contribution) {
        return res.status(404).json({
          error: 'Contribution not found.'
        });
      }

      const status = cleanText(
        req.body?.status,
        30
      ).toLowerCase();

      if (!['approved', 'rejected', 'pending'].includes(status)) {
        return res.status(400).json({
          error: 'Invalid contribution status.'
        });
      }

      contribution.status = status;

      contribution.adminNote = cleanText(
        req.body?.adminNote,
        1000
      );

      contribution.updatedAt = new Date().toISOString();

      saveStore();

      return res.json({
        ok: true,
        message: 'Contribution status updated.',
        contribution
      });

    } catch (error) {
      console.error('Admin review error:', error);

      return res.status(500).json({
        error: 'Could not update contribution.'
      });
    }
  }
);


// ============================================
// ADMIN - VIEW USERS
// ============================================

app.get(
  '/api/admin/users',
  auth('admin'),

  (_req, res) => {
    const users = store.users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      createdAt: user.createdAt,
      accountType: user.profile?.accountType || ''
    }));

    return res.json({
      ok: true,
      count: users.length,
      users
    });
  }
);


// ============================================
// ADMIN - VIEW CONTRIBUTION FILE
// ============================================

app.get(
  '/api/admin/contributions/:id/file',
  auth('admin'),

  (req, res) => {
    const contribution = store.contributions.find(
      item => item.id === req.params.id
    );

    if (!contribution || !contribution.file) {
      return res.status(404).json({
        error: 'File not found.'
      });
    }

    const filePath = path.join(
      UPLOAD_DIR,
      path.basename(contribution.file.storedName)
    );

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        error: 'Stored file is missing.'
      });
    }

    return res.download(
      filePath,
      safeFileName(contribution.file.name)
    );
  }
);


// ============================================
// GENERAL ERROR HANDLER
// ============================================

app.use((error, req, res, next) => {
  console.error('Server error:', error);

  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error: error.message
    });
  }

  return res.status(500).json({
    error: error.message || 'Something went wrong.'
  });
});


// ============================================
// UNKNOWN API ROUTE
// ============================================

app.use('/api', (req, res) => {
  return res.status(404).json({
    error: 'API route not found.'
  });
});


// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(
    `Herbal Plant Explorer server running on port ${PORT}`
  );

  console.log(
    `Data directory: ${DATA_DIR}`
  );
});
