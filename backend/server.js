const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const Database = require('./models/database');
const https = require('https');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3100;

// Initialize database
const db = new Database();

// Setup persistent uploads directory
const persistentDir = process.env.PERSISTENT_DIR || path.join(__dirname, 'persistent');
const uploadsDir = path.join(persistentDir, 'uploads');
if (!fs.existsSync(persistentDir)) fs.mkdirSync(persistentDir, { recursive: true });
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Simple admin session management
const adminSessions = new Set();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'clamoredwashere';
function generateSessionToken() { return crypto.randomBytes(32).toString('hex'); }
function requireAdminAuth(req, res, next) {
  let authToken = req.headers['x-admin-token'] || req.query.token;
  if (!authToken && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    authToken = req.headers.authorization.substring(7);
  }
  if (!authToken || !adminSessions.has(authToken)) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/admin/login');
  }
  next();
}

// Telegram auth (simplified dev version)
function validateTelegramAuth(initData) {
  if (!initData) return { valid: false, error: 'No init data' };
  try {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    urlParams.delete('hash');
    const userParam = urlParams.get('user');
    if (!hash || !userParam) return { valid: false, error: 'Invalid auth data' };
    const user = JSON.parse(decodeURIComponent(userParam));
    if (!user.id) return { valid: false, error: 'No user id' };
    return { valid: true, user };
  } catch (e) {
    return { valid: false, error: 'Invalid format' };
  }
}

// Static
app.use('/assets', express.static(path.join(__dirname, '../assets')));
app.use('/uploads', express.static(uploadsDir));
app.use('/', express.static(path.join(__dirname, '../frontend')));

// Pages
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, '../frontend/login.html')));
app.get('/admin', requireAdminAuth, (req, res) => res.sendFile(path.join(__dirname, '../frontend/admin.html')));
app.get('/mod-panel-x7k9m2n8p4q1', requireAdminAuth, (req, res) => res.sendFile(path.join(__dirname, '../frontend/moderation.html')));

// Health / status
app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));
app.get('/api/status', (req, res) => res.json({ status: 'ok', version: '1.0.0', database: 'connected' }));

// Admin auth endpoints
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = generateSessionToken();
    adminSessions.add(token);
    setTimeout(() => adminSessions.delete(token), 24 * 60 * 60 * 1000);
    return res.json({ success: true, token });
  }
  return res.status(401).json({ success: false, error: 'Invalid password' });
});
app.post('/admin/logout', (req, res) => {
  const token = req.headers['x-admin-token'] || req.body?.token;
  if (token) adminSessions.delete(token);
  res.json({ success: true });
});

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, 'hat-creation-' + Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Only image files allowed'))
});

// Gallery APIs
app.get('/api/gallery/images', async (req, res) => {
  try {
    const { sortBy = 'likes', limit = 50 } = req.query;
    const images = await db.getAllImages(parseInt(limit), sortBy);
    res.json(images);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch images' });
  }
});

app.get('/api/gallery/image/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const image = await db.getImageById(id);
    if (!image) return res.status(404).json({ error: 'Image not found' });
    const imagePath = path.join(uploadsDir, image.filename);
    if (!fs.existsSync(imagePath)) return res.status(404).json({ error: 'Image file not found' });
    res.sendFile(imagePath);
  } catch (e) {
    res.status(500).json({ error: 'Failed to serve image' });
  }
});

app.post('/api/gallery/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image file provided' });
    const { userId, userName, initData } = req.body;
    const auth = validateTelegramAuth(initData);
    if (!auth.valid) {
      fs.unlinkSync(req.file.path);
      return res.status(401).json({ error: 'Unauthorized: ' + auth.error });
    }
    if (String(auth.user.id) !== String(userId)) {
      fs.unlinkSync(req.file.path);
      return res.status(401).json({ error: 'User ID mismatch' });
    }
    const imageId = await db.createImage({
      userId,
      userName: userName || auth.user.first_name || 'Anonymous',
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype
    });
    res.json({ success: true, imageId });
  } catch (e) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

app.post('/api/gallery/like/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, initData } = req.body;
    const auth = validateTelegramAuth(initData);
    if (!auth.valid) return res.status(401).json({ error: 'Unauthorized: ' + auth.error });
    if (String(auth.user.id) !== String(userId)) return res.status(401).json({ error: 'User ID mismatch' });
    const image = await db.getImageById(id);
    if (!image) return res.status(404).json({ error: 'Image not found' });
    const result = await db.toggleLike(id, userId);
    res.json({ success: true, liked: result.liked, totalLikes: result.totalLikes });
  } catch (e) {
    res.status(500).json({ error: 'Failed to toggle like' });
  }
});

// Admin moderation APIs
app.get('/api/admin/images', requireAdminAuth, async (req, res) => {
  try {
    const images = await db.getAllImages(1000, 'recent');
    const detailed = images.map(img => ({
      ...img,
      createdDate: new Date(img.createdAt).toLocaleString(),
      fileSizeKB: img.size ? Math.round(img.size / 1024) : 'Unknown'
    }));
    res.json({ success: true, images: detailed });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/admin/delete-images', requireAdminAuth, async (req, res) => {
  try {
    const { imageIds } = req.body;
    if (!Array.isArray(imageIds) || imageIds.length === 0) return res.status(400).json({ success: false, error: 'No image IDs provided' });
    let deletedCount = 0; const errors = [];
    for (const imageId of imageIds) {
      try {
        const image = await db.getImageById(imageId);
        if (image) {
          await db.deleteImage(imageId);
          if (image.filename) {
            const p = path.join(uploadsDir, image.filename);
            if (fs.existsSync(p)) fs.unlinkSync(p);
          }
          deletedCount++;
        } else {
          errors.push(`Image ${imageId} not found`);
        }
      } catch (err) {
        errors.push(`Failed to delete ${imageId}: ${err.message}`);
      }
    }
    res.json({ success: true, deletedCount, totalRequested: imageIds.length, errors: errors.length ? errors : null });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Telegram DM support
const BOT_TOKEN = process.env.BOT_TOKEN || '8445586343:AAFmTjWitgY65wxCRUhdPV-Il150GeoECz8';

function validateTelegramAuth(initData) {
  if (!initData) return { valid: false, error: 'No init data' };
  try {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    urlParams.delete('hash');
    const userParam = urlParams.get('user');
    if (!hash || !userParam) return { valid: false, error: 'Invalid auth data' };
    const user = JSON.parse(decodeURIComponent(userParam));
    if (!user.id) return { valid: false, error: 'No user id' };
    return { valid: true, user };
  } catch (e) {
    return { valid: false, error: 'Invalid format' };
  }
}

async function sendImageToTelegramUser(userId, imageBuffer, caption = 'Your creation!') {
  if (BOT_TOKEN === 'YOUR_BOT_TOKEN_HERE') return { success: false, error: 'Bot token not configured' };
  const boundary = '----formdata-' + Math.random().toString(36);
  const CRLF = '\r\n';
  let formData = '';
  formData += '--' + boundary + CRLF + 'Content-Disposition: form-data; name="chat_id"' + CRLF + CRLF + userId + CRLF;
  formData += '--' + boundary + CRLF + 'Content-Disposition: form-data; name="caption"' + CRLF + CRLF + caption + CRLF;
  formData += '--' + boundary + CRLF + 'Content-Disposition: form-data; name="photo"; filename="image.png"' + CRLF + 'Content-Type: image/png' + CRLF + CRLF;
  const formDataBuffer = Buffer.concat([
    Buffer.from(formData, 'utf8'),
    imageBuffer,
    Buffer.from(CRLF + '--' + boundary + '--' + CRLF, 'utf8')
  ]);

  return new Promise((resolve) => {
    const url = new URL(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`);
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Content-Length': formDataBuffer.length }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.ok) resolve({ success: true });
          else resolve({ success: false, error: result.description || 'Failed' });
        } catch (e) {
          resolve({ success: false, error: 'Invalid response from Telegram API' });
        }
      });
    });
    req.on('error', (err) => resolve({ success: false, error: err.message }));
    req.write(formDataBuffer);
    req.end();
  });
}

app.post('/api/send-to-dm', async (req, res) => {
  try {
    const { userId, imageData, initData } = req.body;
    const auth = validateTelegramAuth(initData);
    if (!auth.valid) return res.status(401).json({ error: 'Unauthorized: ' + auth.error });
    if (String(auth.user.id) !== String(userId)) return res.status(401).json({ error: 'User ID mismatch' });
    if (!imageData || !imageData.startsWith('data:image/')) return res.status(400).json({ error: 'Invalid image data' });
    const base64 = imageData.split(',')[1];
    const buffer = Buffer.from(base64, 'base64');
    const result = await sendImageToTelegramUser(userId, buffer, 'Your Hat Mini App creation!');
    if (result.success) return res.json({ success: true });
    return res.status(500).json({ error: result.error });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to send image to DM' });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

app.listen(PORT, () => {
  console.log(`Hat Mini App server running on ${PORT}`);
});

module.exports = app;


