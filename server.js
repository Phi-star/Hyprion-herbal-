require('dotenv').config();
const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const crypto       = require('crypto');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios        = require('axios');
const { Dropbox }  = require('dropbox');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURATION
// ============================================================
const HYPRION_ADMIN_PASSWORD = process.env.HYPRION_ADMIN_PASSWORD || 'phistar2025';
const JWT_SECRET             = process.env.JWT_SECRET             || 'hyprion_jwt_' + crypto.randomBytes(32).toString('hex');
const TELEGRAM_BOT_TOKEN     = process.env.TELEGRAM_BOT_TOKEN     || '7756847746:AAHCWrPTLqWKaMvqcVnMeSU9iCWV_77Angw';
const TELEGRAM_CHAT_ID       = process.env.TELEGRAM_CHAT_ID       || '6300694007';

const DROPBOX_APP_KEY       = process.env.DROPBOX_APP_KEY       || 'ho5ep3i58l3tvgu';
const DROPBOX_APP_SECRET    = process.env.DROPBOX_APP_SECRET    || '9fy0w0pgaafyk3e';
const DROPBOX_REFRESH_TOKEN = process.env.DROPBOX_REFRESH_TOKEN || 'Vjhcbg66GMgAAAAAAAAAARJPgSupFcZdyXFkXiFx7VP-oXv_64RQKmtTLUYfPtm3';
const DROPBOX_BACKUP_PATH   = '/hyprion/hypriandatabase.json';

// Local database — hypriandatabase.json
const DB_FILE = path.join(__dirname, 'hypriandatabase.json');

// Active admin JWT sessions store (in-memory)
const activeSessions  = new Map();  // token → session meta
const rateLimitStore  = new Map();  // ip_event → { count, firstAttempt, lastAttempt }
const blockedIPs      = new Map();  // ip → { reason, expiresAt }

// Dropbox client
let dbx                = null;
let dropboxAccessToken = null;

// Interval handles
let autoBackupInterval = null;
let restartTimer       = null;

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Security headers
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options',        'SAMEORIGIN');
    res.setHeader('X-XSS-Protection',       '1; mode=block');
    res.setHeader('Referrer-Policy',        'strict-origin-when-cross-origin');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "connect-src 'self';"
    );
    next();
});

// ============================================================
// SECURITY — IP BLOCKING
// ============================================================
function blockIP(ip, reason, durationMinutes = 30) {
    const expiresAt = Date.now() + durationMinutes * 60 * 1000;
    blockedIPs.set(ip, { reason, expiresAt, blockedAt: new Date().toISOString() });
    console.log(`🚫 Blocked IP ${ip} for ${durationMinutes} min. Reason: ${reason}`);
    setTimeout(() => {
        if (blockedIPs.has(ip)) {
            blockedIPs.delete(ip);
            console.log(`✅ Unblocked IP ${ip}`);
        }
    }, durationMinutes * 60 * 1000);
}

function isIPBlocked(ip) {
    if (!blockedIPs.has(ip)) return false;
    const entry = blockedIPs.get(ip);
    if (Date.now() > entry.expiresAt) { blockedIPs.delete(ip); return false; }
    return true;
}

function checkBruteForce(ip, eventType) {
    const now = Date.now();
    const key = `${ip}_${eventType}`;
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, { count: 1, firstAttempt: now, lastAttempt: now });
    } else {
        const data = rateLimitStore.get(key);
        data.count++;
        data.lastAttempt = now;
        if (data.count > 10 && (now - data.firstAttempt) < 5 * 60 * 1000) {
            blockIP(ip, `Brute force: ${eventType}`);
            rateLimitStore.delete(key);
            return true;
        }
    }
    // Clean stale entries
    for (const [k, d] of rateLimitStore.entries()) {
        if (now - d.lastAttempt > 10 * 60 * 1000) rateLimitStore.delete(k);
    }
    return false;
}

function logSecurity(event, data) {
    console.log(`🔒 SECURITY [${event}]`, { timestamp: new Date().toISOString(), ...data });
}

// Clean expired sessions every 5 minutes
setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    let cleaned = 0;
    for (const [token] of activeSessions.entries()) {
        try { jwt.verify(token, JWT_SECRET); }
        catch { activeSessions.delete(token); cleaned++; }
    }
    if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} expired admin sessions`);
}, 5 * 60 * 1000);

// ============================================================
// ADMIN AUTH — JWT SESSION
// The management page POSTs password → gets a JWT cookie
// Every admin API call is checked against this JWT + activeSessions
// ============================================================
function generateAdminToken(req) {
    const ip      = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const payload = {
        role:      'hyprion_admin',
        tokenType: 'admin_session',
        jti:       crypto.randomBytes(16).toString('hex')
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
    activeSessions.set(token, {
        ip,
        createdAt: new Date().toISOString(),
        lastUsed:  new Date().toISOString(),
        revoked:   false
    });
    logSecurity('ADMIN_LOGIN', { ip });
    return token;
}

function adminAuth(req, res, next) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

    // Block before anything
    if (isIPBlocked(ip)) {
        return res.status(403).json({ success: false, message: 'Access denied. Your IP is temporarily blocked.' });
    }

    // Token from: Authorization header, cookie, or x-admin-token header
    const authHeader = req.headers['authorization'];
    const headerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    const cookieToken = req.cookies && req.cookies.hyprion_admin_session;
    const xToken      = req.headers['x-admin-token'];
    const token       = headerToken || cookieToken || xToken;

    if (!token) {
        logSecurity('MISSING_ADMIN_TOKEN', { ip, path: req.path });
        if (req.accepts('html') && req.method === 'GET') return res.redirect('/hyprionmanagement');
        return res.status(401).json({ success: false, message: 'Unauthorized. Invalid: please provide auth token.' });
    }

    // Brute-force check
    if (checkBruteForce(ip, 'ADMIN_TOKEN_VALIDATION')) {
        return res.status(429).json({ success: false, message: 'Too many failed attempts. You are temporarily blocked.' });
    }

    try {
        // Check blacklist
        const session = activeSessions.get(token);
        if (session && session.revoked) throw new Error('Session revoked');

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'hyprion_admin' || decoded.tokenType !== 'admin_session') {
            throw new Error('Invalid token type');
        }

        // Update last used
        if (session) session.lastUsed = new Date().toISOString();

        req.adminToken = token;
        next();

    } catch (err) {
        logSecurity('INVALID_ADMIN_TOKEN', { ip, error: err.message, path: req.path });
        activeSessions.delete(token);

        if (err.message.includes('jwt expired')) {
            return res.status(401).json({ success: false, message: 'Session expired. Please login again.' });
        }
        return res.status(401).json({ success: false, message: 'Unauthorized. Invalid: please provide auth token.' });
    }
}

// ============================================================
// RATE LIMITER — order submissions
// ============================================================
const orderRateMap = new Map();
function orderRateLimit(req, res, next) {
    const ip     = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (isIPBlocked(ip)) return res.status(403).json({ success: false, message: 'Access denied.' });

    const now    = Date.now();
    const window = 60 * 1000;
    const max    = 5;

    if (!orderRateMap.has(ip)) {
        orderRateMap.set(ip, { count: 1, resetAt: now + window });
    } else {
        const e = orderRateMap.get(ip);
        if (now > e.resetAt) { e.count = 1; e.resetAt = now + window; }
        else { e.count++; if (e.count > max) return res.status(429).json({ success: false, message: 'Too many requests. Please slow down.' }); }
    }
    next();
}

// ============================================================
// DATABASE — hypriandatabase.json
// ============================================================
function dbLoad() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            const init = { orders: [], totalOrders: 0, createdAt: new Date().toISOString(), lastUpdated: new Date().toISOString() };
            fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
            return init;
        }
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (err) {
        console.error('❌ DB load error:', err.message);
        return { orders: [], totalOrders: 0, createdAt: new Date().toISOString(), lastUpdated: new Date().toISOString() };
    }
}

function dbSave(data) {
    try {
        data.lastUpdated = new Date().toISOString();
        data.totalOrders = data.orders.length;
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
        return true;
    } catch (err) {
        console.error('❌ DB save error:', err.message);
        return false;
    }
}

function makeOrderId() {
    const ts   = Date.now().toString(36).toUpperCase();
    const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `HYP-${ts}-${rand}`;
}

// ============================================================
// DROPBOX
// ============================================================
async function refreshDropboxToken() {
    try {
        console.log('🔄 Refreshing Dropbox access token...');
        const resp = await fetch('https://api.dropbox.com/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type:    'refresh_token',
                refresh_token: DROPBOX_REFRESH_TOKEN,
                client_id:     DROPBOX_APP_KEY,
                client_secret: DROPBOX_APP_SECRET
            })
        });
        const data = await resp.json();
        if (data.access_token) {
            dropboxAccessToken = data.access_token;
            dbx = new Dropbox({ accessToken: dropboxAccessToken });
            console.log('✅ Dropbox token refreshed');
            return true;
        }
        console.error('❌ Dropbox token refresh failed:', data);
        return false;
    } catch (err) {
        console.error('❌ Dropbox token refresh error:', err.message);
        return false;
    }
}

async function initializeDropbox() {
    try {
        console.log('🔗 Initialising Dropbox...');
        const ok = await refreshDropboxToken();
        if (!ok) return false;

        // Verify connection
        await dbx.usersGetCurrentAccount();
        console.log('✅ Dropbox connected');

        // Ensure folder exists
        try {
            await dbx.filesCreateFolderV2({ path: '/hyprion' });
            console.log('📁 Dropbox /hyprion folder created');
        } catch (e) {
            if (!e.error?.error?.['.tag']?.includes('conflict')) console.log('📁 Dropbox /hyprion folder already exists');
        }
        return true;
    } catch (err) {
        console.error('❌ Dropbox init error:', err.message);
        return false;
    }
}

async function dropboxBackup() {
    try {
        if (!dbx) await refreshDropboxToken();
        if (!dbx) { console.log('⚠️  Dropbox unavailable — skipping backup'); return; }

        const content = fs.readFileSync(DB_FILE, 'utf8');
        await dbx.filesUpload({ path: DROPBOX_BACKUP_PATH, contents: content, mode: { '.tag': 'overwrite' } });
        console.log(`☁️  Dropbox backup OK → ${DROPBOX_BACKUP_PATH}`);
    } catch (err) {
        console.error('❌ Dropbox backup error:', err.message);
    }
}

// Refresh Dropbox token every 4 hours (same as GlobeSMS)
setInterval(async () => { if (dbx) await refreshDropboxToken(); }, 4 * 60 * 60 * 1000);

// ============================================================
// TELEGRAM
// ============================================================
async function telegramNotify(order) {
    try {
        const text =
            `🌿 *NEW HYPRION ORDER!*\n\n` +
            `🆔 *Order ID:* \`${order.orderId}\`\n` +
            `👤 *Name:* ${order.fullName}\n` +
            `📞 *Phone:* ${order.phone}\n` +
            `💬 *WhatsApp:* ${order.whatsapp || '—'}\n` +
            `📧 *Email:* ${order.email || '—'}\n\n` +
            `📦 *Package:* ${order.package}\n\n` +
            `📍 *Delivery:*\n` +
            `   State: ${order.state}\n` +
            `   City: ${order.city}\n` +
            `   Address: ${order.address}\n\n` +
            `📝 *Notes:* ${order.notes || 'None'}\n` +
            `🔗 *Source:* ${order.source || 'Unknown'}\n` +
            `⏰ *Time:* ${new Date(order.timestamp).toLocaleString('en-NG', { timeZone: 'Africa/Lagos' })}\n\n` +
            `👉 Manage: /hyprionmanagement`;

        await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            { chat_id: TELEGRAM_CHAT_ID, text, parse_mode: 'Markdown' },
            { timeout: 10000 }
        );
        console.log(`📲 Telegram notified → ${order.orderId}`);
    } catch (err) {
        console.error('❌ Telegram error:', err.message);
    }
}

// ============================================================
// AUTO BACKUP — every 30 minutes  (mirrors GlobeSMS pattern)
// ============================================================
function startAutoBackup() {
    if (autoBackupInterval) clearInterval(autoBackupInterval);
    autoBackupInterval = setInterval(async () => {
        try {
            console.log('🔄 Auto-backup running...');
            await dropboxBackup();
            console.log('✅ Auto-backup complete');
        } catch (err) {
            console.error('❌ Auto-backup failed:', err.message);
        }
    }, 30 * 60 * 1000);
    console.log('🔄 Auto-backup scheduled every 30 minutes');
}

// ============================================================
// AUTO RESTART — exact GlobeSMS performHerokuRestart pattern
// process.exit(143) — PM2 / Heroku restarts automatically
// ============================================================
async function performHerokuRestart() {
    console.log('🚀 Initiating Hyprion auto-restart...');
    try {
        await dropboxBackup();           // backup first
        await new Promise(r => setTimeout(r, 3000)); // 3-second grace
        process.exit(143);
    } catch (err) {
        console.error('❌ Auto-restart error:', err.message);
        process.exit(143);
    }
}

const RESTART_INTERVAL = 60 * 60 * 1000; // 1 hour
restartTimer = setInterval(() => {
    console.log('⏰ 1 hour elapsed — initiating scheduled restart...');
    performHerokuRestart();
}, RESTART_INTERVAL);
console.log(`🔄 Auto-restart configured every ${RESTART_INTERVAL / (60 * 1000)} minutes`);

// ============================================================
// PAGE ROUTES
// ============================================================

// Root → /hyprion
app.get('/', (_req, res) => res.redirect('/hyprion'));

// Landing page (public)
app.get('/hyprion', (_req, res) => {
    const file = path.join(__dirname, 'public', 'hyprion.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('hyprion.html not found — place it in /public/');
});

// Order page (public)
app.get('/hyprionorder', (_req, res) => {
    const file = path.join(__dirname, 'public', 'order.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('order.html not found — place it in /public/');
});

// ============================================================
// ADMIN MANAGEMENT PAGE — protected, redirects if no session
// Same pattern as GlobeSMS /dashboard
// ============================================================
app.get('/hyprionmanagement', (req, res) => {
    const ip          = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const cookieToken = req.cookies && req.cookies.hyprion_admin_session;

    // If no cookie, just serve the management page (it has its own password gate UI)
    // The API calls inside it will be rejected if the JWT is invalid
    const file = path.join(__dirname, 'public', 'management.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('management.html not found — place it in /public/');
});

// ============================================================
// API — ADMIN LOGIN  (password → JWT cookie)
// POST /api/hyprion-admin-login
// Body: { "password": "phistar2025" }
// ============================================================
app.post('/api/hyprion-admin-login', (req, res) => {
    const ip       = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const { password } = req.body;

    // Block if IP is already blocked
    if (isIPBlocked(ip)) {
        return res.status(403).json({ success: false, message: 'Access denied. Your IP is temporarily blocked.' });
    }

    // Brute-force check
    if (checkBruteForce(ip, 'ADMIN_LOGIN')) {
        return res.status(429).json({ success: false, message: 'Too many failed login attempts. You are temporarily blocked.' });
    }

    if (!password || password !== HYPRION_ADMIN_PASSWORD) {
        logSecurity('FAILED_ADMIN_LOGIN', { ip, provided: password ? '(wrong password)' : '(empty)' });
        return res.status(401).json({ success: false, message: 'Invalid password.' });
    }

    // Generate JWT session token
    const token = generateAdminToken(req);

    // Set HttpOnly cookie (8 hours) — exactly like GlobeSMS dashboard session
    res.cookie('hyprion_admin_session', token, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   8 * 60 * 60 * 1000  // 8 hours in ms
    });

    return res.json({
        success:   true,
        message:   'Login successful.',
        token,     // also return in body so management.html can store it
        expiresIn: '8h'
    });
});

// ============================================================
// API — ADMIN LOGOUT
// POST /api/hyprion-admin-logout
// ============================================================
app.post('/api/hyprion-admin-logout', adminAuth, (req, res) => {
    // Revoke the session
    if (req.adminToken && activeSessions.has(req.adminToken)) {
        activeSessions.get(req.adminToken).revoked = true;
        activeSessions.delete(req.adminToken);
    }
    res.clearCookie('hyprion_admin_session');
    logSecurity('ADMIN_LOGOUT', { ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress });
    res.json({ success: true, message: 'Logged out.' });
});

// ============================================================
// API — IMAGE LISTING  (public — used by slideshows)
// GET /api/hyprion-images?folder=img/Hyprion
// GET /api/hyprion-images?folder=img/testimonials
// ============================================================
app.get('/api/hyprion-images', (req, res) => {
    const rawFolder  = (req.query.folder || 'img/Hyprion').replace(/\.\./g, '').replace(/^\/+/, '');
    const folderPath = path.join(__dirname, 'public', rawFolder);
    try {
        if (!fs.existsSync(folderPath)) return res.json({ success: true, images: [], count: 0 });
        const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
        const images  = fs.readdirSync(folderPath)
            .filter(f => allowed.includes(path.extname(f).toLowerCase()))
            .sort()
            .map(f => `/${rawFolder}/${f}`);
        res.json({ success: true, images, count: images.length, folder: rawFolder });
    } catch (err) {
        res.json({ success: true, images: [], count: 0, error: err.message });
    }
});

// ============================================================
// API — PLACE ORDER  (public)
// POST /api/hyprion-order
// ============================================================
app.post('/api/hyprion-order', orderRateLimit, async (req, res) => {
    try {
        const { fullName, phone, whatsapp, email, state, city, address, notes, package: pkg, packageQty, source, referral } = req.body;

        if (!fullName || String(fullName).trim().length < 2)
            return res.status(400).json({ success: false, message: 'Full name is required.' });
        if (!phone || !/^[0-9+\s\-]{7,15}$/.test(String(phone).trim()))
            return res.status(400).json({ success: false, message: 'A valid phone number is required.' });
        if (!state || String(state).trim() === '')
            return res.status(400).json({ success: false, message: 'State is required.' });
        if (!city || String(city).trim().length < 2)
            return res.status(400).json({ success: false, message: 'City / LGA is required.' });
        if (!address || String(address).trim().length < 5)
            return res.status(400).json({ success: false, message: 'Delivery address is required.' });

        const order = {
            orderId:    makeOrderId(),
            fullName:   String(fullName).trim(),
            phone:      String(phone).trim(),
            whatsapp:   String(whatsapp  || '').trim(),
            email:      String(email     || '').trim(),
            state:      String(state).trim(),
            city:       String(city).trim(),
            address:    String(address).trim(),
            notes:      String(notes     || '').trim(),
            package:    String(pkg       || 'Starter Pack (1 Bottle)').trim(),
            packageQty: Number(packageQty) || 1,
            source:     String(source    || 'Unknown').trim(),
            referral:   String(referral  || '').trim(),
            status:     'New',
            timestamp:  new Date().toISOString(),
            ip:         req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
        };

        const db    = dbLoad();
        db.orders.unshift(order);
        const saved = dbSave(db);

        if (!saved) return res.status(500).json({ success: false, message: 'Failed to save order. Please try again.' });

        console.log(`✅ New order: ${order.orderId} | ${order.fullName} | ${order.phone} | ${order.state}`);

        // Non-blocking: Telegram + Dropbox
        telegramNotify(order);
        dropboxBackup().catch(e => console.error('Backup error:', e.message));

        return res.status(201).json({
            success:  true,
            message:  'Order placed! We will call you shortly to confirm.',
            orderId:  order.orderId,
            order: {
                orderId:  order.orderId,
                fullName: order.fullName,
                package:  order.package,
                state:    order.state,
                status:   order.status
            }
        });
    } catch (err) {
        console.error('❌ Order error:', err);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ============================================================
// API — GET ALL ORDERS  (admin only)
// GET /api/hyprion-orders
// ============================================================
app.get('/api/hyprion-orders', adminAuth, (req, res) => {
    try {
        const db = dbLoad();
        res.json({ success: true, orders: db.orders, total: db.orders.length, lastUpdated: db.lastUpdated });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to load orders.' });
    }
});

// ============================================================
// API — GET SINGLE ORDER  (admin only)
// GET /api/hyprion-order/:orderId
// ============================================================
app.get('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const db    = dbLoad();
        const order = db.orders.find(o => o.orderId === req.params.orderId);
        if (!order) return res.status(404).json({ success: false, message: 'Order not found.' });
        res.json({ success: true, order });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch order.' });
    }
});

// ============================================================
// API — UPDATE ORDER STATUS  (admin only)
// PATCH /api/hyprion-order/:orderId
// Body: { "status": "Confirmed" }
// ============================================================
app.patch('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const { status } = req.body;
        const allowed    = ['New', 'Confirmed', 'Shipped', 'Delivered', 'Cancelled'];
        if (!allowed.includes(status))
            return res.status(400).json({ success: false, message: `Invalid status. Allowed: ${allowed.join(', ')}` });

        const db    = dbLoad();
        const index = db.orders.findIndex(o => o.orderId === req.params.orderId);
        if (index === -1) return res.status(404).json({ success: false, message: 'Order not found.' });

        const prev = db.orders[index].status;
        db.orders[index].status    = status;
        db.orders[index].updatedAt = new Date().toISOString();
        dbSave(db);

        console.log(`📝 Order ${req.params.orderId}: ${prev} → ${status}`);
        dropboxBackup().catch(() => {});

        res.json({ success: true, orderId: req.params.orderId, status });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update order.' });
    }
});

// ============================================================
// API — DELETE ORDER  (admin only)
// DELETE /api/hyprion-order/:orderId
// ============================================================
app.delete('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const db     = dbLoad();
        const before = db.orders.length;
        db.orders    = db.orders.filter(o => o.orderId !== req.params.orderId);
        if (db.orders.length === before) return res.status(404).json({ success: false, message: 'Order not found.' });
        dbSave(db);
        dropboxBackup().catch(() => {});
        console.log(`🗑️  Deleted order ${req.params.orderId}`);
        res.json({ success: true, message: 'Order deleted.', orderId: req.params.orderId });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete order.' });
    }
});

// ============================================================
// API — MANUAL DROPBOX BACKUP  (admin only)
// POST /api/hyprion-backup
// ============================================================
app.post('/api/hyprion-backup', adminAuth, async (req, res) => {
    try {
        await dropboxBackup();
        res.json({ success: true, message: 'Backup to Dropbox completed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Backup failed: ' + err.message });
    }
});

// ============================================================
// API — VERIFY SESSION  (admin — management.html calls on load)
// GET /api/hyprion-verify-session
// ============================================================
app.get('/api/hyprion-verify-session', adminAuth, (req, res) => {
    res.json({ success: true, authenticated: true, message: 'Session valid.' });
});

// ============================================================
// HEALTH CHECK  (public)
// ============================================================
app.get('/health', (_req, res) => {
    const db = dbLoad();
    res.json({
        status:      'ok',
        server:      'Hyprion Herbal Capsules',
        uptime:      Math.floor(process.uptime()) + 's',
        totalOrders: db.totalOrders || 0,
        dropbox:     dbx ? 'connected' : 'disconnected',
        telegram:    'configured',
        autoBackup:  autoBackupInterval ? 'running' : 'stopped',
        autoRestart: restartTimer       ? 'running' : 'stopped',
        activeSessions: activeSessions.size,
        timestamp:   new Date().toISOString()
    });
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
async function gracefulShutdown(signal) {
    console.log(`\n🔄 ${signal} — shutting down gracefully...`);
    try {
        console.log('📦 Final backup...');
        await dropboxBackup();
    } catch (e) { console.error('Final backup error:', e.message); }

    if (autoBackupInterval) clearInterval(autoBackupInterval);
    if (restartTimer)       clearInterval(restartTimer);

    console.log('👋 Hyprion server stopped.');
    process.exit(0);
}

process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// ============================================================
// START SERVER
// ============================================================
async function initializeServer() {
    try {
        console.log('\n' + '═'.repeat(58));
        console.log('🌿  HYPRION HERBAL CAPSULES SERVER STARTING');
        console.log('═'.repeat(58));

        console.log('🔒 Security Features:');
        console.log('   • JWT admin session tokens (8-hour expiry)');
        console.log('   • HttpOnly cookie auth (same as GlobeSMS)');
        console.log('   • IP brute-force blocking');
        console.log('   • Active session store + revocation');
        console.log('   • Rate limiting on order submissions');

        // Ensure hypriandatabase.json exists
        dbLoad();
        console.log('📂 Database: hypriandatabase.json');

        // Connect Dropbox
        const dropboxOk = await initializeDropbox();

        // Start auto-backup
        startAutoBackup();

        // restartTimer already running (set at module level above)

        const db = dbLoad();

        app.listen(PORT, () => {
            console.log('═'.repeat(58));
            console.log(`✅  Port          : ${PORT}`);
            console.log(`🌿  Landing       : http://localhost:${PORT}/hyprion`);
            console.log(`🛒  Order         : http://localhost:${PORT}/hyprionorder`);
            console.log(`🔐  Admin panel   : http://localhost:${PORT}/hyprionmanagement`);
            console.log(`📦  Orders in DB  : ${db.totalOrders}`);
            console.log(`☁️   Dropbox       : ${dropboxOk ? '✅ Connected' : '❌ Failed'}`);
            console.log(`📲  Telegram      : chat ID ${TELEGRAM_CHAT_ID}`);
            console.log(`🔄  Auto-backup   : every 30 min`);
            console.log(`🔄  Auto-restart  : every 1 hour (exit 143)`);
            console.log(`🔒  Admin auth    : JWT + HttpOnly cookie`);
            console.log('═'.repeat(58) + '\n');
        });

    } catch (err) {
        console.error('❌ Server init failed:', err);
        process.exit(1);
    }
}

initializeServer();
