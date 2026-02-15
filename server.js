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
// CONFIG
// ============================================================
const ADMIN_PASSWORD  = process.env.HYPRION_ADMIN_PASSWORD || 'phistar2025';
const JWT_SECRET      = process.env.JWT_SECRET || 'hyprion_secret_' + crypto.randomBytes(32).toString('hex');
const TELEGRAM_TOKEN  = process.env.TELEGRAM_BOT_TOKEN || '7756847746:AAHCWrPTLqWKaMvqcVnMeSU9iCWV_77Angw';
const TELEGRAM_CHAT   = process.env.TELEGRAM_CHAT_ID    || '6300694007';
const DROPBOX_KEY     = process.env.DROPBOX_APP_KEY        || 'ho5ep3i58l3tvgu';
const DROPBOX_SECRET  = process.env.DROPBOX_APP_SECRET     || '9fy0w0pgaafyk3e';
const DROPBOX_REFRESH = process.env.DROPBOX_REFRESH_TOKEN  || 'Vjhcbg66GMgAAAAAAAAAARJPgSupFcZdyXFkXiFx7VP-oXv_64RQKmtTLUYfPtm3';

// ============================================================
// PIXEL IDs — set via Heroku config vars or .env
// heroku config:set FB_PIXEL_ID=your_facebook_pixel_id
// heroku config:set TIKTOK_PIXEL_ID=your_tiktok_pixel_id
// Leave blank '' to disable a pixel
// ============================================================
const FB_PIXEL_ID     = process.env.FB_PIXEL_ID     || '';  // e.g. '1234567890123456'
const TIKTOK_PIXEL_ID = process.env.TIKTOK_PIXEL_ID || '';  // e.g. 'CTABCDE12345'

// Dropbox paths
const DROPBOX_DB_PATH = '/hyprion/hypriandatabase.json';   // main DB file on Dropbox

// Local DB file
const DB_FILE = path.join(__dirname, 'hypriandatabase.json');

// Catbox image URLs — proxied through /api/hyprion-img/:index to bypass browser shields
const PRODUCT_IMAGES = [
    'https://files.catbox.moe/4bkejb.jpg',
    'https://files.catbox.moe/q99wtp.jpg',
    'https://files.catbox.moe/2dc4wt.jpg',
    'https://files.catbox.moe/zm5m31.jpg',
    'https://files.catbox.moe/engpyz.jpg'
];

let dbx               = null;
let autoBackupInterval = null;
let restartTimer       = null;

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// ============================================================
// ADMIN AUTH — JWT
// Accepts: Authorization: Bearer <token>  OR  x-admin-token header
// ============================================================
function adminAuth(req, res, next) {
    const authHeader  = req.headers['authorization'];
    const bearerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    const xToken      = req.headers['x-admin-token'];
    const token       = bearerToken || xToken;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please login.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'hyprion_admin') throw new Error('Invalid role');
        req.admin = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Session expired. Please login again.' });
        }
        return res.status(401).json({ success: false, message: 'Unauthorized. Invalid token.' });
    }
}

// ============================================================
// ORDER RATE LIMITER
// ============================================================
const orderRateMap = new Map();
function orderRateLimit(req, res, next) {
    const ip  = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x';
    const now = Date.now();
    if (!orderRateMap.has(ip)) {
        orderRateMap.set(ip, { count: 1, resetAt: now + 60000 });
    } else {
        const e = orderRateMap.get(ip);
        if (now > e.resetAt) { e.count = 1; e.resetAt = now + 60000; }
        else { e.count++; if (e.count > 10) return res.status(429).json({ success: false, message: 'Too many requests.' }); }
    }
    next();
}

// ============================================================
// DATABASE — hypriandatabase.json (local)
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
    return `HYP-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

// ============================================================
// DROPBOX — token refresh
// ============================================================
async function refreshDropboxToken() {
    try {
        console.log('🔄 Refreshing Dropbox token...');
        const resp = await axios.post(
            'https://api.dropbox.com/oauth2/token',
            new URLSearchParams({
                grant_type:    'refresh_token',
                refresh_token: DROPBOX_REFRESH,
                client_id:     DROPBOX_KEY,
                client_secret: DROPBOX_SECRET
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 }
        );
        if (resp.data.access_token) {
            dbx = new Dropbox({ accessToken: resp.data.access_token });
            console.log('✅ Dropbox token refreshed');
            return true;
        }
        console.error('❌ Dropbox token refresh failed:', resp.data);
        return false;
    } catch (err) {
        console.error('❌ Dropbox token error:', err.message);
        return false;
    }
}

// Refresh every 4 hours (same as GlobeSMS)
setInterval(() => refreshDropboxToken(), 4 * 60 * 60 * 1000);

// ============================================================
// DROPBOX — RESTORE DATABASE ON STARTUP  (GlobeSMS pattern)
// Downloads hypriandatabase.json from Dropbox → saves locally
// Falls back to local file if Dropbox not available
// ============================================================
async function loadDatabaseFromDropbox() {
    if (dbx) {
        try {
            console.log('📥 Restoring hypriandatabase.json from Dropbox...');
            const response = await dbx.filesDownload({ path: DROPBOX_DB_PATH });

            if (response.result && response.result.fileBinary) {
                const data = JSON.parse(response.result.fileBinary.toString());
                fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
                console.log(`✅ Database restored from Dropbox — ${data.orders ? data.orders.length : 0} orders loaded`);
                return data;
            }
        } catch (error) {
            if (error.error?.error_summary?.includes('not_found')) {
                console.log('📝 No existing database on Dropbox — starting fresh');
            } else {
                console.error('❌ Failed to restore DB from Dropbox:', error.message);
            }
        }
    }
    // Fall back to local file
    console.log('📂 Loading database from local file...');
    return dbLoad();
}

// ============================================================
// DROPBOX — BACKUP DATABASE
// ============================================================
async function dropboxBackup() {
    try {
        if (!dbx) { await refreshDropboxToken(); if (!dbx) return; }
        const content = fs.readFileSync(DB_FILE, 'utf8');
        await dbx.filesUpload({
            path:     DROPBOX_DB_PATH,
            contents: content,
            mode:     { '.tag': 'overwrite' }
        });
        console.log(`☁️  Dropbox backup OK → ${DROPBOX_DB_PATH}`);
    } catch (err) {
        console.error('❌ Dropbox backup error:', err.message);
    }
}

// ============================================================
// DROPBOX — init + create folder
// ============================================================
async function initializeDropbox() {
    try {
        console.log('🔗 Initialising Dropbox...');
        const ok = await refreshDropboxToken();
        if (!ok) return false;

        // Test connection
        await dbx.usersGetCurrentAccount();
        console.log('✅ Dropbox connected');

        // Ensure /hyprion folder exists
        try {
            await dbx.filesCreateFolderV2({ path: '/hyprion' });
            console.log('📁 Dropbox /hyprion folder created');
        } catch (e) {
            // Folder already exists — that's fine
            if (!e.error?.error?.['.tag']?.includes('conflict')) {
                console.log('📁 Dropbox /hyprion folder already exists');
            }
        }
        return true;
    } catch (err) {
        console.error('❌ Dropbox init failed:', err.message);
        return false;
    }
}

// ============================================================
// TELEGRAM
// ============================================================
async function telegramNotify(order) {
    const url  = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
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
        `👉 Manage at: /hyprionmanagement`;

    try {
        const resp = await axios.post(url,
            { chat_id: TELEGRAM_CHAT, text, parse_mode: 'Markdown' },
            { timeout: 15000 }
        );
        if (resp.data && resp.data.ok) {
            console.log(`📲 Telegram sent for order ${order.orderId}`);
        } else {
            console.error('❌ Telegram error:', JSON.stringify(resp.data));
        }
    } catch (err) {
        console.error('❌ Telegram failed:', err.response ? JSON.stringify(err.response.data) : err.message);
    }
}

// ============================================================
// AUTO BACKUP — every 30 minutes
// ============================================================
function startAutoBackup() {
    if (autoBackupInterval) clearInterval(autoBackupInterval);
    autoBackupInterval = setInterval(async () => {
        console.log('🔄 Auto-backup running...');
        await dropboxBackup();
    }, 30 * 60 * 1000);
    console.log('🔄 Auto-backup: every 30 minutes');
}

// ============================================================
// AUTO RESTART — exact GlobeSMS performHerokuRestart
// exit(143) so Heroku / PM2 restarts automatically
// ============================================================
async function performHerokuRestart() {
    console.log('🚀 Initiating auto-restart (Heroku pattern)...');
    try {
        await dropboxBackup();
        await new Promise(r => setTimeout(r, 3000));
    } catch (e) { console.error(e.message); }
    process.exit(143);
}

restartTimer = setInterval(() => {
    console.log('⏰ 1 hour elapsed — initiating scheduled restart...');
    performHerokuRestart();
}, 60 * 60 * 1000);
console.log('🔄 Auto-restart: every 1 hour (exit 143)');

// ============================================================
// PAGE ROUTES
// ============================================================
app.get('/',                  (_req, res) => res.redirect('/hyprion'));
app.get('/hyprion',           (_req, res) => res.sendFile(path.join(__dirname, 'public', 'hyprion.html')));
app.get('/hyprionorder',      (_req, res) => res.sendFile(path.join(__dirname, 'public', 'order.html')));
app.get('/hyprionmanagement', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'management.html')));

// ============================================================
// API — IMAGE PROXY  (bypasses browser ad-blockers / Brave shields)
// GET /api/hyprion-img/:index  → fetches catbox image server-side
// GET /api/hyprion-img-list    → returns the list of proxy URLs
// ============================================================
app.get('/api/hyprion-img-list', (_req, res) => {
    // Return proxy URLs — browser fetches from OUR server, not catbox
    const proxyUrls = PRODUCT_IMAGES.map((_, i) => `/api/hyprion-img/${i}`);
    res.json({ success: true, images: proxyUrls, count: proxyUrls.length });
});

app.get('/api/hyprion-img/:index', async (req, res) => {
    const idx = parseInt(req.params.index, 10);
    if (isNaN(idx) || idx < 0 || idx >= PRODUCT_IMAGES.length) {
        return res.status(404).json({ error: 'Image not found' });
    }
    try {
        const imgResp = await axios.get(PRODUCT_IMAGES[idx], {
            responseType: 'stream',
            timeout: 10000,
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; HyprionServer/1.0)' }
        });
        // Cache for 24 hours
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.setHeader('Content-Type', imgResp.headers['content-type'] || 'image/jpeg');
        imgResp.data.pipe(res);
    } catch (err) {
        console.error(`Image proxy error (index ${idx}):`, err.message);
        res.status(502).json({ error: 'Failed to fetch image' });
    }
});

// ============================================================
// API — TESTIMONIAL IMAGE PROXY  (catbox testimonial screenshots)
// GET /api/hyprion-testi/:index
// ============================================================
const TESTI_IMAGES = [
    'https://files.catbox.moe/gmgfcu.jpg',
    'https://files.catbox.moe/41syse.jpg',
    'https://files.catbox.moe/41syse.jpg'
];

app.get('/api/hyprion-testi/:index', async (req, res) => {
    const idx = parseInt(req.params.index, 10);
    if (isNaN(idx) || idx < 0 || idx >= TESTI_IMAGES.length) {
        return res.status(404).json({ error: 'Image not found' });
    }
    try {
        const imgResp = await axios.get(TESTI_IMAGES[idx], {
            responseType: 'stream',
            timeout: 10000,
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; HyprionServer/1.0)' }
        });
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.setHeader('Content-Type', imgResp.headers['content-type'] || 'image/jpeg');
        imgResp.data.pipe(res);
    } catch (err) {
        console.error(`Testi proxy error (${idx}):`, err.message);
        res.status(502).json({ error: 'Failed to fetch image' });
    }
});

// ============================================================
// API — ADMIN LOGIN
// POST /api/hyprion-admin-login  { password }
// ============================================================
app.post('/api/hyprion-admin-login', (req, res) => {
    const { password } = req.body;
    if (!password || password !== ADMIN_PASSWORD) {
        console.log('❌ Failed admin login');
        return res.status(401).json({ success: false, message: 'Invalid password.' });
    }
    const token = jwt.sign(
        { role: 'hyprion_admin', jti: crypto.randomBytes(8).toString('hex') },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    console.log('✅ Admin logged in');
    return res.json({ success: true, token, expiresIn: '24h' });
});

// ============================================================
// API — VERIFY SESSION
// GET /api/hyprion-verify-session
// ============================================================
app.get('/api/hyprion-verify-session', adminAuth, (_req, res) => {
    res.json({ success: true, authenticated: true });
});

// ============================================================
// API — PLACE ORDER
// POST /api/hyprion-order
// ============================================================
app.post('/api/hyprion-order', orderRateLimit, async (req, res) => {
    try {
        const { fullName, phone, whatsapp, email, state, city, address, notes, package: pkg, packageQty, source, referral } = req.body;

        if (!fullName || String(fullName).trim().length < 2)
            return res.status(400).json({ success: false, message: 'Full name is required.' });
        if (!phone || !/^[0-9+\s\-]{7,15}$/.test(String(phone).trim()))
            return res.status(400).json({ success: false, message: 'A valid phone number is required.' });
        if (!state || !String(state).trim())
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
            timestamp:  new Date().toISOString()
        };

        const db    = dbLoad();
        db.orders.unshift(order);
        const saved = dbSave(db);

        if (!saved) return res.status(500).json({ success: false, message: 'Failed to save order. Please try again.' });

        console.log(`✅ Order: ${order.orderId} | ${order.fullName} | ${order.phone} | ${order.state}`);

        // Non-blocking: Telegram + Dropbox backup
        telegramNotify(order).catch(e => console.error('Telegram:', e.message));
        dropboxBackup().catch(e => console.error('Backup:', e.message));

        return res.status(201).json({
            success:  true,
            message:  'Order placed! We will call you shortly to confirm.',
            orderId:  order.orderId
        });
    } catch (err) {
        console.error('❌ Order error:', err);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ============================================================
// API — GET ALL ORDERS (admin)
// ============================================================
app.get('/api/hyprion-orders', adminAuth, (_req, res) => {
    try {
        const db = dbLoad();
        res.json({ success: true, orders: db.orders, total: db.orders.length, lastUpdated: db.lastUpdated });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to load orders.' });
    }
});

// ============================================================
// API — UPDATE ORDER STATUS (admin)
// ============================================================
app.patch('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const { status } = req.body;
        const allowed    = ['New', 'Confirmed', 'Shipped', 'Delivered', 'Cancelled'];
        if (!allowed.includes(status))
            return res.status(400).json({ success: false, message: `Invalid status. Allowed: ${allowed.join(', ')}` });

        const db  = dbLoad();
        const idx = db.orders.findIndex(o => o.orderId === req.params.orderId);
        if (idx === -1) return res.status(404).json({ success: false, message: 'Order not found.' });

        const prev = db.orders[idx].status;
        db.orders[idx].status    = status;
        db.orders[idx].updatedAt = new Date().toISOString();
        dbSave(db);
        dropboxBackup().catch(() => {});
        console.log(`📝 ${req.params.orderId}: ${prev} → ${status}`);
        res.json({ success: true, orderId: req.params.orderId, status });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update order.' });
    }
});

// ============================================================
// API — DELETE ORDER (admin)
// ============================================================
app.delete('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const db     = dbLoad();
        const before = db.orders.length;
        db.orders    = db.orders.filter(o => o.orderId !== req.params.orderId);
        if (db.orders.length === before) return res.status(404).json({ success: false, message: 'Order not found.' });
        dbSave(db);
        dropboxBackup().catch(() => {});
        console.log(`🗑️  Deleted ${req.params.orderId}`);
        res.json({ success: true, message: 'Order deleted.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete order.' });
    }
});

// ============================================================
// API — MANUAL BACKUP (admin)
// ============================================================
app.post('/api/hyprion-backup', adminAuth, async (_req, res) => {
    try {
        await dropboxBackup();
        res.json({ success: true, message: 'Backup completed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Backup failed: ' + err.message });
    }
});

// ============================================================
// HEALTH
// ============================================================

// ============================================================
// API — PUBLIC CONFIG (pixels — safe to expose, IDs are public)
// GET /api/hyprion-config
// ============================================================
app.get('/api/hyprion-config', (_req, res) => {
    res.json({
        fbPixelId:     FB_PIXEL_ID     || null,
        tiktokPixelId: TIKTOK_PIXEL_ID || null,
        pixelsEnabled: {
            facebook: !!FB_PIXEL_ID,
            tiktok:   !!TIKTOK_PIXEL_ID
        }
    });
});

app.get('/health', (_req, res) => {
    const db = dbLoad();
    res.json({
        status:      'ok',
        server:      'Hyprion Herbal Capsules',
        uptime:      Math.floor(process.uptime()) + 's',
        totalOrders: db.totalOrders || 0,
        dropbox:     dbx ? 'connected' : 'disconnected',
        telegram:    `chat ${TELEGRAM_CHAT}`,
        autoBackup:  autoBackupInterval ? 'running (30min)' : 'stopped',
        autoRestart: restartTimer       ? 'running (1hr)'   : 'stopped',
        timestamp:   new Date().toISOString()
    });
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
async function gracefulShutdown(signal) {
    console.log(`\n🔄 ${signal} — backing up and shutting down...`);
    try { await dropboxBackup(); } catch (e) { console.error(e.message); }
    if (autoBackupInterval) clearInterval(autoBackupInterval);
    if (restartTimer)       clearInterval(restartTimer);
    console.log('👋 Done.');
    process.exit(0);
}
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// ============================================================
// SERVER INIT — GlobeSMS pattern:
// 1. Refresh Dropbox token
// 2. Create folder structure
// 3. RESTORE database from Dropbox (loadDatabaseFromDropbox)
// 4. Start auto-backup
// 5. Listen
// ============================================================
async function initializeServer() {
    try {
        console.log('\n' + '═'.repeat(58));
        console.log('🌿  HYPRION HERBAL CAPSULES SERVER STARTING');
        console.log('═'.repeat(58));

        // Step 1: Connect Dropbox
        const dropboxOk = await initializeDropbox();

        // Step 2: RESTORE DATABASE FROM DROPBOX (like GlobeSMS readAllDatabases)
        const db = await loadDatabaseFromDropbox();

        // Step 3: Start auto-backup (every 30 min)
        startAutoBackup();

        // Step 4: Listen
        app.listen(PORT, () => {
            console.log('═'.repeat(58));
            console.log(`✅  Port         : ${PORT}`);
            console.log(`🌿  Landing      : /hyprion`);
            console.log(`🛒  Order        : /hyprionorder`);
            console.log(`🔐  Admin        : /hyprionmanagement`);
            console.log(`📦  Orders in DB : ${db.orders ? db.orders.length : 0}`);
            console.log(`☁️   Dropbox      : ${dropboxOk ? '✅ Connected' : '❌ Failed (using local)'}`);
            console.log(`📲  Telegram     : chat ${TELEGRAM_CHAT}`);
            console.log(`🖼️   Image proxy  : /api/hyprion-img/0..${PRODUCT_IMAGES.length - 1}`);
            console.log(`🔄  Auto-backup  : every 30 min`);
            console.log(`🔄  Auto-restart : every 1 hour (exit 143)`);
            console.log('═'.repeat(58) + '\n');
        });

    } catch (err) {
        console.error('❌ Server init failed:', err);
        process.exit(1);
    }
}

initializeServer();
