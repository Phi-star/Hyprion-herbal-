require('dotenv').config();
const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const axios     = require('axios');
const { Dropbox } = require('dropbox');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURATION
// ============================================================
const HYPRION_ADMIN_PASSWORD = process.env.HYPRION_ADMIN_PASSWORD || 'phistar2025';
const TELEGRAM_BOT_TOKEN     = process.env.TELEGRAM_BOT_TOKEN    || '7756847746:AAHCWrPTLqWKaMvqcVnMeSU9iCWV_77Angw';
const TELEGRAM_CHAT_ID       = process.env.TELEGRAM_CHAT_ID       || '6300694007';

const DROPBOX_APP_KEY        = process.env.DROPBOX_APP_KEY        || 'ho5ep3i58l3tvgu';
const DROPBOX_APP_SECRET     = process.env.DROPBOX_APP_SECRET     || '9fy0w0pgaafyk3e';
const DROPBOX_REFRESH_TOKEN  = process.env.DROPBOX_REFRESH_TOKEN  || 'Vjhcbg66GMgAAAAAAAAAARJPgSupFcZdyXFkXiFx7VP-oXv_64RQKmtTLUYfPtm3';
const DROPBOX_BACKUP_PATH    = '/hyprion/hypriandatabase.json';

// Local database file — hypriandatabase.json
const DB_FILE = path.join(__dirname, 'hypriandatabase.json');

// Dropbox client
let dbx                = null;
let dropboxAccessToken = null;

// Interval handles
let autoBackupTimer  = null;
let autoRestartTimer = null;

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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

// Simple per-IP rate limiter (order endpoint only)
const orderRateMap = new Map();
function orderRateLimit(req, res, next) {
    const ip     = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now    = Date.now();
    const window = 60 * 1000; // 1-minute window
    const maxReq = 5;

    if (!orderRateMap.has(ip)) {
        orderRateMap.set(ip, { count: 1, resetAt: now + window });
    } else {
        const entry = orderRateMap.get(ip);
        if (now > entry.resetAt) {
            entry.count   = 1;
            entry.resetAt = now + window;
        } else {
            entry.count++;
            if (entry.count > maxReq) {
                return res.status(429).json({
                    success: false,
                    message: 'Too many requests. Please slow down.'
                });
            }
        }
    }
    next();
}

// ============================================================
// ADMIN AUTH MIDDLEWARE
// Token format: base64("phistar2025:hyprion_admin:<timestamp>")
// Built by the management.html login page
// ============================================================
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token || '';

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized. Invalid: please provide auth token.'
        });
    }

    try {
        const decoded = Buffer.from(token, 'base64').toString('utf8');
        if (!decoded.includes(HYPRION_ADMIN_PASSWORD) || !decoded.includes('hyprion_admin')) {
            throw new Error('bad');
        }
        next();
    } catch {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized. Invalid: please provide auth token.'
        });
    }
}

// ============================================================
// DATABASE  — hypriandatabase.json
// ============================================================
function dbLoad() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            const init = {
                orders:      [],
                totalOrders: 0,
                createdAt:   new Date().toISOString(),
                lastUpdated: new Date().toISOString()
            };
            fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
            return init;
        }
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (err) {
        console.error('❌ DB load error:', err.message);
        return {
            orders:      [],
            totalOrders: 0,
            createdAt:   new Date().toISOString(),
            lastUpdated: new Date().toISOString()
        };
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
// DROPBOX  — backs up hypriandatabase.json
// ============================================================
async function dropboxConnect() {
    try {
        const resp = await axios.post(
            'https://api.dropbox.com/oauth2/token',
            null,
            {
                params: {
                    grant_type:    'refresh_token',
                    refresh_token: DROPBOX_REFRESH_TOKEN,
                    client_id:     DROPBOX_APP_KEY,
                    client_secret: DROPBOX_APP_SECRET
                },
                timeout: 15000
            }
        );
        dropboxAccessToken = resp.data.access_token;
        dbx = new Dropbox({ accessToken: dropboxAccessToken });
        console.log('☁️  Dropbox connected');
        return true;
    } catch (err) {
        console.error('❌ Dropbox connect failed:', err.message);
        return false;
    }
}

async function dropboxBackup() {
    try {
        if (!dbx) await dropboxConnect();
        if (!dbx) { console.log('⚠️  Dropbox unavailable — skipping backup'); return; }

        const content = fs.readFileSync(DB_FILE, 'utf8');
        await dbx.filesUpload({
            path:     DROPBOX_BACKUP_PATH,
            contents: content,
            mode:     { '.tag': 'overwrite' }
        });
        console.log(`☁️  Dropbox backup OK → ${DROPBOX_BACKUP_PATH}`);
    } catch (err) {
        console.error('❌ Dropbox backup error:', err.message);
    }
}

// Refresh Dropbox access token every 3 hours
setInterval(async () => {
    if (dbx) {
        console.log('🔄 Refreshing Dropbox token...');
        await dropboxConnect();
    }
}, 3 * 60 * 60 * 1000);

// ============================================================
// TELEGRAM NOTIFICATION
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
        // Non-fatal — order already saved to DB
    }
}

// ============================================================
// AUTO BACKUP — every 30 minutes
// ============================================================
function startAutoBackup() {
    autoBackupTimer = setInterval(async () => {
        console.log('🔄 Auto-backup running...');
        await dropboxBackup();
    }, 30 * 60 * 1000);
    console.log('🔄 Auto-backup: every 30 minutes');
}

// ============================================================
// AUTO RESTART — every 1 hour
// PM2 or a process manager will restart the process after exit(0)
// ============================================================
function startAutoRestart() {
    autoRestartTimer = setInterval(async () => {
        console.log('🔄 Auto-restart: 1-hour interval reached');
        try { await dropboxBackup(); } catch (e) { console.error(e.message); }
        console.log('🔄 Exiting for restart...');
        process.exit(0);
    }, 60 * 60 * 1000);
    console.log('🔄 Auto-restart: every 1 hour');
}

// ============================================================
// PAGE ROUTES
// ============================================================

// Root → redirect to /hyprion
app.get('/', (_req, res) => res.redirect('/hyprion'));

// Landing page
app.get('/hyprion', (_req, res) => {
    const file = path.join(__dirname, 'public', 'hyprion.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('hyprion.html not found — place it in /public/');
});

// Order page
app.get('/hyprionorder', (_req, res) => {
    const file = path.join(__dirname, 'public', 'order.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('order.html not found — place it in /public/');
});

// Admin management page
app.get('/hyprionmanagement', (_req, res) => {
    const file = path.join(__dirname, 'public', 'management.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.status(404).send('management.html not found — place it in /public/');
});

// ============================================================
// API — IMAGE LISTING  (used by the auto-slideshow on all pages)
// GET /api/hyprion-images?folder=img/Hyprion
// GET /api/hyprion-images?folder=img/testimonials
// ============================================================
app.get('/api/hyprion-images', (req, res) => {
    const rawFolder  = (req.query.folder || 'img/Hyprion')
        .replace(/\.\./g, '')   // block traversal
        .replace(/^\/+/, '');
    const folderPath = path.join(__dirname, 'public', rawFolder);

    try {
        if (!fs.existsSync(folderPath)) {
            return res.json({ success: true, images: [], count: 0, folder: rawFolder });
        }
        const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
        const images  = fs.readdirSync(folderPath)
            .filter(f => allowed.includes(path.extname(f).toLowerCase()))
            .sort()
            .map(f => `/${rawFolder}/${f}`);

        res.json({ success: true, images, count: images.length, folder: rawFolder });
    } catch (err) {
        console.error('Image list error:', err.message);
        res.json({ success: true, images: [], count: 0, error: err.message });
    }
});

// ============================================================
// API — PLACE ORDER
// POST /api/hyprion-order
// ============================================================
app.post('/api/hyprion-order', orderRateLimit, async (req, res) => {
    try {
        const {
            fullName, phone, whatsapp, email,
            state, city, address, notes,
            package: pkg, packageQty,
            source, referral
        } = req.body;

        // Validation
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

        // Build order
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

        // Save to hypriandatabase.json
        const db    = dbLoad();
        db.orders.unshift(order);  // newest first
        const saved = dbSave(db);

        if (!saved) {
            return res.status(500).json({ success: false, message: 'Failed to save order. Please try again.' });
        }

        console.log(`✅ Order saved: ${order.orderId} | ${order.fullName} | ${order.phone} | ${order.state}`);

        // Fire-and-forget: Telegram + Dropbox
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
// API — GET ALL ORDERS  (admin)
// GET /api/hyprion-orders
// ============================================================
app.get('/api/hyprion-orders', adminAuth, (req, res) => {
    try {
        const db = dbLoad();
        res.json({
            success:     true,
            orders:      db.orders,
            total:       db.orders.length,
            lastUpdated: db.lastUpdated
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to load orders.' });
    }
});

// ============================================================
// API — GET SINGLE ORDER  (admin)
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
// API — UPDATE ORDER STATUS  (admin)
// PATCH /api/hyprion-order/:orderId
// Body: { "status": "Confirmed" }
// ============================================================
app.patch('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const { status } = req.body;
        const allowed    = ['New', 'Confirmed', 'Shipped', 'Delivered', 'Cancelled'];

        if (!allowed.includes(status)) {
            return res.status(400).json({
                success: false,
                message: `Invalid status. Allowed: ${allowed.join(', ')}`
            });
        }

        const db    = dbLoad();
        const index = db.orders.findIndex(o => o.orderId === req.params.orderId);

        if (index === -1)
            return res.status(404).json({ success: false, message: 'Order not found.' });

        const prev                 = db.orders[index].status;
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
// API — DELETE ORDER  (admin)
// DELETE /api/hyprion-order/:orderId
// ============================================================
app.delete('/api/hyprion-order/:orderId', adminAuth, (req, res) => {
    try {
        const db     = dbLoad();
        const before = db.orders.length;
        db.orders    = db.orders.filter(o => o.orderId !== req.params.orderId);

        if (db.orders.length === before)
            return res.status(404).json({ success: false, message: 'Order not found.' });

        dbSave(db);
        dropboxBackup().catch(() => {});
        console.log(`🗑️  Deleted order ${req.params.orderId}`);

        res.json({ success: true, message: 'Order deleted.', orderId: req.params.orderId });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete order.' });
    }
});

// ============================================================
// API — MANUAL DROPBOX BACKUP  (admin)
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
// HEALTH CHECK  (public)
// GET /health
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
        autoBackup:  autoBackupTimer  ? 'running' : 'stopped',
        autoRestart: autoRestartTimer ? 'running' : 'stopped',
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

    if (autoBackupTimer)  clearInterval(autoBackupTimer);
    if (autoRestartTimer) clearInterval(autoRestartTimer);

    console.log('👋 Hyprion server stopped.');
    process.exit(0);
}

process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// ============================================================
// START
// ============================================================
async function startServer() {
    console.log('\n' + '═'.repeat(58));
    console.log('🌿  HYPRION HERBAL CAPSULES SERVER');
    console.log('═'.repeat(58));

    dbLoad(); // ensure hypriandatabase.json exists
    console.log('📂 Database : hypriandatabase.json');

    const dropboxOk = await dropboxConnect();

    startAutoBackup();
    startAutoRestart();

    app.listen(PORT, () => {
        const db = dbLoad();
        console.log('═'.repeat(58));
        console.log(`✅  Port        : ${PORT}`);
        console.log(`🌿  Landing     : http://localhost:${PORT}/hyprion`);
        console.log(`🛒  Order       : http://localhost:${PORT}/hyprionorder`);
        console.log(`🔐  Admin       : http://localhost:${PORT}/hyprionmanagement`);
        console.log(`📦  Orders in DB: ${db.totalOrders}`);
        console.log(`☁️   Dropbox     : ${dropboxOk ? '✅ Connected' : '❌ Failed'}`);
        console.log(`📲  Telegram    : chat ID ${TELEGRAM_CHAT_ID}`);
        console.log(`🔄  Backup      : every 30 min`);
        console.log(`🔄  Restart     : every 1 hour`);
        console.log('═'.repeat(58) + '\n');
    });
}

startServer();
