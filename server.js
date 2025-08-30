'use strict';

/**
 * AI Phone Reception System (Cloud Run ready)
 * - /api/token: OpenAI Realtime用エフェメラル発行
 * - /api/sdp:   SDPをOpenAIへプロキシ
 * - /ready:     OpenAI/TURNの軽量疎通
 * - /health:    Liveness
 * - /api/*:     Cache-Control: no-store, X-Request-ID
 * - CSRF + CORS + Helmet + RateLimit + Compression
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const path = require('path');
const tls = require('node:tls');
require('dotenv').config();

const app = express();
const isDev = process.env.NODE_ENV !== 'production';

/** ---------- X-Request-ID (correlation id) ---------- */
app.use((req, res, next) => {
  const incoming = (req.headers['x-request-id'] || '').toString().trim();
  const requestId = incoming || `req_${Date.now()}_${uuidv4().slice(0,8)}`;
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
});

/** ---------- Logger (PII redaction) ---------- */
const redact = winston.format((info) => {
  const s = JSON.stringify(info)
    .replace(/sk-[A-Za-z0-9-_]{10,}/g, '[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9\.\-_]+/g, 'Bearer [REDACTED]');
  return JSON.parse(s);
})();

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    redact,
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

/** ---------- Trust proxy ---------- */
app.set('trust proxy', 1);

/** ---------- Security headers ---------- */
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "https://api.openai.com", "wss://api.openai.com"],
      mediaSrc: ["'self'", "blob:"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // NOTE: 次段でnonce化推奨
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use((_, res, next) => {
  res.setHeader('Permissions-Policy', 'microphone=(self)');
  next();
});

/** ---------- Compression ---------- */
app.use(compression({ filter: (req, _res) => !/\.sdp$/.test(req.url) }));

/** ---------- Body ---------- */
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

/** ---------- Cookies & CSRF ---------- */
app.use(cookieParser());
const csrfProtection = csrf({
  cookie: { httpOnly: false, sameSite: 'strict', secure: !isDev }
});

/** ---------- CORS ---------- */
const ALLOWED_ORIGINS = isDev
  ? ['http://localhost:8080', 'http://localhost:3000', 'http://127.0.0.1:8080']
  : (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    if (!origin && isDev) return cb(null, true);
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    logger.warn('CORS blocked', { origin });
    cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','X-CSRF-Token','Authorization','X-Request-ID'],
  credentials: true,
  maxAge: 86400
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/** ---------- /api/* no-store ---------- */
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

/** ---------- Rate limiting ---------- */
const keyOf = (req) => (req.headers['cf-connecting-ip'] ||
  (req.headers['x-forwarded-for'] || '').split(',')[0] ||
  req.ip || 'unknown');

const rl = (windowMs, max, message) => rateLimit({
  windowMs, max, message,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: keyOf,
  handler: (req, res) => {
    logger.warn('Rate limit', { ip: keyOf(req), path: req.path, requestId: req.requestId });
    res.status(429).json({ error: message, retryAfter: Math.ceil(windowMs/1000) });
  }
});
const globalLimiter = rl(15*60_000, 100, 'Too many requests');
const tokenLimiter  = rl(60_000, 10,  'Too many token requests');
const sdpLimiter    = rl(60_000, 5,   'Too many SDP posts');
app.use(globalLimiter);

/** ---------- Static ---------- */
app.use(express.static('public', { etag: true, maxAge: isDev ? 0 : 3_600_000 }))
app.get('/', (_req,res)=>res.sendFile(require('path').join(__dirname,'public','index.html')));;

/** ---------- Health ---------- */
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'healthy', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

/** ---------- Ready (OpenAI/TURN疎通) ---------- */
app.get('/ready', async (_req, res) => {
  const results = { openai: false, turn: false, errors: {} };
  // OpenAI TLS
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 2000);
    const r = await fetch('https://api.openai.com/', { method: 'HEAD', signal: ac.signal });
    clearTimeout(t);
    results.openai = r.ok || r.status >= 200;
  } catch (e) { results.errors.openai = e.message; }

  // TURN TLS (turns:host:443?transport=tcp)
  try {
    const turns = (process.env.TURN_URLS || '').split(',').map(s=>s.trim()).find(u => u.startsWith('turns:'));
    if (turns) {
      const hostPort = turns.replace('turns:', '').split('?')[0];
      const [host, portStr] = hostPort.split(':');
      const port = parseInt(portStr || '443', 10);
      await new Promise((resolve, reject) => {
        const s = tls.connect({ host, port, servername: host, timeout: 2000 }, () => { s.end(); resolve(); });
        s.on('error', reject);
        s.on('timeout', () => { s.destroy(new Error('timeout')); });
      });
      results.turn = true;
    } else {
      results.turn = isDev ? true : false;
      if (!isDev) results.errors.turn = 'TURN_URLS not set';
    }
  } catch (e) { results.errors.turn = e.message; }

  const ready = results.openai && results.turn;
  res.status(ready ? 200 : 503).json({ ready, results, ts: new Date().toISOString() });
});

/** ---------- CSRF token ---------- */
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/** ---------- /api/client-error ---------- */
app.post('/api/client-error', csrfProtection, (req, res) => {
  const bodyChunks = [];
  req.on('data', c => bodyChunks.push(c));
  req.on('end', () => {
    let payload = {};
    try { payload = JSON.parse(Buffer.concat(bodyChunks).toString('utf8')); } catch {}
    logger.warn('ClientError', { requestId: req.requestId, ...payload });
    res.status(204).end();
  });
});

/** ---------- Allowed lists ---------- */
const ALLOWED_VOICES = (process.env.ALLOWED_VOICES || 'verse,cedar,marin').split(',').map(s => s.trim());
const ALLOWED_MODELS = (process.env.ALLOWED_MODELS || 'gpt-realtime').split(',').map(s => s.trim());

/** ---------- Ephemeral token ---------- */
const tokenHistory = new Map();
const TOKEN_HISTORY_TTL = 5*60_000;
setInterval(() => { const now = Date.now(); for (const [k,v] of tokenHistory.entries()) if (now - v.ts > TOKEN_HISTORY_TTL) tokenHistory.delete(k); }, 60_000);

app.post('/api/token', tokenLimiter, csrfProtection, async (req, res) => {
  const clientIp  = keyOf(req);
  const requestId = req.requestId;

  const ipHist = tokenHistory.get(clientIp) || { count: 0, ts: Date.now() };
  if (ipHist.count > 20) {
    logger.error('Suspicious token usage', { requestId, clientIp, count: ipHist.count });
    return res.status(403).json({ error: 'Access denied' });
  }

  if (!process.env.OPENAI_API_KEY) {
    logger.error('Missing OPENAI_API_KEY', { requestId });
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  const json = req.body || {};

  const voice = (json.voice || process.env.VOICE_MODEL || 'verse').trim();
  const model = (json.model || process.env.REALTIME_MODEL || 'gpt-realtime').trim();
  if (!ALLOWED_VOICES.includes(voice)) return res.status(400).json({ error: `voice not allowed: ${voice}` });
  if (!ALLOWED_MODELS.includes(model)) return res.status(400).json({ error: `model not allowed: ${model}` });

  const EPHEMERAL_PATH = process.env.OPENAI_EPHEMERAL_ENDPOINT || 'client_secrets';
  const EPHEMERAL_URL  = `https://api.openai.com/v1/realtime/${EPHEMERAL_PATH}`;
  const instructions = process.env.SYSTEM_PROMPT ||
  'あなたは当社の電話受付です。日本語のみを使用し、敬語で丁寧に応対してください。' +
  '営業時間やよくある質問に回答し、対応できない場合は担当者へおつなぎします。';
  const sessionConfig = { session: { type: 'realtime', model, instructions } };

  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 5000);
    const r = await fetch(EPHEMERAL_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
        'X-Request-ID': requestId,
        ...(process.env.OPENAI_BETA_HEADER ? { 'OpenAI-Beta': process.env.OPENAI_BETA_HEADER } : {})
      },
      body: JSON.stringify(sessionConfig),
      signal: ac.signal
    });
    clearTimeout(t);

    const data = await r.json().catch(() => ({}));
    const token = data?.client_secret?.value || data?.value || data?.secret?.value || null;
    const expiresAt = data?.expires_at || data?.client_secret?.expires_at || null;
    const turnServers = data?.turn_servers || data?.ice_servers || [];

    if (!r.ok || !token) {
      logger.error('Token generation failed', { requestId, status: r.status, data });
      return res.status(502).json({ error: 'Failed to generate ephemeral token', requestId });
    }

    tokenHistory.set(clientIp, { count: ipHist.count + 1, ts: Date.now() });

    const ice = [
      { urls: ['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302'] },
      ...turnServers
    ];
    if (isDev) {
      ice.push({ urls: 'turns:openrelay.metered.ca:443?transport=tcp', username: 'openrelayproject', credential: 'openrelayproject' });
    } else if (process.env.TURN_URLS) {
      ice.push({
        urls: process.env.TURN_URLS.split(','),
        username: process.env.TURN_USERNAME || undefined,
        credential: process.env.TURN_CREDENTIAL || undefined
      });
    }

    logger.info('Token generated', { requestId, model, voice });
    res.json({
      token, expires_at: expiresAt, ttl_seconds: 60,
      ice_servers: ice, request_id: requestId, server_time: new Date().toISOString()
    });
  } catch (e) {
    const msg = e?.name === 'AbortError' ? 'Upstream timeout' : e.message;
    logger.error('Token fatal', { requestId, msg });
    res.status(500).json({ error: 'Internal server error', requestId });
  }
});

/** ---------- SDP proxy (1MB cap) ---------- */
app.post('/api/sdp', sdpLimiter, csrfProtection, async (req, res) => {
  const requestId = req.requestId;
  try {
    // read raw body with 1MB cap
    let size = 0, raw = '';
    await new Promise((resolve, reject) => {
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        size += Buffer.byteLength(chunk, 'utf8');
        if (size > 1024*1024) { reject(Object.assign(new Error('SDP too large'), { status: 413 })); return; }
        raw += chunk;
      });
      req.on('end', resolve);
      req.on('error', reject);
    });

    const auth = req.headers['authorization'];
    if (!auth || !/^Bearer\s+/.test(auth)) return res.status(400).send('Missing Authorization: Bearer <ephemeral-token>');
    if (/sk-[A-Za-z0-9-_]{10,}/.test(auth)) return res.status(400).send('Server API key is not allowed on /api/sdp');

    const headers = {
      'Authorization': auth,
      'Content-Type': 'application/sdp',
      'X-Request-ID': requestId,
      ...(process.env.OPENAI_BETA_HEADER ? { 'OpenAI-Beta': process.env.OPENAI_BETA_HEADER } : {})
    };

    const upstream = await fetch(`https://api.openai.com/v1/realtime/calls?model=${encodeURIComponent(process.env.REALTIME_MODEL || 'gpt-realtime')}`, {      method: 'POST', body: raw, headers
    });
    const text = await upstream.text();
    logger.info('SDP proxied', { requestId, status: upstream.status });
    res.status(upstream.status).type('application/sdp').send(text);
  } catch (e) {
    const status = e.status || 502;
    logger.error('/api/sdp error', { requestId, status, err: e.message });
    res.status(status).send(status === 413 ? 'SDP too large' : 'SDP proxy error');
  }
});

/** ---------- SPA fallback ---------- */
app.get(/^\/(?!api)(?!health$)(?!ready$).*/, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/** ---------- Error handler ---------- */
app.use((err, req, res, _next) => {
  if (err.code === 'EBADCSRFTOKEN') return res.status(403).json({ error: 'Invalid CSRF token' });
  res.status(500).json({ error: 'Internal server error', message: isDev ? err.message : undefined });
});

/** ---------- Boot ---------- */
const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info('Server started', {
    port: PORT,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    cors: ALLOWED_ORIGINS
  });
});

/** ---------- Graceful shutdown ---------- */
const quit = () => { try { server.close(() => process.exit(0)); } catch { process.exit(1); } setTimeout(()=>process.exit(1), 30_000); };
process.on('SIGTERM', quit);
process.on('SIGINT',  quit);
process.on('uncaughtException', quit);
process.on('unhandledRejection', () => {});
