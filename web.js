// web.js — Dashboard web con Sicurezza (Helmet, Rate Limit, CSRF, Zod)
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const axios = require('axios');
const path = require('path');
const fs = require('fs');

// ==================== SICUREZZA — import ====================
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { doubleCsrf } = require('csrf-csrf');
const { z } = require('zod');

function createWebServer({ storage, client, log, botStartTime }) {
  const app = express();
  const PORT = parseInt(process.env.PORT) || 3000;
  const HOST = process.env.WEB_HOST || '0.0.0.0';
  const IS_PROD = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
  const CLIENT_SECRET = (process.env.DISCORD_CLIENT_SECRET || '').trim();
  const DASHBOARD_URL = (process.env.DASHBOARD_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
  const SESSION_SECRET = process.env.SESSION_SECRET || 'cambia-questo-segreto-ora';
  const ENV_ADMIN_IDS = (process.env.DASHBOARD_ADMIN_IDS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  const DASHBOARD_ROLES = ['Senior Admin'];

  async function isAuthorizedByRole(userId) {
    if (ENV_ADMIN_IDS.includes(userId)) return true;
    try {
      for (const guild of client.guilds.cache.values()) {
        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) continue;
        if (member.roles.cache.some(r => DASHBOARD_ROLES.includes(r.name))) return true;
      }
    } catch (err) { log.err('isAuthorizedByRole', err); }
    return false;
  }

  // ==================== HELMET ====================
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https://cdn.discordapp.com"],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    hsts: IS_PROD ? { maxAge: 15552000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'no-referrer' }
  }));

  // ==================== BODY LIMITS ====================
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));

  // ==================== SESSION STORE ====================
  const SESSION_DIR = path.join(__dirname, 'data', 'sessions');
  try { if (!fs.existsSync(SESSION_DIR)) fs.mkdirSync(SESSION_DIR, { recursive: true }); } catch {}

  app.use(session({
    store: new FileStore({ path: SESSION_DIR, ttl: 7 * 24 * 60 * 60, retries: 0, logFn: () => {} }),
    secret: SESSION_SECRET,
    resave: false, saveUninitialized: false, proxy: true,
    cookie: {
      secure: IS_PROD,
      httpOnly: true,
      sameSite: IS_PROD ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));

  // ==================== CSRF ====================
  const CSRF_SECRET = process.env.CSRF_SECRET || SESSION_SECRET;
  const { generateCsrfToken, validateRequest } = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier: (req) => (req.session && req.session.user && req.session.user.id) || 'anon',
    cookieName: '_csrf',
    cookieOptions: {
      httpOnly: true,
      sameSite: IS_PROD ? 'none' : 'lax',
      secure: IS_PROD,
      path: '/'
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    getCsrfTokenFromRequest: (req) => (req.headers['x-csrf-token'] || (req.body && req.body._csrf) || '').toString()
  });

  app.use((req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.path === '/auth/login') return next();
    return validateRequest(req, res, next);
  });

  app.get('/api/csrf-token', (req, res) => {
    try { res.json({ csrfToken: generateCsrfToken(req, res) }); }
    catch (e) { res.status(500).json({ error: 'Errore CSRF' }); }
  });

  // ==================== RATE LIMIT ====================
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Troppe richieste di login, riprova più tardi.' }
  });
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 300,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Troppe richieste, riprova più tardi.' }
  });
  app.use('/auth', authLimiter);
  app.use('/api', apiLimiter);

  // ==================== SCHEMI ZOD ====================
  const userIdSchema = z.string().regex(/^\d{17,20}$/, 'ID utente non valido');
  const guildIdSchema = z.string().regex(/^\d{17,20}$/, 'ID server non valido');

  const schemaBlacklistAdd = z.object({
    userId: userIdSchema,
    username: z.string().min(1).max(64),
    reason: z.string().min(1).max(500)
  });
  const schemaBulkDelete = z.object({
    ids: z.array(z.union([z.string(), z.number()])).min(1).max(500)
  });
  const schemaConfig = z.object({
    autoroleId: z.string().regex(/^\d{17,20}$/).nullable().optional(),
    logChannelId: z.string().regex(/^\d{17,20}$/).nullable().optional()
  });
  const schemaWelcome = z.object({
    channelId: z.string().regex(/^\d{17,20}$/).nullable().optional(),
    message: z.string().max(2000).nullable().optional(),
    embedEnabled: z.boolean().optional()
  });
  const schemaCommandAdd = z.object({
    name: z.string().min(1).max(50).regex(/^[a-z0-9_-]+$/i, 'Nome comando non valido'),
    response: z.string().min(1).max(4096)
  });
  const schemaMessagesSend = z.object({
    channelId: z.string().regex(/^\d{17,20}$/),
    content: z.string().max(2000).optional(),
    embed: z.object({
      title: z.string().max(256).optional(),
      description: z.string().max(4096).optional(),
      color: z.string().max(20).optional(),
      image: z.string().url().max(500).optional(),
      thumbnail: z.string().url().max(500).optional(),
      footer: z.string().max(2048).optional()
    }).optional()
  }).refine(d => (d.content && d.content.length > 0) || (d.embed && (d.embed.title || d.embed.description)), {
    message: 'Testo o embed obbligatorio'
  });
  const schemaUserAction = z.object({
    action: z.enum(['kick', 'ban', 'unban']),
    userId: userIdSchema,
    guildId: guildIdSchema,
    reason: z.string().max(512).optional().default('')
  });

  function parseOrFail(schema, data, res) {
    const r = schema.safeParse(data);
    if (!r.success) {
      const issues = r.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
      res.status(400).json({ error: `Dati non validi — ${issues}` });
      return null;
    }
    return r.data;
  }

  // ==================== UTILITY ====================
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function apiError(res, e, msg = 'Errore interno') {
    try { log.err('api-error', e); } catch {}
    res.status(500).json({ error: msg });
  }

  function requireAuth(req, res, next) {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Non autenticato' });
      return res.redirect('/auth/login');
    }
    if (!req.session.user.dashboardAuthorized) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Non autorizzato' });
      return res.status(403).send('Accesso negato: devi avere il ruolo "Senior Admin" su un server del bot.');
    }
    next();
  }

  // ==================== PUBBLICI ====================
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: Math.floor((Date.now() - botStartTime) / 1000), guilds: client.guilds.cache.size, ping: client.ws.ping, timestamp: new Date().toISOString() });
  });
  app.get('/', (req, res) => {
    res.json({ message: 'Bot Dashboard', version: '5.1.0', loggedIn: !!req.session.user });
  });

  // ==================== OAUTH2 ====================
  app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID || !CLIENT_SECRET) return res.status(500).send('OAuth2 non configurato.');
    const params = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: `${DASHBOARD_URL}/auth/callback`, response_type: 'code', scope: 'identify' });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });

  app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Codice mancante');
    try {
      const tokenRes = await axios.post('https://discord.com/api/oauth2/token',
        new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: `${DASHBOARD_URL}/auth/callback` }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
      );
      const userRes = await axios.get('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }, timeout: 10000 });
      const user = userRes.data;

      if (!(await isAuthorizedByRole(user.id))) {
        return res.status(403).send('Accesso negato: devi avere il ruolo "Senior Admin" su un server del bot.');
      }
      log.ok(`OAuth login riuscito per ${user.username} (${user.id})`);

      try {
        const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'sconosciuto';
        const ua = (req.headers['user-agent'] || '').slice(0, 300);
        storage.saveDashboardAccess(user.id, user.username, ip, ua);
      } catch (e) { log.err('saveDashboardAccess', e); }

      req.session.regenerate((err) => {
        if (err) return res.status(500).send('Errore login');
        req.session.user = { id: user.id, username: user.username, global_name: user.global_name || user.username, avatar: user.avatar, dashboardAuthorized: true };
        req.session.save(() => res.redirect('/dashboard'));
      });
    } catch (err) {
      log.err('OAuth', err.response?.data || err.message);
      res.status(500).send('Errore login');
    }
  });

  app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
  app.get('/auth/me', (req, res) => res.json({ user: req.session.user || null }));

  // ==================== API ====================
  app.get('/api/stats', requireAuth, (req, res) => {
    try {
      const s = storage.getStats();
      res.json({ logs: s.total, blacklist: s.blacklist, guilds: client.guilds.cache.size, ping: client.ws.ping, uptime: Math.floor((Date.now() - botStartTime) / 1000), byType: s.byType });
    } catch (e) { apiError(res, e, 'Errore statistiche'); }
  });

  app.get('/api/blacklist', requireAuth, (req, res) => {
    try { res.json(storage.getAllBlacklist()); } catch (e) { apiError(res, e); }
  });
  app.post('/api/blacklist', requireAuth, (req, res) => {
    const data = parseOrFail(schemaBlacklistAdd, req.body || {}, res);
    if (!data) return;
    try {
      if (storage.isBlacklisted(data.userId)) return res.status(409).json({ error: 'Già in blacklist' });
      storage.addToBlacklist(data.userId, data.username, data.reason, req.session.user.id, req.session.user.username);
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });
  app.delete('/api/blacklist/:userId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).json({ error: 'ID non valido' });
    try { res.json({ ok: storage.removeFromBlacklist(req.params.userId) }); } catch (e) { apiError(res, e); }
  });
  app.post('/api/blacklist/bulk-delete', requireAuth, (req, res) => {
    const data = parseOrFail(schemaBulkDelete, req.body || {}, res);
    if (!data) return;
    try {
      let count = 0;
      for (const id of data.ids) if (storage.removeFromBlacklist(String(id))) count++;
      res.json({ ok: true, count });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/logs/all', requireAuth, (req, res) => {
    try { res.json(storage.getAllLogs(500)); } catch (e) { res.json([]); }
  });
  app.get('/api/logs/:userId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).json({ error: 'ID non valido' });
    try { res.json(storage.getLogsForUser(req.params.userId)); } catch (e) { apiError(res, e); }
  });

  app.get('/api/notes/all', requireAuth, (req, res) => {
    try { res.json(storage.getAllNotes()); } catch (e) { res.json([]); }
  });
  app.delete('/api/notes/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'ID non valido' });
    try { res.json({ ok: storage.deleteNoteById(id) }); } catch (e) { apiError(res, e); }
  });
  app.post('/api/notes/bulk-delete', requireAuth, (req, res) => {
    const data = parseOrFail(schemaBulkDelete, req.body || {}, res);
    if (!data) return;
    try {
      let count = 0;
      for (const id of data.ids) if (storage.deleteNoteById(parseInt(id, 10))) count++;
      res.json({ ok: true, count });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/config/:guildId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    try { res.json(storage.getGuildConfig(req.params.guildId)); } catch (e) { apiError(res, e); }
  });
  app.post('/api/config/:guildId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const data = parseOrFail(schemaConfig, req.body || {}, res);
    if (!data) return;
    const guildId = req.params.guildId;
    try {
      if (data.autoroleId !== undefined) {
        if (data.autoroleId) storage.setAutorole(guildId, data.autoroleId);
        else storage.clearAutorole(guildId);
      }
      if (data.logChannelId !== undefined) {
        if (data.logChannelId) storage.setLogChannel(guildId, data.logChannelId);
        else storage.clearLogChannel(guildId);
      }
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/welcome/:guildId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    try { res.json(storage.getWelcomeConfig(req.params.guildId) || {}); } catch (e) { apiError(res, e); }
  });
  app.post('/api/welcome/:guildId', requireAuth, (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const data = parseOrFail(schemaWelcome, req.body || {}, res);
    if (!data) return;
    const guildId = req.params.guildId;
    try {
      if (data.channelId !== undefined) {
        if (data.channelId) storage.setWelcomeChannel(guildId, data.channelId);
        else storage.disableWelcome(guildId);
      }
      if (data.message !== undefined && data.message !== null) storage.setWelcomeMessage(guildId, data.message);
      if (data.embedEnabled !== undefined) {
        const current = storage.getWelcomeConfig(guildId);
        storage.setWelcomeConfig(guildId, { channelId: current?.channel_id ?? null, message: current?.message ?? null, embedEnabled: data.embedEnabled });
      }
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/tickets', requireAuth, (req, res) => {
    try {
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-')) {
            tickets.push({ guild: guild.name, guildId: guild.id, channel: ch.name, channelId: ch.id, userId: ch.name.replace('ticket-', '') });
          }
        }
      }
      res.json(tickets);
    } catch (e) { apiError(res, e); }
  });
  app.delete('/api/tickets/:channelId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.channelId)) return res.status(400).json({ error: 'ID canale non valido' });
    try {
      const ch = await client.channels.fetch(req.params.channelId).catch(() => null);
      if (!ch) return res.status(404).json({ error: 'Canale non trovato' });
      if (!ch.guild) return res.status(400).json({ error: 'Canale non appartenente a un server' });
      await ch.delete('Chiuso dalla dashboard web');
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/commands', requireAuth, (req, res) => {
    try {
      const cmds = storage.loadCommands();
      res.json(Object.entries(cmds).map(([name, response]) => ({ name, response })));
    } catch (e) { apiError(res, e); }
  });
  app.post('/api/commands', requireAuth, (req, res) => {
    const data = parseOrFail(schemaCommandAdd, req.body || {}, res);
    if (!data) return;
    try {
      storage.saveCommand(data.name.toLowerCase(), data.response);
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });
  app.delete('/api/commands/:name', requireAuth, (req, res) => {
    const name = String(req.params.name || '').toLowerCase();
    if (!/^[a-z0-9_-]{1,50}$/.test(name)) return res.status(400).json({ error: 'Nome non valido' });
    try { res.json({ ok: storage.deleteCommand(name) }); } catch (e) { apiError(res, e); }
  });
  app.post('/api/commands/bulk-delete', requireAuth, (req, res) => {
    const schema = z.object({ names: z.array(z.string().regex(/^[a-z0-9_-]{1,50}$/i)).min(1).max(500) });
    const data = parseOrFail(schema, req.body || {}, res);
    if (!data) return;
    try {
      let count = 0;
      for (const n of data.names) if (storage.deleteCommand(n)) count++;
      res.json({ ok: true, count });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/charts', requireAuth, (req, res) => {
    try {
      const byType = storage.db.prepare('SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type').all();
      const byDay = storage.db.prepare("SELECT substr(timestamp,1,10) as day, COUNT(*) as c FROM mod_logs GROUP BY day ORDER BY day DESC LIMIT 30").all();
      res.json({ byType, byDay });
    } catch (e) { res.json({ byType: [], byDay: [] }); }
  });

  app.get('/api/top', requireAuth, (req, res) => {
    try {
      const moderators = storage.db.prepare(`SELECT moderator, COUNT(*) as c FROM mod_logs WHERE moderator IS NOT NULL AND moderator != 'Sistema Automatico' GROUP BY moderator ORDER BY c DESC LIMIT 10`).all();
      const targets = storage.db.prepare(`SELECT target_id, target, COUNT(*) as c FROM mod_logs WHERE target_id IS NOT NULL GROUP BY target_id ORDER BY c DESC LIMIT 10`).all();
      const types = storage.db.prepare(`SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type ORDER BY c DESC`).all();
      const byMonth = storage.db.prepare(`SELECT substr(timestamp,1,7) as month, COUNT(*) as c FROM mod_logs GROUP BY month ORDER BY month DESC LIMIT 12`).all();
      res.json({ moderators, targets, types, byMonth });
    } catch (e) {
      log.err('api/top', e);
      res.json({ moderators: [], targets: [], types: [], byMonth: [] });
    }
  });

  app.get('/api/guilds', requireAuth, (req, res) => {
    try {
      const guilds = client.guilds.cache.map(g => ({
        id: g.id, name: g.name,
        roles: g.roles.cache.filter(r => r.name !== '@everyone').map(r => ({ id: r.id, name: r.name })),
        channels: g.channels.cache.filter(c => c.type === 0).map(c => ({ id: c.id, name: c.name }))
      }));
      res.json(guilds);
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/user/:userId', requireAuth, (req, res) => {
    const userId = req.params.userId;
    if (!/^\d{17,20}$/.test(userId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const logs = storage.getLogsForUser(userId);
      const notes = storage.db.prepare('SELECT * FROM member_notes WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(userId);
      const blacklistEntry = storage.getBlacklistEntry(userId);
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name === `ticket-${userId}`) {
            tickets.push({ guild: guild.name, guildId: guild.id, channel: ch.name, channelId: ch.id });
          }
        }
      }
      const byTypeMap = logs.reduce((acc, l) => { acc[l.type] = (acc[l.type] || 0) + 1; return acc; }, {});
      res.json({ userId, logs, notes, blacklist: blacklistEntry, tickets, byType: Object.entries(byTypeMap).map(([type, c]) => ({ type, c })) });
    } catch (e) { apiError(res, e, 'Errore caricamento utente'); }
  });

  app.get('/api/search', requireAuth, (req, res) => {
    const q = (req.query.q || '').toString().trim().toLowerCase().slice(0, 100);
    if (!q) return res.json({ blacklist: [], notes: [], logs: [], tickets: [] });
    try {
      const blacklist = storage.getAllBlacklist().filter(e => (e.user_id || '').toLowerCase().includes(q) || (e.username || '').toLowerCase().includes(q) || (e.reason || '').toLowerCase().includes(q));
      const notes = storage.getAllNotes().filter(n => (n.user_id || '').toLowerCase().includes(q) || (n.content || '').toLowerCase().includes(q) || (n.author_tag || '').toLowerCase().includes(q));
      const logs = storage.getAllLogs(500).filter(l => (l.target_id || '').toLowerCase().includes(q) || (l.target || '').toLowerCase().includes(q) || (l.moderator || '').toLowerCase().includes(q) || (l.reason || '').toLowerCase().includes(q));
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-') && ch.name.toLowerCase().includes(q)) {
            tickets.push({ guild: guild.name, channel: ch.name, channelId: ch.id, userId: ch.name.replace('ticket-', '') });
          }
        }
      }
      res.json({ blacklist, notes, logs, tickets });
    } catch (e) { apiError(res, e, 'Errore ricerca'); }
  });

  function toCsv(rows, headers) {
    if (!rows.length) return headers.join(',');
    const esc = (v) => {
      const s = (v === null || v === undefined) ? '' : String(v);
      return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return headers.join(',') + '\n' + rows.map(r => headers.map(h => esc(r[h])).join(',')).join('\n');
  }

  app.get('/api/export/blacklist.csv', requireAuth, (req, res) => {
    try {
      const csv = toCsv(storage.getAllBlacklist(), ['user_id', 'username', 'reason', 'moderator_tag', 'added_at']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="blacklist.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/notes.csv', requireAuth, (req, res) => {
    try {
      const csv = toCsv(storage.getAllNotes(), ['id', 'guild_id', 'user_id', 'author_tag', 'content', 'created_at']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="notes.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/logs.csv', requireAuth, (req, res) => {
    try {
      const csv = toCsv(storage.getAllLogs(5000), ['id', 'type', 'target_id', 'target', 'moderator', 'reason', 'duration', 'channel', 'timestamp']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="modlogs.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/access-logs.csv', requireAuth, (req, res) => {
    try {
      const csv = toCsv(storage.getDashboardAccessLogs(), ['id', 'user_id', 'username', 'ip', 'user_agent', 'timestamp']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="access-logs.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/access-logs', requireAuth, (req, res) => {
    try { res.json(storage.getDashboardAccessLogs()); } catch (e) { res.json([]); }
  });

  // ==================== MESSAGGI ====================
  app.get('/api/messages/channels', requireAuth, (req, res) => {
    try {
      const out = [];
      for (const guild of client.guilds.cache.values()) {
        for (const ch of guild.channels.cache.values()) {
          if (ch.type === 0) out.push({ guildId: guild.id, guildName: guild.name, channelId: ch.id, channelName: ch.name });
        }
      }
      out.sort((a, b) => a.guildName.localeCompare(b.guildName) || a.channelName.localeCompare(b.channelName));
      res.json(out);
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/messages/send', requireAuth, async (req, res) => {
    const data = parseOrFail(schemaMessagesSend, req.body || {}, res);
    if (!data) return;
    try {
      const channel = await client.channels.fetch(data.channelId).catch(() => null);
      if (!channel || !channel.isTextBased()) return res.status(404).json({ error: 'Canale non valido' });
      const botMember = channel.guild?.members?.me;
      if (botMember && !channel.permissionsFor(botMember)?.has('SendMessages')) return res.status(403).json({ error: 'Il bot non può scrivere in questo canale' });

      const payload = {};
      if (data.content) payload.content = data.content;
      if (data.embed && (data.embed.title || data.embed.description)) {
        const { EmbedBuilder } = require('discord.js');
        const e = new EmbedBuilder();
        if (data.embed.title) e.setTitle(String(data.embed.title).slice(0, 256));
        if (data.embed.description) e.setDescription(String(data.embed.description).slice(0, 4096));
        if (data.embed.color) { try { e.setColor(data.embed.color); } catch {} }
        if (data.embed.image) e.setImage(data.embed.image);
        if (data.embed.thumbnail) e.setThumbnail(data.embed.thumbnail);
        if (data.embed.footer) e.setFooter({ text: String(data.embed.footer).slice(0, 2048) });
        payload.embeds = [e];
      }

      const sent = await channel.send(payload);
      try {
        storage.saveDashboardAccess(req.session.user.id, `MSG→#${channel.name} (${channel.guild?.name || 'DM'})`, (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '-', (req.headers['user-agent'] || '').slice(0, 300));
      } catch {}
      res.json({ ok: true, messageId: sent.id, channelId: channel.id });
    } catch (e) { apiError(res, e, 'Errore invio messaggio'); }
  });

  // ==================== AZIONI UTENTE ====================
  app.get('/api/user-lookup/:userId', requireAuth, async (req, res) => {
    const userId = req.params.userId;
    if (!/^\d{17,20}$/.test(userId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const user = await client.users.fetch(userId).catch(() => null);
      if (!user) return res.status(404).json({ error: 'Utente non trovato' });
      const memberships = [];
      for (const guild of client.guilds.cache.values()) {
        const member = await guild.members.fetch(userId).catch(() => null);
        if (member) {
          memberships.push({ guildId: guild.id, guildName: guild.name, joinedAt: member.joinedAt, roles: member.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name) });
        }
      }
      res.json({ id: user.id, username: user.username, tag: user.tag, bot: user.bot, avatar: user.displayAvatarURL({ size: 128 }), createdAt: user.createdAt, memberships });
    } catch (e) { apiError(res, e, 'Errore lookup utente'); }
  });

  app.post('/api/user-action', requireAuth, async (req, res) => {
    const data = parseOrFail(schemaUserAction, req.body || {}, res);
    if (!data) return;
    const { action, userId, guildId, reason } = data;
    try {
      const guild = client.guilds.cache.get(guildId);
      if (!guild) return res.status(404).json({ error: 'Server non trovato' });
      const botMember = guild.members.me;
      if (!botMember) return res.status(500).json({ error: 'Bot non nel server' });
      const r = (reason || `Azione da dashboard (${req.session.user.username})`).slice(0, 512);

      if (action === 'kick') {
        if (!botMember.permissions.has('KickMembers')) return res.status(403).json({ error: 'Il bot non ha "Espelli Membri"' });
        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) return res.status(404).json({ error: 'Utente non nel server' });
        if (member.id === guild.ownerId) return res.status(403).json({ error: 'Non puoi espellere il proprietario' });
        if (member.roles.highest.position >= botMember.roles.highest.position) return res.status(403).json({ error: 'Ruolo troppo alto per il bot' });
        if (!member.kickable) return res.status(403).json({ error: 'Utente non espellibile' });
        await member.kick(r);
        storage.saveLog({ type: 'Kick (dashboard)', targetId: userId, target: `${member.user.tag} (${userId})`, moderator: `${req.session.user.username} (${req.session.user.id})`, reason: r, channel: 'Web Dashboard' });
      }

      if (action === 'ban') {
        if (!botMember.permissions.has('BanMembers')) return res.status(403).json({ error: 'Il bot non ha "Banna Membri"' });
        if (userId === guild.ownerId) return res.status(403).json({ error: 'Non puoi bannare il proprietario' });
        const member = await guild.members.fetch(userId).catch(() => null);
        if (member) {
          if (member.roles.highest.position >= botMember.roles.highest.position) return res.status(403).json({ error: 'Ruolo troppo alto per il bot' });
          if (!member.bannable) return res.status(403).json({ error: 'Utente non bannabile' });
        }
        await guild.members.ban(userId, { reason: r });
        storage.saveLog({ type: 'Ban (dashboard)', targetId: userId, target: member ? `${member.user.tag} (${userId})` : userId, moderator: `${req.session.user.username} (${req.session.user.id})`, reason: r, channel: 'Web Dashboard' });
      }

      if (action === 'unban') {
        if (!botMember.permissions.has('BanMembers')) return res.status(403).json({ error: 'Il bot non ha "Banna Membri"' });
        let ban = null;
        try { ban = await guild.bans.fetch(userId); } catch (e) { if (e.code !== 10026) throw e; }
        if (!ban) return res.status(404).json({ error: 'Utente non bannato' });
        await guild.members.unban(userId, r);
        storage.saveLog({ type: 'Unban (dashboard)', targetId: userId, target: `${ban.user.tag} (${userId})`, moderator: `${req.session.user.username} (${req.session.user.id})`, reason: r, channel: 'Web Dashboard' });
      }

      try {
        storage.saveDashboardAccess(req.session.user.id, `${action.toUpperCase()} ${userId} su ${guild.name}`, (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '-', (req.headers['user-agent'] || '').slice(0, 300));
      } catch {}

      res.json({ ok: true, action, userId, guildId });
    } catch (e) { apiError(res, e, 'Errore azione utente'); }
  });

  // ==================== PAGINE HTML ====================
  const pageHandler = (page, paramsFn) => (req, res, next) => {
    try {
      const params = paramsFn ? paramsFn(req) : {};
      res.send(renderLayout(req.session.user, page, params, {
        csrfToken: (() => { try { return generateCsrfToken(req, res); } catch { return ''; } })()
      }));
    } catch (e) {
      log.err(`page ${page}`, e);
      res.status(500).send('Errore rendering');
    }
  };

  app.get('/dashboard', requireAuth, pageHandler('dashboard'));
  app.get('/modlogs', requireAuth, pageHandler('modlogs'));
  app.get('/notes', requireAuth, pageHandler('notes'));
  app.get('/tickets', requireAuth, pageHandler('tickets'));
  app.get('/commands', requireAuth, pageHandler('commands'));
  app.get('/config', requireAuth, pageHandler('config'));
  app.get('/charts', requireAuth, pageHandler('charts'));
  app.get('/top', requireAuth, pageHandler('top'));
  app.get('/user/:userId', requireAuth, (req, res, next) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).send('ID non valido');
    pageHandler('user', r => ({ userId: r.params.userId }))(req, res, next);
  });
  app.get('/search', requireAuth, pageHandler('search', r => ({ q: (r.query.q || '').toString().slice(0, 100) })));
  app.get('/access-logs', requireAuth, pageHandler('accesslogs'));
  app.get('/messages', requireAuth, pageHandler('messages'));
  app.get('/user-actions', requireAuth, pageHandler('userActions'));
  app.get('/user-actions/:userId', requireAuth, (req, res, next) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).send('ID non valido');
    pageHandler('userActions', r => ({ userId: r.params.userId }))(req, res, next);
  });

  app.use((err, req, res, next) => {
    log.err('web-error', err);
    if (req.path.startsWith('/api/')) return res.status(500).json({ error: 'Errore interno' });
    res.status(500).send('Errore interno');
  });

  const server = app.listen(PORT, HOST, () => {
    log.ok(`🌐 Dashboard web su http://${HOST}:${PORT}`);
    log.info(`   Login URL: ${DASHBOARD_URL}/auth/login`);
    log.info(`   Sicurezza: helmet ✓ rate-limit ✓ csrf ✓ zod ✓`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      log.warn(`Porta ${PORT} occupata, provo ${PORT + 1}...`);
      server.listen(PORT + 1, HOST);
    } else log.err('Web server', err);
  });

  return server;
}

// ============================================================
// ================= HTML — TUTTE LE PAGINE ===================
// ============================================================
function renderLayout(user, page, params = {}, security = {}) {
  const name = escapeHtml(user.global_name || user.username);
  const avatar = user.avatar ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(user.id)}/${encodeURIComponent(user.avatar)}.png?size=64` : `https://cdn.discordapp.com/embed/avatars/0.png`;
  const csrfToken = security.csrfToken || '';
  const safeQ = escapeHtml(params.q || '');

  const pages = {
    dashboard: renderDashboardContent(),
    modlogs: renderModlogsContent(),
    notes: renderNotesContent(),
    tickets: renderTicketsContent(),
    commands: renderCommandsContent(),
    config: renderConfigContent(),
    charts: renderChartsContent(),
    top: renderTopContent(),
    user: renderUserContent(params.userId),
    search: renderSearchContent(params.q || ''),
    accesslogs: renderAccessLogsContent(),
    messages: renderMessagesContent(),
    userActions: renderUserActionsContent(params.userId || '')
  };

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="${escapeHtml(csrfToken)}">
<title>Dashboard - ${escapeHtml(page)}</title>
<script>
  window.__CSRF__ = document.querySelector('meta[name="csrf-token"]').content;
  window.apiFetch = async function(url, options = {}) {
    const opts = Object.assign({}, options);
    opts.headers = Object.assign({}, opts.headers || {});
    const method = (opts.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      opts.headers['X-CSRF-Token'] = window.__CSRF__;
      if (opts.body && typeof opts.body === 'string' && !opts.headers['Content-Type']) {
        opts.headers['Content-Type'] = 'application/json';
      }
    }
    return fetch(url, opts);
  };
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, "Segoe UI", sans-serif; background: #1a1a1a; color: #eee; padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 18px; border-bottom: 1px solid #333; gap: 16px; flex-wrap: wrap; }
  h1 { font-size: 22px; }
  .user { display: flex; align-items: center; gap: 12px; }
  .user img { width: 40px; height: 40px; border-radius: 50%; }
  .search-box { flex: 1; max-width: 400px; min-width: 200px; }
  .search-box form { display: flex; gap: 8px; }
  .search-box input { margin: 0; }
  nav { display: flex; gap: 8px; margin-bottom: 24px; flex-wrap: wrap; }
  nav a { padding: 8px 14px; background: #252525; border: 1px solid #333; border-radius: 6px; color: #bbb; font-size: 14px; }
  nav a:hover { background: #2f2f2f; }
  nav a.active { background: #5865F2; color: white; border-color: #5865F2; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .card { background: #252525; border: 1px solid #333; border-radius: 10px; padding: 18px; }
  .card h2 { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: bold; color: #5865F2; }
  .section { background: #252525; border: 1px solid #333; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  .section h2 { font-size: 18px; margin-bottom: 14px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #333; font-size: 14px; }
  th { color: #888; font-size: 11px; text-transform: uppercase; }
  button { background: #5865F2; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  button:hover { background: #4752c4; }
  button.danger { background: #ed4245; }
  button.danger:hover { background: #c93b3e; }
  button.small { padding: 5px 10px; font-size: 12px; }
  button.secondary { background: #444; }
  button.secondary:hover { background: #555; }
  input, select, textarea { background: #1a1a1a; border: 1px solid #444; color: #eee; padding: 8px 12px; border-radius: 6px; font-size: 14px; width: 100%; margin-bottom: 10px; font-family: inherit; }
  .form-row { display: flex; gap: 10px; align-items: flex-start; flex-wrap: wrap; }
  .form-row input, .form-row select { flex: 1; min-width: 150px; }
  .form-row > button { margin-top: 0; }
  .loading { color: #888; font-style: italic; }
  a { color: #5865F2; text-decoration: none; }
  a.user-link { color: #5865F2; text-decoration: none; border-bottom: 1px dashed #5865F2; }
  a.user-link:hover { color: #4752c4; border-bottom-style: solid; }
  .filter-bar { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-bar select, .filter-bar input { max-width: 250px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.kick, .badge.warn { background: #faa61a; color: #000; }
  .badge.ban { background: #ed4245; color: #fff; }
  .badge.timeout { background: #5865F2; color: #fff; }
  .badge.default { background: #444; color: #eee; }
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 768px) { .charts-grid { grid-template-columns: 1fr; } }
  .chart-box { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; }
  .config-block { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .config-block h3 { font-size: 16px; margin-bottom: 12px; color: #bbb; }
  .success { color: #00FF00; font-size: 13px; margin-top: 8px; }
  .error { color: #ed4245; font-size: 13px; margin-top: 8px; }
  code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  .export-bar { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
  .export-bar a { padding: 6px 12px; background: #444; border-radius: 6px; font-size: 12px; color: #eee; }
  .export-bar a:hover { background: #555; }
</style>
</head>
<body>
  <header>
    <h1>🤖 Dashboard Bot</h1>
    <div class="search-box">
      <form action="/search" method="get">
        <input type="text" name="q" placeholder="🔍 Cerca utente, motivo, moderatore..." value="${safeQ}" maxlength="100">
      </form>
    </div>
    <div class="user">
      <img src="${avatar}" alt="">
      <span>${name}</span>
      <a href="/auth/logout"><button class="danger">Logout</button></a>
    </div>
  </header>

  <nav>
    <a href="/dashboard" class="${page === 'dashboard' ? 'active' : ''}">📊 Dashboard</a>
    <a href="/modlogs" class="${page === 'modlogs' ? 'active' : ''}">📋 Mod Logs</a>
    <a href="/notes" class="${page === 'notes' ? 'active' : ''}">📝 Note</a>
    <a href="/tickets" class="${page === 'tickets' ? 'active' : ''}">🎫 Ticket</a>
    <a href="/commands" class="${page === 'commands' ? 'active' : ''}">🔧 Comandi</a>
    <a href="/config" class="${page === 'config' ? 'active' : ''}">⚙️ Config</a>
    <a href="/charts" class="${page === 'charts' ? 'active' : ''}">📊 Grafici</a>
    <a href="/top" class="${page === 'top' ? 'active' : ''}">🏆 Top</a>
    <a href="/messages" class="${page === 'messages' ? 'active' : ''}">✉️ Messaggi</a>
    <a href="/user-actions" class="${page === 'userActions' ? 'active' : ''}">🛠️ Gestione Utenti</a>
    <a href="/access-logs" class="${page === 'accesslogs' ? 'active' : ''}">🔐 Accessi</a>
  </nav>

  ${pages[page] || '<p>Pagina non trovata</p>'}
</body>
</html>`;
}

// ==================== UTILITY HTML ====================
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ---------- DASHBOARD ----------
function renderDashboardContent() {
  return `
  <div class="grid">
    <div class="card"><h2>Log Totali</h2><div class="value" id="stat-logs">...</div></div>
    <div class="card"><h2>Blacklist</h2><div class="value" id="stat-bl">...</div></div>
    <div class="card"><h2>Server</h2><div class="value" id="stat-guilds">...</div></div>
    <div class="card"><h2>Ping</h2><div class="value" id="stat-ping">...</div></div>
    <div class="card"><h2>Uptime</h2><div class="value" id="stat-uptime">...</div></div>
  </div>

  <div class="section">
    <h2>➕ Aggiungi alla Blacklist</h2>
    <div class="form-row">
      <input type="text" id="bl-userId" placeholder="ID utente (17-20 cifre)" maxlength="20">
      <input type="text" id="bl-username" placeholder="Username" maxlength="64">
      <input type="text" id="bl-reason" placeholder="Motivo" maxlength="500">
      <button onclick="addBL()">Aggiungi</button>
    </div>
    <div id="bl-msg"></div>
  </div>

  <div class="section">
    <h2>🚫 Blacklist Globale</h2>
    <div class="export-bar">
      <a href="/api/export/blacklist.csv">📥 Esporta CSV</a>
      <a href="#" onclick="bulkDeleteBL();return false;">🗑️ Elimina selezionati</a>
    </div>
    <div id="blacklist-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  async function loadStats() {
    const res = await apiFetch('/api/stats'); if (!res.ok) return;
    const s = await res.json();
    document.getElementById('stat-logs').textContent = s.logs;
    document.getElementById('stat-bl').textContent = s.blacklist;
    document.getElementById('stat-guilds').textContent = s.guilds;
    document.getElementById('stat-ping').textContent = s.ping + 'ms';
    const h = Math.floor(s.uptime/3600), m = Math.floor((s.uptime%3600)/60);
    document.getElementById('stat-uptime').textContent = h + 'h ' + m + 'm';
  }
  async function loadBlacklist() {
    const res = await apiFetch('/api/blacklist');
    const list = await res.json();
    const el = document.getElementById('blacklist-content');
    if (!list.length) { el.innerHTML = '<p class="loading">Nessun utente in blacklist.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="bl-select-all" onclick="toggleAllBL()"></th><th>Utente</th><th>Motivo</th><th>Aggiunto da</th><th></th></tr></thead><tbody>' +
      list.map(e => '<tr><td><input type="checkbox" class="bl-check" value="' + esc(e.user_id) + '"></td><td><a class="user-link" href="/user/' + esc(e.user_id) + '">' + esc(e.username) + '</a><br><small style="color:#666">' + esc(e.user_id) + '</small></td><td>' + esc(e.reason) + '</td><td>' + esc(e.moderator_tag) + '</td><td><button class="danger small" onclick="removeBL(\\'' + esc(e.user_id) + '\\')">Rimuovi</button></td></tr>').join('') +
      '</tbody></table>';
  }
  function toggleAllBL() {
    const checked = document.getElementById('bl-select-all').checked;
    document.querySelectorAll('.bl-check').forEach(c => c.checked = checked);
  }
  async function bulkDeleteBL() {
    const ids = Array.from(document.querySelectorAll('.bl-check:checked')).map(c => c.value);
    if (!ids.length) { alert('Nessun utente selezionato'); return; }
    if (!confirm('Rimuovere ' + ids.length + ' utenti dalla blacklist?')) return;
    const res = await apiFetch('/api/blacklist/bulk-delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    const data = await res.json();
    if (res.ok) { alert('✅ Rimossi ' + data.count + ' utenti'); loadBlacklist(); loadStats(); }
    else alert('❌ ' + (data.error || 'Errore'));
  }
  async function addBL() {
    const userId = document.getElementById('bl-userId').value.trim();
    const username = document.getElementById('bl-username').value.trim();
    const reason = document.getElementById('bl-reason').value.trim();
    const msg = document.getElementById('bl-msg');
    if (!userId || !username || !reason) { msg.innerHTML = '<span class="error">❌ Compila tutti i campi</span>'; return; }
    const res = await apiFetch('/api/blacklist', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, username, reason })
    });
    const data = await res.json();
    if (res.ok) {
      msg.innerHTML = '<span class="success">✅ Aggiunto</span>';
      document.getElementById('bl-userId').value = '';
      document.getElementById('bl-username').value = '';
      document.getElementById('bl-reason').value = '';
      loadBlacklist(); loadStats();
    } else { msg.innerHTML = '<span class="error">❌ ' + esc(data.error || 'Errore') + '</span>'; }
  }
  async function removeBL(userId) {
    if (!confirm('Rimuovere ' + userId + ' dalla blacklist?')) return;
    await apiFetch('/api/blacklist/' + encodeURIComponent(userId), { method: 'DELETE' });
    loadBlacklist(); loadStats();
  }
  loadStats(); loadBlacklist();
  setInterval(loadStats, 10000);
  </script>`;
}

// ---------- MOD LOGS ----------
function renderModlogsContent() {
  return `
  <div class="section">
    <h2>📋 Mod Logs</h2>
    <div class="export-bar"><a href="/api/export/logs.csv">📥 Esporta CSV</a></div>
    <div class="filter-bar">
      <select id="filter-type" onchange="loadLogs()">
        <option value="">Tutti i tipi</option>
        <option value="Kick">Kick</option>
        <option value="Ban">Ban</option>
        <option value="Warn">Warn</option>
        <option value="Timeout">Timeout</option>
        <option value="Clear">Clear</option>
        <option value="Purge">Purge</option>
        <option value="Lock">Lock</option>
        <option value="Unlock">Unlock</option>
      </select>
      <input type="text" id="filter-user" placeholder="Filtra per ID utente" oninput="loadLogs()" maxlength="20">
    </div>
    <div id="logs-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let allLogs = [];
  async function loadLogs() {
    if (!allLogs.length) { const res = await apiFetch('/api/logs/all'); allLogs = await res.json(); }
    const type = document.getElementById('filter-type').value;
    const userId = document.getElementById('filter-user').value.trim();
    let logs = allLogs;
    if (type) logs = logs.filter(l => l.type === type);
    if (userId) logs = logs.filter(l => (l.target_id || '').includes(userId));
    const el = document.getElementById('logs-content');
    if (!logs.length) { el.innerHTML = '<p class="loading">Nessun log trovato.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      logs.map(l => '<tr>' +
        '<td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td>' +
        '<td><span class="badge ' + esc((l.type || 'default').toLowerCase()) + '">' + esc(l.type || '-') + '</span></td>' +
        '<td>' + (l.target_id ? '<a class="user-link" href="/user/' + esc(l.target_id) + '">' + esc(l.target || l.target_id) + '</a>' : esc(l.target || '-')) + '</td>' +
        '<td>' + esc(l.moderator || '-') + '</td>' +
        '<td>' + esc(l.reason || '-') + '</td>' +
        '<td>' + esc(l.duration || '-') + '</td>' +
      '</tr>').join('') + '</tbody></table>';
  }
  loadLogs();
  </script>`;
}

// ---------- NOTE ----------
function renderNotesContent() {
  return `
  <div class="section">
    <h2>📝 Note Staff</h2>
    <div class="export-bar">
      <a href="/api/export/notes.csv">📥 Esporta CSV</a>
      <a href="#" onclick="bulkDeleteNotes();return false;">🗑️ Elimina selezionate</a>
    </div>
    <div id="notes-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  async function loadNotes() {
    const res = await apiFetch('/api/notes/all');
    const notes = await res.json();
    const el = document.getElementById('notes-content');
    if (!notes.length) { el.innerHTML = '<p class="loading">Nessuna nota.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="note-select-all" onclick="toggleAllNotes()"></th><th>#</th><th>Utente</th><th>Autore</th><th>Contenuto</th><th>Data</th><th></th></tr></thead><tbody>' +
      notes.map(n => '<tr><td><input type="checkbox" class="note-check" value="' + esc(n.id) + '"></td><td>' + esc(n.id) + '</td><td><a class="user-link" href="/user/' + esc(n.user_id) + '">' + esc(n.user_id) + '</a></td><td>' + esc(n.author_tag) + '</td><td>' + esc(n.content) + '</td><td>' + esc(new Date(n.created_at).toLocaleString('it-IT')) + '</td><td><button class="danger small" onclick="deleteNote(' + esc(n.id) + ')">Elimina</button></td></tr>').join('') + '</tbody></table>';
  }
  function toggleAllNotes() {
    const checked = document.getElementById('note-select-all').checked;
    document.querySelectorAll('.note-check').forEach(c => c.checked = checked);
  }
  async function bulkDeleteNotes() {
    const ids = Array.from(document.querySelectorAll('.note-check:checked')).map(c => c.value);
    if (!ids.length) { alert('Nessuna nota selezionata'); return; }
    if (!confirm('Eliminare ' + ids.length + ' note?')) return;
    const res = await apiFetch('/api/notes/bulk-delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    const data = await res.json();
    if (res.ok) { alert('✅ Eliminate ' + data.count + ' note'); loadNotes(); }
    else alert('❌ ' + (data.error || 'Errore'));
  }
  async function deleteNote(id) {
    if (!confirm('Eliminare la nota #' + id + '?')) return;
    const res = await apiFetch('/api/notes/' + encodeURIComponent(id), { method: 'DELETE' });
    if (res.ok) loadNotes();
    else alert('Errore durante l\\'eliminazione');
  }
  loadNotes();
  </script>`;
}

// ---------- TICKET ----------
function renderTicketsContent() {
  return `
  <div class="section">
    <h2>🎫 Ticket Aperti</h2>
    <p style="color:#888;font-size:13px;margin-bottom:14px;">Il pulsante Chiudi cancella il canale del ticket su Discord.</p>
    <div id="tickets-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  async function loadTickets() {
    const res = await apiFetch('/api/tickets');
    const tickets = await res.json();
    const el = document.getElementById('tickets-content');
    if (!tickets.length) { el.innerHTML = '<p class="loading">Nessun ticket aperto.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th>Utente (ID)</th><th></th></tr></thead><tbody>' +
      tickets.map(t => '<tr>' +
        '<td>' + esc(t.guild) + '</td>' +
        '<td>#' + esc(t.channel) + '</td>' +
        '<td><a class="user-link" href="/user/' + esc(t.userId) + '">' + esc(t.userId) + '</a></td>' +
        '<td><button class="danger small" onclick="closeTicket(\\'' + esc(t.channelId) + '\\')">Chiudi</button></td>' +
      '</tr>').join('') + '</tbody></table>';
  }
  async function closeTicket(channelId) {
    if (!confirm('Chiudere ed eliminare questo ticket? Il canale verrà cancellato su Discord.')) return;
    const res = await apiFetch('/api/tickets/' + encodeURIComponent(channelId), { method: 'DELETE' });
    if (res.ok) loadTickets();
    else { const data = await res.json(); alert('Errore: ' + (data.error || 'sconosciuto')); }
  }
  loadTickets();
  setInterval(loadTickets, 15000);
  </script>`;
}

// ---------- COMANDI CUSTOM ----------
function renderCommandsContent() {
  return `
  <div class="section">
    <h2>➕ Aggiungi Comando Custom</h2>
    <div class="form-row">
      <input type="text" id="cmd-name" placeholder="Nome (es. regole)" maxlength="50">
      <input type="text" id="cmd-response" placeholder="Risposta" maxlength="4096">
      <button onclick="addCmd()">Aggiungi</button>
    </div>
    <div id="cmd-msg"></div>
  </div>

  <div class="section">
    <h2>🔧 Comandi Custom</h2>
    <div class="export-bar">
      <a href="#" onclick="bulkDeleteCmds();return false;">🗑️ Elimina selezionati</a>
    </div>
    <div id="commands-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  async function loadCmds() {
    const res = await apiFetch('/api/commands');
    const cmds = await res.json();
    const el = document.getElementById('commands-content');
    if (!cmds.length) { el.innerHTML = '<p class="loading">Nessun comando custom.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="cmd-select-all" onclick="toggleAllCmds()"></th><th>Comando</th><th>Risposta</th><th></th></tr></thead><tbody>' +
      cmds.map(c => '<tr><td><input type="checkbox" class="cmd-check" value="' + esc(c.name) + '"></td><td><code>-' + esc(c.name) + '</code></td><td>' + esc(c.response) + '</td><td><button class="danger small" onclick="removeCmd(\\'' + esc(c.name) + '\\')">Elimina</button></td></tr>').join('') + '</tbody></table>';
  }
  function toggleAllCmds() {
    const checked = document.getElementById('cmd-select-all').checked;
    document.querySelectorAll('.cmd-check').forEach(c => c.checked = checked);
  }
  async function bulkDeleteCmds() {
    const names = Array.from(document.querySelectorAll('.cmd-check:checked')).map(c => c.value);
    if (!names.length) { alert('Nessun comando selezionato'); return; }
    if (!confirm('Eliminare ' + names.length + ' comandi?')) return;
    const res = await apiFetch('/api/commands/bulk-delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ names })
    });
    const data = await res.json();
    if (res.ok) { alert('✅ Eliminati ' + data.count + ' comandi'); loadCmds(); }
    else alert('❌ ' + (data.error || 'Errore'));
  }
  async function addCmd() {
    const name = document.getElementById('cmd-name').value.trim();
    const response = document.getElementById('cmd-response').value.trim();
    const msg = document.getElementById('cmd-msg');
    if (!name || !response) { msg.innerHTML = '<span class="error">❌ Compila tutti i campi</span>'; return; }
    const res = await apiFetch('/api/commands', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, response })
    });
    if (res.ok) {
      msg.innerHTML = '<span class="success">✅ Aggiunto</span>';
      document.getElementById('cmd-name').value = '';
      document.getElementById('cmd-response').value = '';
      loadCmds();
    } else { msg.innerHTML = '<span class="error">❌ Errore</span>'; }
  }
  async function removeCmd(name) {
    if (!confirm('Eliminare il comando -' + name + '?')) return;
    await apiFetch('/api/commands/' + encodeURIComponent(name), { method: 'DELETE' });
    loadCmds();
  }
  loadCmds();
  </script>`;
}

// ---------- CONFIG ----------
function renderConfigContent() {
  return `
  <div class="section">
    <h2>⚙️ Configurazione Server</h2>
    <p style="color:#888;font-size:13px;margin-bottom:14px;">Seleziona un server per configurare autorole, canale log e welcome.</p>
    <select id="guild-select" onchange="loadGuildConfig()"></select>
  </div>

  <div id="config-content"></div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let guildsData = [];

  async function loadGuilds() {
    const res = await apiFetch('/api/guilds');
    guildsData = await res.json();
    const sel = document.getElementById('guild-select');
    sel.innerHTML = guildsData.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('');
    if (guildsData.length) loadGuildConfig();
  }

  async function loadGuildConfig() {
    const guildId = document.getElementById('guild-select').value;
    const guild = guildsData.find(g => g.id === guildId);
    if (!guild) return;

    const [configRes, welcomeRes] = await Promise.all([
      apiFetch('/api/config/' + encodeURIComponent(guildId)),
      apiFetch('/api/welcome/' + encodeURIComponent(guildId))
    ]);
    const config = await configRes.json();
    const welcome = await welcomeRes.json();

    const content = document.getElementById('config-content');
    content.innerHTML = \`
      <div class="section">
        <div class="config-block">
          <h3>🎭 Autorole</h3>
          <select id="cfg-autorole">
            <option value="">— Nessuno —</option>
            \${guild.roles.map(r => '<option value="' + esc(r.id) + '" ' + (config.autorole_id === r.id ? 'selected' : '') + '>' + esc(r.name) + '</option>').join('')}
          </select>
          <button onclick="saveAutorole('\\\${esc(guildId)}')">Salva</button>
          <div id="autorole-msg"></div>
        </div>

        <div class="config-block">
          <h3>📋 Canale Log Moderazione</h3>
          <select id="cfg-logchannel">
            <option value="">— Nessuno —</option>
            \${guild.channels.map(c => '<option value="' + esc(c.id) + '" ' + (config.log_channel_id === c.id ? 'selected' : '') + '>#' + esc(c.name) + '</option>').join('')}
          </select>
          <button onclick="saveLogChannel('\\\${esc(guildId)}')">Salva</button>
          <div id="logchannel-msg"></div>
        </div>

        <div class="config-block">
          <h3>👋 Welcome</h3>
          <label style="font-size:13px;color:#888;">Canale di benvenuto</label>
          <select id="cfg-welcomechannel">
            <option value="">— Disattivato —</option>
            \${guild.channels.map(c => '<option value="' + esc(c.id) + '" ' + (welcome.channel_id === c.id ? 'selected' : '') + '>#' + esc(c.name) + '</option>').join('')}
          </select>
          <label style="font-size:13px;color:#888;">Messaggio (usa {user}, {username}, {server}, {memberCount})</label>
          <textarea id="cfg-welcomemessage" rows="3" placeholder="Benvenuto {user} in {server}!">\${esc(welcome.message || '')}</textarea>
          <label style="font-size:13px;color:#888;">
            <input type="checkbox" id="cfg-welcomeembed" style="width:auto;margin-right:6px;" \${welcome.embed_enabled ? 'checked' : ''}>
            Usa formato embed
          </label>
          <br><button onclick="saveWelcome('\\\${esc(guildId)}')">Salva</button>
          <div id="welcome-msg"></div>
        </div>
      </div>
    \`;
  }

  async function saveAutorole(guildId) {
    const autoroleId = document.getElementById('cfg-autorole').value || null;
    const res = await apiFetch('/api/config/' + encodeURIComponent(guildId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ autoroleId })
    });
    document.getElementById('autorole-msg').innerHTML = res.ok
      ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  async function saveLogChannel(guildId) {
    const logChannelId = document.getElementById('cfg-logchannel').value || null;
    const res = await apiFetch('/api/config/' + encodeURIComponent(guildId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logChannelId })
    });
    document.getElementById('logchannel-msg').innerHTML = res.ok
      ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  async function saveWelcome(guildId) {
    const channelId = document.getElementById('cfg-welcomechannel').value || null;
    const message = document.getElementById('cfg-welcomemessage').value;
    const embedEnabled = document.getElementById('cfg-welcomeembed').checked;
    const res = await apiFetch('/api/welcome/' + encodeURIComponent(guildId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelId, message, embedEnabled })
    });
    document.getElementById('welcome-msg').innerHTML = res.ok
      ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  loadGuilds();
  </script>`;
}

// ---------- GRAFICI ----------
function renderChartsContent() {
  return `
  <div class="section">
    <h2>📊 Statistiche Visuali</h2>
    <div class="charts-grid">
      <div class="chart-box"><canvas id="chart-types"></canvas></div>
      <div class="chart-box"><canvas id="chart-days"></canvas></div>
    </div>
  </div>

  <script>
  async function loadCharts() {
    const res = await apiFetch('/api/charts');
    const data = await res.json();
    const colors = ['#5865F2','#ed4245','#faa61a','#00FF00','#9B59B6','#1ABC9C'];
    new Chart(document.getElementById('chart-types'), {
      type: 'doughnut',
      data: { labels: data.byType.map(t => t.type), datasets: [{ data: data.byType.map(t => t.c), backgroundColor: colors }] },
      options: { plugins: { title: { display: true, text: 'Azioni per tipo', color: '#eee' }, legend: { labels: { color: '#eee' } } } }
    });
    new Chart(document.getElementById('chart-days'), {
      type: 'line',
      data: {
        labels: data.byDay.map(d => d.day).reverse(),
        datasets: [{ label: 'Azioni', data: data.byDay.map(d => d.c).reverse(), borderColor: '#5865F2', backgroundColor: 'rgba(88,101,242,0.2)', fill: true }]
      },
      options: { plugins: { title: { display: true, text: 'Azioni negli ultimi 30 giorni', color: '#eee' }, legend: { labels: { color: '#eee' } } }, scales: { x: { ticks: { color: '#888' } }, y: { ticks: { color: '#888' } } } }
    });
  }
  loadCharts();
  </script>`;
}

// ---------- TOP 10 ----------
function renderTopContent() {
  return `
  <div class="grid">
    <div class="card"><h2>Top Moderatori</h2><div class="value" id="top-mod">...</div></div>
    <div class="card"><h2>Top Utenti</h2><div class="value" id="top-user">...</div></div>
    <div class="card"><h2>Tipi Azione</h2><div class="value" id="top-types">...</div></div>
  </div>

  <div class="section">
    <h2>🏆 Top 10 Moderatori</h2>
    <div id="top-mod-content" class="loading">Caricamento...</div>
  </div>

  <div class="section">
    <h2>🎯 Top 10 Utenti più Moderati</h2>
    <div id="top-user-content" class="loading">Caricamento...</div>
  </div>

  <div class="section">
    <h2>📈 Azioni per Mese (ultimi 12)</h2>
    <div class="chart-box"><canvas id="chart-month"></canvas></div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  async function loadTop() {
    const res = await apiFetch('/api/top');
    const data = await res.json();
    document.getElementById('top-mod').textContent = data.moderators.length;
    document.getElementById('top-user').textContent = data.targets.length;
    document.getElementById('top-types').textContent = data.types.length;

    const modEl = document.getElementById('top-mod-content');
    if (!data.moderators.length) modEl.innerHTML = '<p class="loading">Nessun dato.</p>';
    else modEl.innerHTML = '<table><thead><tr><th>#</th><th>Moderatore</th><th>Azioni</th></tr></thead><tbody>' +
      data.moderators.map((m, i) => '<tr><td>#' + (i + 1) + '</td><td>' + esc(m.moderator || '-') + '</td><td><b>' + esc(m.c) + '</b></td></tr>').join('') + '</tbody></table>';

    const userEl = document.getElementById('top-user-content');
    if (!data.targets.length) userEl.innerHTML = '<p class="loading">Nessun dato.</p>';
    else userEl.innerHTML = '<table><thead><tr><th>#</th><th>Utente</th><th>Azioni</th></tr></thead><tbody>' +
      data.targets.map((t, i) => '<tr><td>#' + (i + 1) + '</td><td>' + (t.target_id ? '<a class="user-link" href="/user/' + esc(t.target_id) + '">' + esc(t.target || t.target_id) + '</a>' : esc(t.target || '-')) + '</td><td><b>' + esc(t.c) + '</b></td></tr>').join('') + '</tbody></table>';

    if (data.byMonth.length) {
      new Chart(document.getElementById('chart-month'), {
        type: 'bar',
        data: { labels: data.byMonth.map(m => m.month).reverse(), datasets: [{ label: 'Azioni', data: data.byMonth.map(m => m.c).reverse(), backgroundColor: '#5865F2' }] },
        options: { plugins: { legend: { labels: { color: '#eee' } } }, scales: { x: { ticks: { color: '#888' } }, y: { ticks: { color: '#888' } } } }
      });
    }
  }
  loadTop();
  </script>`;
}

// ---------- PAGINA UTENTE ----------
function renderUserContent(userId) {
  const safeUserId = escapeHtml(userId);
  return `
  <div class="section">
    <h2>👤 Utente <code>${safeUserId}</code></h2>
    <p style="color:#888;font-size:13px;">Dettagli completi su questo utente.</p>
    <a href="/user-actions/${encodeURIComponent(userId)}"><button class="secondary small" style="margin-top:10px;">🛠️ Gestisci utente</button></a>
  </div>

  <div class="grid">
    <div class="card"><h2>Log Totali</h2><div class="value" id="u-logs">...</div></div>
    <div class="card"><h2>Note</h2><div class="value" id="u-notes">...</div></div>
    <div class="card"><h2>Ticket Aperti</h2><div class="value" id="u-tickets">...</div></div>
    <div class="card"><h2>Blacklist</h2><div class="value" id="u-bl">...</div></div>
  </div>

  <div class="section" id="user-blacklist-section" style="display:none;">
    <h2>🚫 Stato Blacklist</h2>
    <div id="user-blacklist-content"></div>
  </div>

  <div class="section">
    <h2>📊 Azioni per Tipo</h2>
    <div class="chart-box" style="max-width:400px;margin:0 auto;"><canvas id="user-chart"></canvas></div>
  </div>

  <div class="section">
    <h2>📋 Mod Logs</h2>
    <div id="user-logs-content" class="loading">Caricamento...</div>
  </div>

  <div class="section">
    <h2>📝 Note</h2>
    <div id="user-notes-content" class="loading">Caricamento...</div>
  </div>

  <div class="section">
    <h2>🎫 Ticket Aperti</h2>
    <div id="user-tickets-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  const USER_ID = ${JSON.stringify(userId)};
  let chartInstance = null;

  async function loadUser() {
    const res = await apiFetch('/api/user/' + encodeURIComponent(USER_ID));
    if (!res.ok) { document.getElementById('u-logs').textContent = 'Errore'; return; }
    const data = await res.json();

    document.getElementById('u-logs').textContent = data.logs.length;
    document.getElementById('u-notes').textContent = data.notes.length;
    document.getElementById('u-tickets').textContent = data.tickets.length;
    document.getElementById('u-bl').textContent = data.blacklist ? 'Sì' : 'No';
    document.getElementById('u-bl').style.color = data.blacklist ? '#ed4245' : '#00FF00';

    if (data.blacklist) {
      document.getElementById('user-blacklist-section').style.display = 'block';
      const b = data.blacklist;
      document.getElementById('user-blacklist-content').innerHTML =
        '<table><thead><tr><th>Username</th><th>Motivo</th><th>Aggiunto da</th><th>Data</th><th></th></tr></thead><tbody>' +
        '<tr><td>' + esc(b.username) + '</td><td>' + esc(b.reason) + '</td><td>' + esc(b.moderator_tag) + '</td><td>' + esc(new Date(b.added_at).toLocaleString('it-IT')) + '</td><td><button class="danger small" onclick="removeBL()">Rimuovi</button></td></tr></tbody></table>';
    }

    if (data.byType.length) {
      const colors = ['#5865F2','#ed4245','#faa61a','#00FF00','#9B59B6','#1ABC9C'];
      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById('user-chart'), {
        type: 'doughnut',
        data: { labels: data.byType.map(t => t.type), datasets: [{ data: data.byType.map(t => t.c), backgroundColor: colors }] },
        options: { plugins: { legend: { labels: { color: '#eee' } } } }
      });
    } else {
      document.getElementById('user-chart').parentElement.innerHTML = '<p class="loading">Nessuna azione.</p>';
    }

    const logsEl = document.getElementById('user-logs-content');
    if (!data.logs.length) logsEl.innerHTML = '<p class="loading">Nessun log.</p>';
    else logsEl.innerHTML = '<table><thead><tr><th>Data</th><th>Tipo</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      data.logs.map(l => '<tr><td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td><td><span class="badge ' + esc((l.type || 'default').toLowerCase()) + '">' + esc(l.type || '-') + '</span></td><td>' + esc(l.moderator || '-') + '</td><td>' + esc(l.reason || '-') + '</td><td>' + esc(l.duration || '-') + '</td></tr>').join('') + '</tbody></table>';

    const notesEl = document.getElementById('user-notes-content');
    if (!data.notes.length) notesEl.innerHTML = '<p class="loading">Nessuna nota.</p>';
    else notesEl.innerHTML = '<table><thead><tr><th>#</th><th>Autore</th><th>Contenuto</th><th>Data</th><th></th></tr></thead><tbody>' +
      data.notes.map(n => '<tr><td>' + esc(n.id) + '</td><td>' + esc(n.author_tag) + '</td><td>' + esc(n.content) + '</td><td>' + esc(new Date(n.created_at).toLocaleString('it-IT')) + '</td><td><button class="danger small" onclick="deleteNote(' + esc(n.id) + ')">Elimina</button></td></tr>').join('') + '</tbody></table>';

    const ticketsEl = document.getElementById('user-tickets-content');
    if (!data.tickets.length) ticketsEl.innerHTML = '<p class="loading">Nessun ticket aperto.</p>';
    else ticketsEl.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th></th></tr></thead><tbody>' +
      data.tickets.map(t => '<tr><td>' + esc(t.guild) + '</td><td>#' + esc(t.channel) + '</td><td><button class="danger small" onclick="closeTicket(\\'' + esc(t.channelId) + '\\')">Chiudi</button></td></tr>').join('') + '</tbody></table>';
  }

  async function removeBL() {
    if (!confirm('Rimuovere ' + USER_ID + ' dalla blacklist?')) return;
    await apiFetch('/api/blacklist/' + encodeURIComponent(USER_ID), { method: 'DELETE' });
    loadUser();
  }
  async function deleteNote(id) {
    if (!confirm('Eliminare la nota #' + id + '?')) return;
    await apiFetch('/api/notes/' + encodeURIComponent(id), { method: 'DELETE' });
    loadUser();
  }
  async function closeTicket(channelId) {
    if (!confirm('Chiudere questo ticket? Il canale verrà cancellato.')) return;
    await apiFetch('/api/tickets/' + encodeURIComponent(channelId), { method: 'DELETE' });
    loadUser();
  }
  loadUser();
  </script>`;
}

// ---------- RICERCA ----------
function renderSearchContent(q) {
  return `
  <div class="section">
    <h2>🔍 Risultati per "${escapeHtml(q)}"</h2>
    <div id="search-content" class="loading">Ricerca in corso...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  const QUERY = ${JSON.stringify(q)};

  async function doSearch() {
    const el = document.getElementById('search-content');
    if (!QUERY.trim()) { el.innerHTML = '<p class="loading">Inserisci un termine di ricerca.</p>'; return; }
    const res = await apiFetch('/api/search?q=' + encodeURIComponent(QUERY));
    const data = await res.json();
    const total = data.blacklist.length + data.notes.length + data.logs.length + data.tickets.length;
    if (!total) { el.innerHTML = '<p class="loading">Nessun risultato.</p>'; return; }

    let html = '';
    if (data.blacklist.length) {
      html += '<h3 style="margin-top:20px;">🚫 Blacklist (' + data.blacklist.length + ')</h3>';
      html += '<table><thead><tr><th>Utente</th><th>Motivo</th><th>Aggiunto da</th></tr></thead><tbody>' +
        data.blacklist.map(e => '<tr><td><a class="user-link" href="/user/' + esc(e.user_id) + '">' + esc(e.username) + '</a></td><td>' + esc(e.reason) + '</td><td>' + esc(e.moderator_tag) + '</td></tr>').join('') + '</tbody></table>';
    }
    if (data.notes.length) {
      html += '<h3 style="margin-top:20px;">📝 Note (' + data.notes.length + ')</h3>';
      html += '<table><thead><tr><th>#</th><th>Utente</th><th>Contenuto</th></tr></thead><tbody>' +
        data.notes.map(n => '<tr><td>' + esc(n.id) + '</td><td><a class="user-link" href="/user/' + esc(n.user_id) + '">' + esc(n.user_id) + '</a></td><td>' + esc(n.content) + '</td></tr>').join('') + '</tbody></table>';
    }
    if (data.logs.length) {
      html += '<h3 style="margin-top:20px;">📋 Logs (' + data.logs.length + ')</h3>';
      html += '<table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th></tr></thead><tbody>' +
        data.logs.slice(0, 50).map(l => '<tr><td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td><td><span class="badge ' + esc((l.type || 'default').toLowerCase()) + '">' + esc(l.type || '-') + '</span></td><td>' + (l.target_id ? '<a class="user-link" href="/user/' + esc(l.target_id) + '">' + esc(l.target || l.target_id) + '</a>' : esc(l.target || '-')) + '</td><td>' + esc(l.moderator || '-') + '</td><td>' + esc(l.reason || '-') + '</td></tr>').join('') + '</tbody></table>';
      if (data.logs.length > 50) html += '<p style="color:#888;font-size:12px;">...e altri ' + (data.logs.length - 50) + ' log</p>';
    }
    if (data.tickets.length) {
      html += '<h3 style="margin-top:20px;">🎫 Ticket (' + data.tickets.length + ')</h3>';
      html += '<table><thead><tr><th>Server</th><th>Canale</th></tr></thead><tbody>' +
        data.tickets.map(t => '<tr><td>' + esc(t.guild) + '</td><td>#' + esc(t.channel) + '</td></tr>').join('') + '</tbody></table>';
    }
    el.innerHTML = html;
  }
  doSearch();
  </script>`;
}

// ---------- ACCESS LOGS ----------
function renderAccessLogsContent() {
  return `
  <div class="section">
    <h2>🔐 Log Accessi Dashboard</h2>
    <p style="color:#888;font-size:13px;margin-bottom:14px;">Ultimi 500 accessi alla dashboard.</p>
    <div class="export-bar"><a href="/api/export/access-logs.csv">📥 Esporta CSV</a></div>
    <div id="access-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  async function loadAccess() {
    const res = await apiFetch('/api/access-logs');
    const logs = await res.json();
    const el = document.getElementById('access-content');
    if (!logs.length) { el.innerHTML = '<p class="loading">Nessun accesso registrato.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Data</th><th>Utente</th><th>IP</th><th>User Agent</th></tr></thead><tbody>' +
      logs.map(l => '<tr>' +
        '<td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td>' +
        '<td><a class="user-link" href="/user/' + esc(l.user_id) + '">' + esc(l.username) + '</a></td>' +
        '<td><code>' + esc(l.ip || '-') + '</code></td>' +
        '<td style="font-size:11px;color:#888;">' + esc((l.user_agent || '-').slice(0, 80)) + '</td>' +
      '</tr>').join('') + '</tbody></table>';
  }
  loadAccess();
  </script>`;
}

// ---------- MESSAGGI ----------
function renderMessagesContent() {
  return `
  <div class="section">
    <h2>✉️ Invia Messaggio</h2>
    <label style="font-size:13px;color:#888;">Canale</label>
    <select id="msg-channel"></select>

    <label style="font-size:13px;color:#888;">Testo (max 2000)</label>
    <textarea id="msg-content" rows="3" placeholder="Ciao {user}..." maxlength="2000"></textarea>

    <details style="margin:14px 0;">
      <summary style="cursor:pointer;color:#5865F2;">➕ Aggiungi embed (opzionale)</summary>
      <div style="margin-top:12px;">
        <input id="emb-title" placeholder="Titolo" maxlength="256">
        <textarea id="emb-desc" rows="3" placeholder="Descrizione" maxlength="4096"></textarea>
        <input id="emb-color" placeholder="Colore (es. #5865F2)" maxlength="20">
        <input id="emb-image" placeholder="URL immagine" maxlength="500">
        <input id="emb-thumb" placeholder="URL thumbnail" maxlength="500">
        <input id="emb-footer" placeholder="Footer" maxlength="2048">
      </div>
    </details>

    <button onclick="sendMessage()">📤 Invia</button>
    <div id="msg-result"></div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let channelsCache = [];
  async function loadChannels() {
    const res = await apiFetch('/api/messages/channels');
    channelsCache = await res.json();
    const sel = document.getElementById('msg-channel');
    sel.innerHTML = channelsCache.map(c =>
      '<option value="' + esc(c.channelId) + '">' + esc(c.guildName) + ' → #' + esc(c.channelName) + '</option>'
    ).join('') || '<option value="">Nessun canale</option>';
  }

  async function sendMessage() {
    const channelId = document.getElementById('msg-channel').value;
    const content = document.getElementById('msg-content').value.trim();
    const embed = {
      title: document.getElementById('emb-title').value.trim() || undefined,
      description: document.getElementById('emb-desc').value.trim() || undefined,
      color: document.getElementById('emb-color').value.trim() || undefined,
      image: document.getElementById('emb-image').value.trim() || undefined,
      thumbnail: document.getElementById('emb-thumb').value.trim() || undefined,
      footer: document.getElementById('emb-footer').value.trim() || undefined
    };
    const result = document.getElementById('msg-result');
    if (!channelId) { result.innerHTML = '<span class="error">❌ Seleziona un canale</span>'; return; }
    if (!content && !embed.title && !embed.description) {
      result.innerHTML = '<span class="error">❌ Testo o embed obbligatorio</span>'; return;
    }
    const btn = document.querySelector('button[onclick="sendMessage()"]');
    btn.disabled = true; btn.textContent = '⏳ Invio...';
    const res = await apiFetch('/api/messages/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelId, content, embed })
    });
    const data = await res.json();
    btn.disabled = false; btn.textContent = '📤 Invia';
    if (res.ok) {
      result.innerHTML = '<span class="success">✅ Inviato! ID: ' + esc(data.messageId) + '</span>';
      document.getElementById('msg-content').value = '';
    } else {
      result.innerHTML = '<span class="error">❌ ' + esc(data.error || 'Errore') + '</span>';
    }
  }
  loadChannels();
  </script>`;
}

// ---------- GESTIONE UTENTI ----------
function renderUserActionsContent(userId = '') {
  return `
  <div class="section">
    <h2>🛠️ Gestione Utenti</h2>
    <div class="form-row">
      <input id="ua-userid" placeholder="ID utente (17-20 cifre)" value="${escapeHtml(userId)}" maxlength="20">
      <button onclick="lookupUser()">🔍 Cerca</button>
    </div>
    <div id="ua-userinfo"></div>
  </div>

  <div class="section" id="ua-actions" style="display:none;">
    <h2>⚡ Azioni</h2>
    <label style="font-size:13px;color:#888;">Server</label>
    <select id="ua-guild"></select>
    <label style="font-size:13px;color:#888;">Motivo (opzionale)</label>
    <input id="ua-reason" placeholder="Motivo dell'azione" maxlength="512">
    <div style="display:flex;gap:8px;margin-top:8px;">
      <button class="secondary" onclick="doAction('kick')">👢 Kick</button>
      <button class="danger" onclick="doAction('ban')">🔨 Ban</button>
      <button class="secondary" onclick="doAction('unban')">🔓 Unban</button>
    </div>
    <div id="ua-result"></div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let currentUser = null;

  async function lookupUser() {
    const userId = document.getElementById('ua-userid').value.trim();
    const info = document.getElementById('ua-userinfo');
    const actions = document.getElementById('ua-actions');
    if (!/^\\d{17,20}$/.test(userId)) { info.innerHTML = '<span class="error">❌ ID non valido</span>'; return; }
    info.innerHTML = '<p class="loading">Ricerca...</p>';
    const res = await apiFetch('/api/user-lookup/' + encodeURIComponent(userId));
    const data = await res.json();
    if (!res.ok) { info.innerHTML = '<span class="error">❌ ' + esc(data.error || 'Errore') + '</span>'; actions.style.display='none'; return; }
    currentUser = data;

    info.innerHTML =
      '<div style="display:flex;gap:14px;align-items:center;margin-top:12px;">' +
      '<img src="' + esc(data.avatar) + '" style="width:64px;height:64px;border-radius:50%;">' +
      '<div><b>' + esc(data.tag) + '</b><br><small style="color:#666;">' + esc(data.id) + (data.bot ? ' • BOT' : '') + '</small></div>' +
      '</div>' +
      '<p style="margin-top:12px;color:#888;font-size:13px;">Server in comune: ' + esc(data.memberships.length) + '</p>';

    const sel = document.getElementById('ua-guild');
    sel.innerHTML = data.memberships.map(m =>
      '<option value="' + esc(m.guildId) + '">' + esc(m.guildName) + ' (ruoli: ' + esc(m.roles.join(', ')) + ')</option>'
    ).join('') || '<option value="">Nessun server</option>';

    actions.style.display = 'block';
  }

  async function doAction(action) {
    if (!currentUser) return;
    const guildId = document.getElementById('ua-guild').value;
    const reason = document.getElementById('ua-reason').value.trim();
    const result = document.getElementById('ua-result');
    if (!guildId) { result.innerHTML = '<span class="error">❌ Seleziona un server</span>'; return; }
    if (!confirm('Confermi ' + action.toUpperCase() + ' di ' + currentUser.tag + '?')) return;
    const res = await apiFetch('/api/user-action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, userId: currentUser.id, guildId, reason })
    });
    const data = await res.json();
    result.innerHTML = res.ok
      ? '<span class="success">✅ ' + esc(action.toUpperCase()) + ' eseguito</span>'
      : '<span class="error">❌ ' + esc(data.error || 'Errore') + '</span>';
  }

  ${userId ? 'lookupUser();' : ''}
  </script>`;
}

module.exports = { createWebServer };
