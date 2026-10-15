// web.js — Dashboard con Tailwind, sidebar, dark/light, toast + tutte le funzionalità
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const axios = require('axios');
const path = require('path');
const fs = require('fs');

function createWebServer({ storage, client, log, botStartTime }) {
  const app = express();
  const PORT = parseInt(process.env.PORT) || 3000;
  const HOST = process.env.WEB_HOST || '0.0.0.0';

  app.set('trust proxy', 1);

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

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const SESSION_DIR = path.join(__dirname, 'data', 'sessions');
  try { if (!fs.existsSync(SESSION_DIR)) fs.mkdirSync(SESSION_DIR, { recursive: true }); } catch {}

  app.use(session({
    store: new FileStore({ path: SESSION_DIR, ttl: 7*24*60*60, retries: 0, logFn: () => {} }),
    secret: SESSION_SECRET,
    resave: false, saveUninitialized: false, proxy: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true, sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));

  function requireAuth(req, res, next) {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Non autenticato' });
      return res.redirect('/auth/login');
    }
    if (!req.session.user.dashboardAuthorized) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Non autorizzato' });
      return res.status(403).send('Accesso negato.');
    }
    next();
  }

  // ==================== PUBBLICI ====================
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      uptime: Math.floor((Date.now() - botStartTime) / 1000),
      guilds: client.guilds.cache.size,
      ping: client.ws.ping,
      timestamp: new Date().toISOString()
    });
  });

  app.get('/', (req, res) => {
    res.json({ message: 'Bot Dashboard', version: '6.0.0', loggedIn: !!req.session.user });
  });

  // ==================== OAUTH2 ====================
  app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID || !CLIENT_SECRET) return res.status(500).send('OAuth2 non configurato.');
    const params = new URLSearchParams({
      client_id: CLIENT_ID, redirect_uri: `${DASHBOARD_URL}/auth/callback`,
      response_type: 'code', scope: 'identify'
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });

  app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Codice mancante');
    try {
      const tokenRes = await axios.post('https://discord.com/api/oauth2/token',
        new URLSearchParams({
          client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
          grant_type: 'authorization_code', code,
          redirect_uri: `${DASHBOARD_URL}/auth/callback`
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const userRes = await axios.get('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
      });
      const user = userRes.data;

      if (!(await isAuthorizedByRole(user.id))) {
        return res.status(403).send('Accesso negato: devi avere il ruolo "Senior Admin".');
      }
      log.ok(`OAuth login: ${user.username} (${user.id})`);

      try {
        const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'sconosciuto';
        const ua = (req.headers['user-agent'] || '').slice(0, 300);
        storage.saveDashboardAccess(user.id, user.username, ip, ua);
      } catch (e) { log.err('saveDashboardAccess', e); }

      req.session.user = {
        id: user.id, username: user.username,
        global_name: user.global_name || user.username,
        avatar: user.avatar, dashboardAuthorized: true
      };
      req.session.save(() => res.redirect('/dashboard'));
    } catch (err) {
      log.err('OAuth', err.response?.data || err.message);
      res.status(500).send('Errore login');
    }
  });

  app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
  app.get('/auth/me', (req, res) => res.json({ user: req.session.user || null }));

  // ==================== API ====================
  app.get('/api/stats', requireAuth, (req, res) => {
    const s = storage.getStats();
    res.json({
      logs: s.total, blacklist: s.blacklist,
      guilds: client.guilds.cache.size, ping: client.ws.ping,
      uptime: Math.floor((Date.now() - botStartTime) / 1000), byType: s.byType
    });
  });

  app.get('/api/blacklist', requireAuth, (req, res) => res.json(storage.getAllBlacklist()));
  app.post('/api/blacklist', requireAuth, (req, res) => {
    const { userId, username, reason } = req.body || {};
    if (!userId || !username || !reason) return res.status(400).json({ error: 'Campi mancanti' });
    if (storage.isBlacklisted(userId)) return res.status(409).json({ error: 'Già in blacklist' });
    storage.addToBlacklist(userId, username, reason, req.session.user.id, req.session.user.username);
    res.json({ ok: true });
  });
  app.delete('/api/blacklist/:userId', requireAuth, (req, res) => {
    res.json({ ok: storage.removeFromBlacklist(req.params.userId) });
  });
  app.post('/api/blacklist/bulk-delete', requireAuth, (req, res) => {
    const { ids } = req.body || {};
    if (!Array.isArray(ids)) return res.status(400).json({ error: 'Nessun ID' });
    let count = 0;
    for (const id of ids) if (storage.removeFromBlacklist(id)) count++;
    res.json({ ok: true, count });
  });

  app.get('/api/logs/all', requireAuth, (req, res) => {
    try { res.json(storage.getAllLogs(500)); } catch { res.json([]); }
  });
  app.get('/api/logs/:userId', requireAuth, (req, res) => {
    res.json(storage.getLogsForUser(req.params.userId));
  });

  app.get('/api/notes/all', requireAuth, (req, res) => {
    try { res.json(storage.getAllNotes()); } catch { res.json([]); }
  });
  app.delete('/api/notes/:id', requireAuth, (req, res) => {
    res.json({ ok: storage.deleteNoteById(parseInt(req.params.id)) });
  });
  app.post('/api/notes/bulk-delete', requireAuth, (req, res) => {
    const { ids } = req.body || {};
    if (!Array.isArray(ids)) return res.status(400).json({ error: 'Nessun ID' });
    let count = 0;
    for (const id of ids) if (storage.deleteNoteById(parseInt(id))) count++;
    res.json({ ok: true, count });
  });

  app.get('/api/config/:guildId', requireAuth, (req, res) => {
    res.json(storage.getGuildConfig(req.params.guildId));
  });
  app.post('/api/config/:guildId', requireAuth, (req, res) => {
    const { autoroleId, logChannelId } = req.body || {};
    const g = req.params.guildId;
    try {
      if (autoroleId !== undefined) {
        if (autoroleId) storage.setAutorole(g, autoroleId);
        else storage.clearAutorole(g);
      }
      if (logChannelId !== undefined) {
        if (logChannelId) storage.setLogChannel(g, logChannelId);
        else storage.clearLogChannel(g);
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/welcome/:guildId', requireAuth, (req, res) => {
    res.json(storage.getWelcomeConfig(req.params.guildId) || {});
  });
  app.post('/api/welcome/:guildId', requireAuth, (req, res) => {
    const { channelId, message, embedEnabled } = req.body || {};
    const g = req.params.guildId;
    try {
      if (channelId !== undefined) {
        if (channelId) storage.setWelcomeChannel(g, channelId);
        else storage.disableWelcome(g);
      }
      if (message !== undefined && message !== null) storage.setWelcomeMessage(g, message);
      if (embedEnabled !== undefined) {
        const c = storage.getWelcomeConfig(g);
        storage.setWelcomeConfig(g, {
          channelId: c?.channel_id ?? null,
          message: c?.message ?? null,
          embedEnabled
        });
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/tickets', requireAuth, (req, res) => {
    const tickets = [];
    for (const guild of client.guilds.cache.values()) {
      for (const ch of guild.channels.cache.values()) {
        if (ch.name && ch.name.startsWith('ticket-')) {
          tickets.push({
            guild: guild.name, guildId: guild.id,
            channel: ch.name, channelId: ch.id,
            userId: ch.name.replace('ticket-', '')
          });
        }
      }
    }
    res.json(tickets);
  });
  app.delete('/api/tickets/:channelId', requireAuth, async (req, res) => {
    try {
      const ch = await client.channels.fetch(req.params.channelId).catch(() => null);
      if (!ch) return res.status(404).json({ error: 'Canale non trovato' });
      await ch.delete('Chiuso dalla dashboard web');
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/commands', requireAuth, (req, res) => {
    const cmds = storage.loadCommands();
    res.json(Object.entries(cmds).map(([name, response]) => ({ name, response })));
  });
  app.post('/api/commands', requireAuth, (req, res) => {
    const { name, response } = req.body || {};
    if (!name || !response) return res.status(400).json({ error: 'Campi mancanti' });
    storage.saveCommand(name.toLowerCase(), response);
    res.json({ ok: true });
  });
  app.delete('/api/commands/:name', requireAuth, (req, res) => {
    res.json({ ok: storage.deleteCommand(req.params.name.toLowerCase()) });
  });
  app.post('/api/commands/bulk-delete', requireAuth, (req, res) => {
    const { names } = req.body || {};
    if (!Array.isArray(names)) return res.status(400).json({ error: 'Nessun nome' });
    let count = 0;
    for (const n of names) if (storage.deleteCommand(n)) count++;
    res.json({ ok: true, count });
  });

  app.get('/api/charts', requireAuth, (req, res) => {
    try {
      const byType = storage.db.prepare('SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type').all();
      const byDay = storage.db.prepare("SELECT substr(timestamp,1,10) as day, COUNT(*) as c FROM mod_logs GROUP BY day ORDER BY day DESC LIMIT 30").all();
      res.json({ byType, byDay });
    } catch { res.json({ byType: [], byDay: [] }); }
  });

  app.get('/api/top', requireAuth, (req, res) => {
    try {
      const moderators = storage.db.prepare(`SELECT moderator, COUNT(*) as c FROM mod_logs WHERE moderator IS NOT NULL AND moderator != 'Sistema Automatico' GROUP BY moderator ORDER BY c DESC LIMIT 10`).all();
      const targets = storage.db.prepare(`SELECT target_id, target, COUNT(*) as c FROM mod_logs WHERE target_id IS NOT NULL GROUP BY target_id ORDER BY c DESC LIMIT 10`).all();
      const types = storage.db.prepare(`SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type ORDER BY c DESC`).all();
      const byMonth = storage.db.prepare(`SELECT substr(timestamp,1,7) as month, COUNT(*) as c FROM mod_logs GROUP BY month ORDER BY month DESC LIMIT 12`).all();
      res.json({ moderators, targets, types, byMonth });
    } catch (e) { log.err('api/top', e); res.json({ moderators: [], targets: [], types: [], byMonth: [] }); }
  });

  app.get('/api/guilds', requireAuth, (req, res) => {
    const guilds = client.guilds.cache.map(g => ({
      id: g.id, name: g.name,
      roles: g.roles.cache.filter(r => r.name !== '@everyone').map(r => ({ id: r.id, name: r.name })),
      channels: g.channels.cache.filter(c => c.type === 0).map(c => ({ id: c.id, name: c.name }))
    }));
    res.json(guilds);
  });

  app.get('/api/user/:userId', requireAuth, (req, res) => {
    const userId = req.params.userId;
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
      res.json({
        userId, logs, notes, blacklist: blacklistEntry, tickets,
        byType: Object.entries(byTypeMap).map(([type, c]) => ({ type, c }))
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/search', requireAuth, (req, res) => {
    const q = (req.query.q || '').toString().trim().toLowerCase();
    if (!q) return res.json({ blacklist: [], notes: [], logs: [], tickets: [] });
    try {
      const blacklist = storage.getAllBlacklist().filter(e =>
        (e.user_id || '').toLowerCase().includes(q) ||
        (e.username || '').toLowerCase().includes(q) ||
        (e.reason || '').toLowerCase().includes(q)
      );
      const notes = storage.getAllNotes().filter(n =>
        (n.user_id || '').toLowerCase().includes(q) ||
        (n.content || '').toLowerCase().includes(q) ||
        (n.author_tag || '').toLowerCase().includes(q)
      );
      const logs = storage.getAllLogs(500).filter(l =>
        (l.target_id || '').toLowerCase().includes(q) ||
        (l.target || '').toLowerCase().includes(q) ||
        (l.moderator || '').toLowerCase().includes(q) ||
        (l.reason || '').toLowerCase().includes(q)
      );
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-') && ch.name.toLowerCase().includes(q)) {
            tickets.push({ guild: guild.name, channel: ch.name, channelId: ch.id, userId: ch.name.replace('ticket-', '') });
          }
        }
      }
      res.json({ blacklist, notes, logs, tickets });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  function toCsv(rows, headers) {
    if (!rows.length) return headers.join(',');
    const esc = (v) => {
      const s = (v === null || v === undefined) ? '' : String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return headers.join(',') + '\n' + rows.map(r => headers.map(h => esc(r[h])).join(',')).join('\n');
  }

  app.get('/api/export/blacklist.csv', requireAuth, (req, res) => {
    const csv = toCsv(storage.getAllBlacklist(), ['user_id', 'username', 'reason', 'moderator_tag', 'added_at']);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="blacklist.csv"');
    res.send(csv);
  });
  app.get('/api/export/notes.csv', requireAuth, (req, res) => {
    const csv = toCsv(storage.getAllNotes(), ['id', 'guild_id', 'user_id', 'author_tag', 'content', 'created_at']);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="notes.csv"');
    res.send(csv);
  });
  app.get('/api/export/logs.csv', requireAuth, (req, res) => {
    const csv = toCsv(storage.getAllLogs(5000), ['id', 'type', 'target_id', 'target', 'moderator', 'reason', 'duration', 'channel', 'timestamp']);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="modlogs.csv"');
    res.send(csv);
  });
  app.get('/api/export/access-logs.csv', requireAuth, (req, res) => {
    const csv = toCsv(storage.getDashboardAccessLogs(), ['id', 'user_id', 'username', 'ip', 'user_agent', 'timestamp']);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="access-logs.csv"');
    res.send(csv);
  });

  app.get('/api/access-logs', requireAuth, (req, res) => {
    try { res.json(storage.getDashboardAccessLogs()); } catch { res.json([]); }
  });

  // ==================== PAGINE HTML ====================
  const pages = ['dashboard', 'modlogs', 'notes', 'tickets', 'commands', 'config', 'charts', 'top', 'access-logs'];
  pages.forEach(p => {
    app.get('/' + p, requireAuth, (req, res) => res.send(renderLayout(req.session.user, p.replace('-', ''), {})));
  });
  app.get('/user/:userId', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'user', { userId: req.params.userId })));
  app.get('/search', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'search', { q: (req.query.q || '').toString() })));

  // ==================== AVVIO ====================
  const server = app.listen(PORT, HOST, () => {
    log.ok(`🌐 Dashboard web su http://${HOST}:${PORT}`);
    log.info(`   Login URL: ${DASHBOARD_URL}/auth/login`);
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
// ================= LAYOUT CON TAILWIND + SIDEBAR ============
// ============================================================
function renderLayout(user, page, params = {}) {
  const name = user.global_name || user.username;
  const avatar = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`
    : `https://cdn.discordapp.com/embed/avatars/0.png`;

  const nav = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊', href: '/dashboard' },
    { id: 'modlogs', label: 'Mod Logs', icon: '📋', href: '/modlogs' },
    { id: 'notes', label: 'Note', icon: '📝', href: '/notes' },
    { id: 'tickets', label: 'Ticket', icon: '🎫', href: '/tickets' },
    { id: 'commands', label: 'Comandi', icon: '🔧', href: '/commands' },
    { id: 'config', label: 'Config', icon: '⚙️', href: '/config' },
    { id: 'charts', label: 'Grafici', icon: '📈', href: '/charts' },
    { id: 'top', label: 'Top 10', icon: '🏆', href: '/top' },
    { id: 'accesslogs', label: 'Accessi', icon: '🔐', href: '/access-logs' },
  ];

  const pageContents = {
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
    accesslogs: renderAccessLogsContent()
  };

  const navHtml = nav.map(item => `
    <a href="${item.href}" class="sidebar-link ${page === item.id ? 'active' : ''}">
      <span class="text-lg">${item.icon}</span>
      <span>${item.label}</span>
    </a>
  `).join('');

  return `<!DOCTYPE html>
<html lang="it" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard - ${page}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    darkMode: 'class',
    theme: { extend: { colors: {
      discord: { DEFAULT: '#5865F2', dark: '#4752c4' }
    } } }
  }
</script>
<style>
  html { font-family: -apple-system, "Segoe UI", system-ui, sans-serif; }
  body { transition: background-color 0.2s, color 0.2s; }
  html[data-theme="dark"] body { background: #1a1a1a; color: #eee; }
  html[data-theme="dark"] .card-bg { background: #252525; border-color: #333; }
  html[data-theme="light"] body { background: #f3f4f6; color: #111827; }
  html[data-theme="light"] .card-bg { background: #ffffff; border-color: #e5e7eb; }
  .sidebar-link {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px; border-radius: 8px;
    color: #9ca3af; font-size: 14px; font-weight: 500;
    transition: all 0.15s;
  }
  html[data-theme="light"] .sidebar-link { color: #6b7280; }
  .sidebar-link:hover { background: rgba(88,101,242,0.1); color: #5865F2; }
  .sidebar-link.active { background: #5865F2; color: #fff; }
  html[data-theme="light"] .sidebar-link.active { color: #fff; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.kick, .badge.warn { background: #faa61a; color: #000; }
  .badge.ban { background: #ed4245; color: #fff; }
  .badge.timeout { background: #5865F2; color: #fff; }
  .badge.default { background: #444; color: #eee; }
  .toast {
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    padding: 14px 20px; border-radius: 10px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    font-size: 14px; font-weight: 500;
    animation: slideIn 0.3s ease-out;
    max-width: 380px;
  }
  @keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  .toast.success { background: #10b981; color: #fff; }
  .toast.error { background: #ef4444; color: #fff; }
  .toast.info { background: #3b82f6; color: #fff; }
  code { background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  html[data-theme="light"] code { background: rgba(0,0,0,0.06); }
  .user-link { color: #5865F2; text-decoration: none; border-bottom: 1px dashed #5865F2; }
  .user-link:hover { border-bottom-style: solid; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid rgba(128,128,128,0.2); font-size: 14px; }
  th { font-size: 11px; text-transform: uppercase; opacity: 0.6; }
  input, select, textarea {
    background: rgba(0,0,0,0.2); border: 1px solid rgba(128,128,128,0.3);
    color: inherit; padding: 8px 12px; border-radius: 6px; font-size: 14px;
    width: 100%; font-family: inherit;
  }
  html[data-theme="light"] input, html[data-theme="light"] select, html[data-theme="light"] textarea { background: #fff; }
  .btn { background: #5865F2; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; transition: background 0.15s; }
  .btn:hover { background: #4752c4; }
  .btn.danger { background: #ed4245; }
  .btn.danger:hover { background: #c93b3e; }
  .btn.small { padding: 5px 10px; font-size: 12px; }
</style>
</head>
<body class="min-h-screen">

<div class="flex">
  <!-- Sidebar -->
  <aside id="sidebar" class="fixed lg:sticky top-0 left-0 h-screen w-64 card-bg border-r p-4 transition-transform -translate-x-full lg:translate-x-0 z-40">
    <div class="flex items-center justify-between mb-6 px-2">
      <h1 class="text-lg font-bold">🤖 Dashboard</h1>
      <button onclick="toggleTheme()" id="theme-btn" class="text-2xl" title="Cambia tema">🌙</button>
    </div>
    <nav class="space-y-1">${navHtml}</nav>
    <div class="absolute bottom-4 left-4 right-4">
      <div class="flex items-center gap-3 p-3 rounded-lg card-bg border">
        <img src="${avatar}" class="w-9 h-9 rounded-full" alt="">
        <div class="flex-1 min-w-0">
          <div class="text-sm font-medium truncate">${name}</div>
          <a href="/auth/logout" class="text-xs text-red-400 hover:underline">Logout</a>
        </div>
      </div>
    </div>
  </aside>

  <!-- Main -->
  <main class="flex-1 min-w-0 p-6">
    <div class="flex items-center gap-4 mb-6 lg:hidden">
      <button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full')" class="text-2xl">☰</button>
      <h1 class="text-lg font-bold">🤖 Dashboard</h1>
    </div>
    <form action="/search" method="get" class="mb-6">
      <input type="text" name="q" placeholder="🔍 Cerca utente, motivo, moderatore..." value="${params.q || ''}" class="max-w-xl">
    </form>
    ${pageContents[page] || '<p>Pagina non trovata</p>'}
  </main>
</div>

<script>
// Theme management
(function() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeBtn(saved);
})();

function toggleTheme() {
  const curr = document.documentElement.getAttribute('data-theme');
  const next = curr === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeBtn(next);
}

function updateThemeBtn(theme) {
  const btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = theme === 'dark' ? '☀️' : '🌙';
}

// Toast system
function showToast(msg, type = 'info', duration = 3000) {
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, duration);
}

// Sostituisci alert globali con toast per un'esperienza migliore
window._origAlert = window.alert;
window.alert = (msg) => {
  const isSuccess = typeof msg === 'string' && (msg.includes('✅') || msg.toLowerCase().includes('ok'));
  const isError = typeof msg === 'string' && (msg.includes('❌') || msg.toLowerCase().includes('err'));
  showToast(msg, isSuccess ? 'success' : isError ? 'error' : 'info');
};
</script>
</body>
</html>`;
}

// ============================================================
// ================= CONTENUTI PAGINE =========================
// ============================================================

function renderDashboardContent() {
  return `
  <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Log Totali</div><div class="text-3xl font-bold text-discord" id="stat-logs">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Blacklist</div><div class="text-3xl font-bold text-discord" id="stat-bl">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Server</div><div class="text-3xl font-bold text-discord" id="stat-guilds">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Ping</div><div class="text-3xl font-bold text-discord" id="stat-ping">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Uptime</div><div class="text-3xl font-bold text-discord" id="stat-uptime">...</div></div>
  </div>

  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">➕ Aggiungi alla Blacklist</h2>
    <div class="flex flex-wrap gap-3">
      <input type="text" id="bl-userId" placeholder="ID utente" class="flex-1 min-w-[200px]">
      <input type="text" id="bl-username" placeholder="Username" class="flex-1 min-w-[150px]">
      <input type="text" id="bl-reason" placeholder="Motivo" class="flex-1 min-w-[200px]">
      <button onclick="addBL()" class="btn">Aggiungi</button>
    </div>
  </div>

  <div class="card-bg border rounded-xl p-5">
    <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
      <h2 class="text-lg font-semibold">🚫 Blacklist Globale</h2>
      <div class="flex gap-2">
        <a href="/api/export/blacklist.csv" class="text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white">📥 CSV</a>
        <button onclick="bulkDeleteBL()" class="text-xs px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white">🗑️ Elimina selezionati</button>
      </div>
    </div>
    <div id="blacklist-content" class="opacity-60 italic">Caricamento...</div>
  </div>

  <script>
  async function loadStats() {
    const res = await fetch('/api/stats'); if (!res.ok) return;
    const s = await res.json();
    document.getElementById('stat-logs').textContent = s.logs;
    document.getElementById('stat-bl').textContent = s.blacklist;
    document.getElementById('stat-guilds').textContent = s.guilds;
    document.getElementById('stat-ping').textContent = s.ping + 'ms';
    const h = Math.floor(s.uptime/3600), m = Math.floor((s.uptime%3600)/60);
    document.getElementById('stat-uptime').textContent = h + 'h ' + m + 'm';
  }
  async function loadBlacklist() {
    const res = await fetch('/api/blacklist');
    const list = await res.json();
    const el = document.getElementById('blacklist-content');
    if (!list.length) { el.innerHTML = '<p class="opacity-60 italic">Nessun utente in blacklist.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="bl-select-all" onclick="toggleAllBL()"></th><th>Utente</th><th>Motivo</th><th>Aggiunto da</th><th></th></tr></thead><tbody>' +
      list.map(e => '<tr><td><input type="checkbox" class="bl-check" value="' + e.user_id + '"></td><td><a class="user-link" href="/user/' + e.user_id + '">' + e.username + '</a><br><small class="opacity-60">' + e.user_id + '</small></td><td>' + e.reason + '</td><td>' + e.moderator_tag + '</td><td><button class="btn danger small" onclick="removeBL(\\'' + e.user_id + '\\')">Rimuovi</button></td></tr>').join('') +
      '</tbody></table>';
  }
  function toggleAllBL() {
    const c = document.getElementById('bl-select-all').checked;
    document.querySelectorAll('.bl-check').forEach(x => x.checked = c);
  }
  async function bulkDeleteBL() {
    const ids = Array.from(document.querySelectorAll('.bl-check:checked')).map(c => c.value);
    if (!ids.length) return showToast('Nessun utente selezionato', 'error');
    if (!confirm('Rimuovere ' + ids.length + ' utenti?')) return;
    const res = await fetch('/api/blacklist/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
    const d = await res.json();
    if (res.ok) { showToast('Rimossi ' + d.count + ' utenti', 'success'); loadBlacklist(); loadStats(); }
    else showToast(d.error || 'Errore', 'error');
  }
  async function addBL() {
    const userId = document.getElementById('bl-userId').value.trim();
    const username = document.getElementById('bl-username').value.trim();
    const reason = document.getElementById('bl-reason').value.trim();
    if (!userId || !username || !reason) return showToast('Compila tutti i campi', 'error');
    const res = await fetch('/api/blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId, username, reason }) });
    if (res.ok) {
      showToast('Aggiunto alla blacklist', 'success');
      document.getElementById('bl-userId').value = '';
      document.getElementById('bl-username').value = '';
      document.getElementById('bl-reason').value = '';
      loadBlacklist(); loadStats();
    } else { const d = await res.json(); showToast(d.error || 'Errore', 'error'); }
  }
  async function removeBL(userId) {
    if (!confirm('Rimuovere ' + userId + '?')) return;
    await fetch('/api/blacklist/' + userId, { method: 'DELETE' });
    showToast('Rimosso', 'success');
    loadBlacklist(); loadStats();
  }
  loadStats(); loadBlacklist();
  setInterval(loadStats, 10000);
  </script>`;
}

function renderModlogsContent() {
  return `
  <div class="card-bg border rounded-xl p-5">
    <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
      <h2 class="text-lg font-semibold">📋 Mod Logs</h2>
      <a href="/api/export/logs.csv" class="text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white">📥 CSV</a>
    </div>
    <div class="flex gap-3 mb-4 flex-wrap">
      <select id="filter-type" onchange="loadLogs()" class="max-w-[220px]">
        <option value="">Tutti i tipi</option>
        <option>Kick</option><option>Ban</option><option>Warn</option>
        <option>Timeout</option><option>Clear</option><option>Purge</option>
        <option>Lock</option><option>Unlock</option>
      </select>
      <input type="text" id="filter-user" placeholder="Filtra per ID utente" oninput="loadLogs()" class="max-w-[300px]">
    </div>
    <div id="logs-content" class="opacity-60 italic">Caricamento...</div>
  </div>

  <script>
  let allLogs = [];
  async function loadLogs() {
    if (!allLogs.length) { const res = await fetch('/api/logs/all'); allLogs = await res.json(); }
    const type = document.getElementById('filter-type').value;
    const uid = document.getElementById('filter-user').value.trim();
    let logs = allLogs;
    if (type) logs = logs.filter(l => l.type === type);
    if (uid) logs = logs.filter(l => (l.target_id || '').includes(uid));
    const el = document.getElementById('logs-content');
    if (!logs.length) { el.innerHTML = '<p class="opacity-60 italic">Nessun log trovato.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      logs.map(l => '<tr>' +
        '<td>' + new Date(l.timestamp).toLocaleString('it-IT') + '</td>' +
        '<td><span class="badge ' + (l.type || 'default').toLowerCase() + '">' + (l.type || '-') + '</span></td>' +
        '<td>' + (l.target_id ? '<a class="user-link" href="/user/' + l.target_id + '">' + (l.target || l.target_id) + '</a>' : (l.target || '-')) + '</td>' +
        '<td>' + (l.moderator || '-') + '</td><td>' + (l.reason || '-') + '</td><td>' + (l.duration || '-') + '</td>' +
      '</tr>').join('') + '</tbody></table>';
  }
  loadLogs();
  </script>`;
}

function renderNotesContent() {
  return `
  <div class="card-bg border rounded-xl p-5">
    <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
      <h2 class="text-lg font-semibold">📝 Note Staff</h2>
      <div class="flex gap-2">
        <a href="/api/export/notes.csv" class="text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white">📥 CSV</a>
        <button onclick="bulkDeleteNotes()" class="text-xs px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white">🗑️ Elimina selezionate</button>
      </div>
    </div>
    <div id="notes-content" class="opacity-60 italic">Caricamento...</div>
  </div>

  <script>
  async function loadNotes() {
    const res = await fetch('/api/notes/all');
    const notes = await res.json();
    const el = document.getElementById('notes-content');
    if (!notes.length) { el.innerHTML = '<p class="opacity-60 italic">Nessuna nota.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="note-select-all" onclick="toggleAllNotes()"></th><th>#</th><th>Utente</th><th>Autore</th><th>Contenuto</th><th>Data</th><th></th></tr></thead><tbody>' +
      notes.map(n => '<tr><td><input type="checkbox" class="note-check" value="' + n.id + '"></td><td>' + n.id + '</td><td><a class="user-link" href="/user/' + n.user_id + '">' + n.user_id + '</a></td><td>' + n.author_tag + '</td><td>' + n.content + '</td><td>' + new Date(n.created_at).toLocaleString('it-IT') + '</td><td><button class="btn danger small" onclick="deleteNote(' + n.id + ')">Elimina</button></td></tr>').join('') + '</tbody></table>';
  }
  function toggleAllNotes() {
    const c = document.getElementById('note-select-all').checked;
    document.querySelectorAll('.note-check').forEach(x => x.checked = c);
  }
  async function bulkDeleteNotes() {
    const ids = Array.from(document.querySelectorAll('.note-check:checked')).map(c => c.value);
    if (!ids.length) return showToast('Nessuna nota selezionata', 'error');
    if (!confirm('Eliminare ' + ids.length + ' note?')) return;
    const res = await fetch('/api/notes/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
    const d = await res.json();
    if (res.ok) { showToast('Eliminate ' + d.count + ' note', 'success'); loadNotes(); }
    else showToast(d.error || 'Errore', 'error');
  }
  async function deleteNote(id) {
    if (!confirm('Eliminare la nota #' + id + '?')) return;
    await fetch('/api/notes/' + id, { method: 'DELETE' });
    showToast('Nota eliminata', 'success'); loadNotes();
  }
  loadNotes();
  </script>`;
}

function renderTicketsContent() {
  return `
  <div class="card-bg border rounded-xl p-5">
    <h2 class="text-lg font-semibold mb-4">🎫 Ticket Aperti</h2>
    <p class="text-sm opacity-60 mb-4">Il pulsante Chiudi cancella il canale del ticket su Discord.</p>
    <div id="tickets-content" class="opacity-60 italic">Caricamento...</div>
  </div>

  <script>
  async function loadTickets() {
    const res = await fetch('/api/tickets');
    const tickets = await res.json();
    const el = document.getElementById('tickets-content');
    if (!tickets.length) { el.innerHTML = '<p class="opacity-60 italic">Nessun ticket aperto.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th>Utente</th><th></th></tr></thead><tbody>' +
      tickets.map(t => '<tr><td>' + t.guild + '</td><td>#' + t.channel + '</td><td><a class="user-link" href="/user/' + t.userId + '">' + t.userId + '</a></td><td><button class="btn danger small" onclick="closeTicket(\\'' + t.channelId + '\\')">Chiudi</button></td></tr>').join('') + '</tbody></table>';
  }
  async function closeTicket(id) {
    if (!confirm('Chiudere ed eliminare questo ticket?')) return;
    const res = await fetch('/api/tickets/' + id, { method: 'DELETE' });
    if (res.ok) { showToast('Ticket chiuso', 'success'); loadTickets(); }
    else { const d = await res.json(); showToast(d.error || 'Errore', 'error'); }
  }
  loadTickets();
  setInterval(loadTickets, 15000);
  </script>`;
}

function renderCommandsContent() {
  return `
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">➕ Aggiungi Comando Custom</h2>
    <div class="flex flex-wrap gap-3">
      <input type="text" id="cmd-name" placeholder="Nome" class="flex-1 min-w-[200px]">
      <input type="text" id="cmd-response" placeholder="Risposta" class="flex-1 min-w-[300px]">
      <button onclick="addCmd()" class="btn">Aggiungi</button>
    </div>
  </div>

  <div class="card-bg border rounded-xl p-5">
    <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
      <h2 class="text-lg font-semibold">🔧 Comandi Custom</h2>
      <button onclick="bulkDeleteCmds()" class="text-xs px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white">🗑️ Elimina selezionati</button>
    </div>
    <div id="commands-content" class="opacity-60 italic">Caricamento...</div>
  </div>

  <script>
  async function loadCmds() {
    const res = await fetch('/api/commands');
    const cmds = await res.json();
    const el = document.getElementById('commands-content');
    if (!cmds.length) { el.innerHTML = '<p class="opacity-60 italic">Nessun comando custom.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th style="width:30px;"><input type="checkbox" id="cmd-select-all" onclick="toggleAllCmds()"></th><th>Comando</th><th>Risposta</th><th></th></tr></thead><tbody>' +
      cmds.map(c => '<tr><td><input type="checkbox" class="cmd-check" value="' + c.name + '"></td><td><code>-' + c.name + '</code></td><td>' + c.response + '</td><td><button class="btn danger small" onclick="removeCmd(\\'' + c.name + '\\')">Elimina</button></td></tr>').join('') + '</tbody></table>';
  }
  function toggleAllCmds() {
    const c = document.getElementById('cmd-select-all').checked;
    document.querySelectorAll('.cmd-check').forEach(x => x.checked = c);
  }
  async function bulkDeleteCmds() {
    const names = Array.from(document.querySelectorAll('.cmd-check:checked')).map(c => c.value);
    if (!names.length) return showToast('Nessun comando selezionato', 'error');
    if (!confirm('Eliminare ' + names.length + ' comandi?')) return;
    const res = await fetch('/api/commands/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ names }) });
    const d = await res.json();
    if (res.ok) { showToast('Eliminati ' + d.count + ' comandi', 'success'); loadCmds(); }
    else showToast(d.error || 'Errore', 'error');
  }
  async function addCmd() {
    const name = document.getElementById('cmd-name').value.trim();
    const response = document.getElementById('cmd-response').value.trim();
    if (!name || !response) return showToast('Compila tutti i campi', 'error');
    const res = await fetch('/api/commands', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, response }) });
    if (res.ok) {
      showToast('Comando aggiunto', 'success');
      document.getElementById('cmd-name').value = '';
      document.getElementById('cmd-response').value = '';
      loadCmds();
    } else showToast('Errore', 'error');
  }
  async function removeCmd(name) {
    if (!confirm('Eliminare il comando -' + name + '?')) return;
    await fetch('/api/commands/' + name, { method: 'DELETE' });
    showToast('Comando eliminato', 'success'); loadCmds();
  }
  loadCmds();
  </script>`;
}

function renderConfigContent() {
  return `
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">⚙️ Configurazione Server</h2>
    <p class="text-sm opacity-60 mb-4">Seleziona un server per configurare autorole, canale log e welcome.</p>
    <select id="guild-select" onchange="loadGuildConfig()"></select>
  </div>
  <div id="config-content"></div>

  <script>
  let guildsData = [];
  async function loadGuilds() {
    const res = await fetch('/api/guilds');
    guildsData = await res.json();
    const sel = document.getElementById('guild-select');
    sel.innerHTML = guildsData.map(g => '<option value="' + g.id + '">' + g.name + '</option>').join('');
    if (guildsData.length) loadGuildConfig();
  }
  async function loadGuildConfig() {
    const guildId = document.getElementById('guild-select').value;
    const guild = guildsData.find(g => g.id === guildId);
    if (!guild) return;
    const [cr, wr] = await Promise.all([fetch('/api/config/' + guildId), fetch('/api/welcome/' + guildId)]);
    const config = await cr.json();
    const welcome = await wr.json();
    document.getElementById('config-content').innerHTML = \`
      <div class="card-bg border rounded-xl p-5 mb-4">
        <h3 class="text-base font-semibold mb-3">🎭 Autorole</h3>
        <select id="cfg-autorole"><option value="">— Nessuno —</option>
          \${guild.roles.map(r => '<option value="' + r.id + '" ' + (config.autorole_id === r.id ? 'selected' : '') + '>' + r.name + '</option>').join('')}
        </select>
        <button onclick="saveAutorole('\\\${guildId}')" class="btn mt-3">Salva</button>
      </div>
      <div class="card-bg border rounded-xl p-5 mb-4">
        <h3 class="text-base font-semibold mb-3">📋 Canale Log</h3>
        <select id="cfg-logchannel"><option value="">— Nessuno —</option>
          \${guild.channels.map(c => '<option value="' + c.id + '" ' + (config.log_channel_id === c.id ? 'selected' : '') + '>#' + c.name + '</option>').join('')}
        </select>
        <button onclick="saveLogChannel('\\\${guildId}')" class="btn mt-3">Salva</button>
      </div>
      <div class="card-bg border rounded-xl p-5">
        <h3 class="text-base font-semibold mb-3">👋 Welcome</h3>
        <label class="text-sm opacity-60">Canale</label>
        <select id="cfg-welcomechannel"><option value="">— Disattivato —</option>
          \${guild.channels.map(c => '<option value="' + c.id + '" ' + (welcome.channel_id === c.id ? 'selected' : '') + '>#' + c.name + '</option>').join('')}
        </select>
        <label class="text-sm opacity-60 mt-3 block">Messaggio</label>
        <textarea id="cfg-welcomemessage" rows="3">\${welcome.message || ''}</textarea>
        <label class="flex items-center gap-2 mt-3 text-sm">
          <input type="checkbox" id="cfg-welcomeembed" style="width:auto;" \${welcome.embed_enabled ? 'checked' : ''}> Usa embed
        </label>
        <button onclick="saveWelcome('\\\${guildId}')" class="btn mt-3">Salva</button>
      </div>
    \`;
  }
  async function saveAutorole(g) {
    const v = document.getElementById('cfg-autorole').value || null;
    const r = await fetch('/api/config/' + g, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ autoroleId: v }) });
    showToast(r.ok ? 'Autorole salvato' : 'Errore', r.ok ? 'success' : 'error');
  }
  async function saveLogChannel(g) {
    const v = document.getElementById('cfg-logchannel').value || null;
    const r = await fetch('/api/config/' + g, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ logChannelId: v }) });
    showToast(r.ok ? 'Canale log salvato' : 'Errore', r.ok ? 'success' : 'error');
  }
  async function saveWelcome(g) {
    const channelId = document.getElementById('cfg-welcomechannel').value || null;
    const message = document.getElementById('cfg-welcomemessage').value;
    const embedEnabled = document.getElementById('cfg-welcomeembed').checked;
    const r = await fetch('/api/welcome/' + g, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId, message, embedEnabled }) });
    showToast(r.ok ? 'Welcome salvato' : 'Errore', r.ok ? 'success' : 'error');
  }
  loadGuilds();
  </script>`;
}

function renderChartsContent() {
  return `
  <div class="card-bg border rounded-xl p-5">
    <h2 class="text-lg font-semibold mb-4">📊 Statistiche Visuali</h2>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="rounded-xl p-4 border border-gray-700"><canvas id="chart-types"></canvas></div>
      <div class="rounded-xl p-4 border border-gray-700"><canvas id="chart-days"></canvas></div>
    </div>
  </div>
  <script>
  async function loadCharts() {
    const res = await fetch('/api/charts');
    const data = await res.json();
    const colors = ['#5865F2','#ed4245','#faa61a','#10b981','#9B59B6','#1ABC9C'];
    new Chart(document.getElementById('chart-types'), {
      type: 'doughnut',
      data: { labels: data.byType.map(t => t.type), datasets: [{ data: data.byType.map(t => t.c), backgroundColor: colors }] },
      options: { plugins: { legend: { labels: { color: getComputedStyle(document.body).color } } } }
    });
    new Chart(document.getElementById('chart-days'), {
      type: 'line',
      data: { labels: data.byDay.map(d => d.day).reverse(), datasets: [{ label: 'Azioni', data: data.byDay.map(d => d.c).reverse(), borderColor: '#5865F2', backgroundColor: 'rgba(88,101,242,0.2)', fill: true }] },
      options: { plugins: { legend: { labels: { color: getComputedStyle(document.body).color } } } }
    });
  }
  loadCharts();
  </script>`;
}

function renderTopContent() {
  return `
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">🏆 Top 10 Moderatori</h2>
    <div id="top-mod-content" class="opacity-60 italic">Caricamento...</div>
  </div>
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">🎯 Top 10 Utenti più Moderati</h2>
    <div id="top-user-content" class="opacity-60 italic">Caricamento...</div>
  </div>
  <div class="card-bg border rounded-xl p-5">
    <h2 class="text-lg font-semibold mb-4">📈 Azioni per Mese</h2>
    <div class="rounded-xl p-4 border border-gray-700"><canvas id="chart-month"></canvas></div>
  </div>
  <script>
  async function loadTop() {
    const res = await fetch('/api/top');
    const data = await res.json();
    const modEl = document.getElementById('top-mod-content');
    if (!data.moderators.length) modEl.innerHTML = '<p class="opacity-60 italic">Nessun dato.</p>';
    else modEl.innerHTML = '<table><thead><tr><th>#</th><th>Moderatore</th><th>Azioni</th></tr></thead><tbody>' +
      data.moderators.map((m, i) => '<tr><td>#' + (i+1) + '</td><td>' + (m.moderator || '-') + '</td><td class="font-bold text-discord">' + m.c + '</td></tr>').join('') + '</tbody></table>';
    const userEl = document.getElementById('top-user-content');
    if (!data.targets.length) userEl.innerHTML = '<p class="opacity-60 italic">Nessun dato.</p>';
    else userEl.innerHTML = '<table><thead><tr><th>#</th><th>Utente</th><th>Azioni</th></tr></thead><tbody>' +
      data.targets.map((t, i) => '<tr><td>#' + (i+1) + '</td><td>' + (t.target_id ? '<a class="user-link" href="/user/' + t.target_id + '">' + (t.target || t.target_id) + '</a>' : (t.target || '-')) + '</td><td class="font-bold text-discord">' + t.c + '</td></tr>').join('') + '</tbody></table>';
    if (data.byMonth.length) {
      new Chart(document.getElementById('chart-month'), {
        type: 'bar',
        data: { labels: data.byMonth.map(m => m.month).reverse(), datasets: [{ label: 'Azioni', data: data.byMonth.map(m => m.c).reverse(), backgroundColor: '#5865F2' }] },
        options: { plugins: { legend: { labels: { color: getComputedStyle(document.body).color } } } }
      });
    }
  }
  loadTop();
  </script>`;
}

function renderUserContent(userId) {
  return `
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold">👤 Utente <code>${userId}</code></h2>
  </div>
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Log</div><div class="text-3xl font-bold text-discord" id="u-logs">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Note</div><div class="text-3xl font-bold text-discord" id="u-notes">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Ticket</div><div class="text-3xl font-bold text-discord" id="u-tickets">...</div></div>
    <div class="card-bg border rounded-xl p-5"><div class="text-xs uppercase opacity-60 mb-2">Blacklist</div><div class="text-3xl font-bold" id="u-bl">...</div></div>
  </div>
  <div class="card-bg border rounded-xl p-5 mb-6" id="user-blacklist-section" style="display:none;">
    <h2 class="text-lg font-semibold mb-4">🚫 Stato Blacklist</h2>
    <div id="user-blacklist-content"></div>
  </div>
  <div class="card-bg border rounded-xl p-5 mb-6">
    <h2 class="text-lg font-semibold mb-4">📊 Azioni per Tipo</h2>
    <div class="rounded-xl p-4 border border-gray-700 max-w-md mx-auto"><canvas id="user-chart"></canvas></div>
  </div>
  <div class="card-bg border rounded-xl p-5 mb-6"><h2 class="text-lg font-semibold mb-4">📋 Mod Logs</h2><div id="user-logs-content" class="opacity-60 italic">Caricamento...</div></div>
  <div class="card-bg border rounded-xl p-5 mb-6"><h2 class="text-lg font-semibold mb-4">📝 Note</h2><div id="user-notes-content" class="opacity-60 italic">Caricamento...</div></div>
  <div class="card-bg border rounded-xl p-5"><h2 class="text-lg font-semibold mb-4">🎫 Ticket Aperti</h2><div id="user-tickets-content" class="opacity-60 italic">Caricamento...</div></div>

  <script>
  const USER_ID = '${userId}';
  let chartInstance = null;
  async function loadUser() {
    const res = await fetch('/api/user/' + USER_ID);
    if (!res.ok) return showToast('Errore caricamento utente', 'error');
    const data = await res.json();
    document.getElementById('u-logs').textContent = data.logs.length;
    document.getElementById('u-notes').textContent = data.notes.length;
    document.getElementById('u-tickets').textContent = data.tickets.length;
    const ubl = document.getElementById('u-bl');
    ubl.textContent = data.blacklist ? 'Sì' : 'No';
    ubl.style.color = data.blacklist ? '#ed4245' : '#10b981';
    if (data.blacklist) {
      document.getElementById('user-blacklist-section').style.display = 'block';
      const b = data.blacklist;
      document.getElementById('user-blacklist-content').innerHTML =
        '<table><thead><tr><th>Username</th><th>Motivo</th><th>Aggiunto da</th><th>Data</th><th></th></tr></thead><tbody>' +
        '<tr><td>' + b.username + '</td><td>' + b.reason + '</td><td>' + b.moderator_tag + '</td><td>' + new Date(b.added_at).toLocaleString('it-IT') + '</td><td><button class="btn danger small" onclick="removeBL()">Rimuovi</button></td></tr></tbody></table>';
    }
    if (data.byType.length) {
      const colors = ['#5865F2','#ed4245','#faa61a','#10b981','#9B59B6','#1ABC9C'];
      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById('user-chart'), {
        type: 'doughnut',
        data: { labels: data.byType.map(t => t.type), datasets: [{ data: data.byType.map(t => t.c), backgroundColor: colors }] },
        options: { plugins: { legend: { labels: { color: getComputedStyle(document.body).color } } } }
      });
    } else {
      document.getElementById('user-chart').parentElement.innerHTML = '<p class="opacity-60 italic">Nessuna azione.</p>';
    }
    const logsEl = document.getElementById('user-logs-content');
    if (!data.logs.length) logsEl.innerHTML = '<p class="opacity-60 italic">Nessun log.</p>';
    else logsEl.innerHTML = '<table><thead><tr><th>Data</th><th>Tipo</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      data.logs.map(l => '<tr><td>' + new Date(l.timestamp).toLocaleString('it-IT') + '</td><td><span class="badge ' + (l.type || 'default').toLowerCase() + '">' + (l.type || '-') + '</span></td><td>' + (l.moderator || '-') + '</td><td>' + (l.reason || '-') + '</td><td>' + (l.duration || '-') + '</td></tr>').join('') + '</tbody></table>';
    const notesEl = document.getElementById('user-notes-content');
    if (!data.notes.length) notesEl.innerHTML = '<p class="opacity-60 italic">Nessuna nota.</p>';
    else notesEl.innerHTML = '<table><thead><tr><th>#</th><th>Autore</th><th>Contenuto</th><th>Data</th><th></th></tr></thead><tbody>' +
      data.notes.map(n => '<tr><td>' + n.id + '</td><td>' + n.author_tag + '</td><td>' + n.content + '</td><td>' + new Date(n.created_at).toLocaleString('it-IT') + '</td><td><button class="btn danger small" onclick="deleteNote(' + n.id + ')">Elimina</button></td></tr>').join('') + '</tbody></table>';
    const ticketsEl = document.getElementById('user-tickets-content');
    if (!data.tickets.length) ticketsEl.innerHTML = '<p class="opacity-60 italic">Nessun ticket aperto.</p>';
    else ticketsEl.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th></th></tr></thead><tbody>' +
      data.tickets.map(t => '<tr><td>' + t.guild + '</td><td>#' + t.channel + '</td><td><button class="btn danger small" onclick="closeTicket(\\'' + t.channelId + '\\')">Chiudi</button></td></tr>').join('') + '</tbody></table>';
  }
  async function removeBL() { if (!confirm('Rimuovere dalla blacklist?')) return; await fetch('/api/blacklist/' + USER_ID, { method: 'DELETE' }); showToast('Rimosso', 'success'); loadUser(); }
  async function deleteNote(id) { if (!confirm('Eliminare la nota?')) return; await fetch('/api/notes/' + id, { method: 'DELETE' }); showToast('Nota eliminata', 'success'); loadUser(); }
  async function closeTicket(id) { if (!confirm('Chiudere il ticket?')) return; await fetch('/api/tickets/' + id, { method: 'DELETE' }); showToast('Ticket chiuso', 'success'); loadUser(); }
  loadUser();
  </script>`;
}

function renderSearchContent(q) {
  return `
  <div class="card-bg border rounded-xl p-5">
    <h2 class="text-lg font-semibold mb-4">🔍 Risultati per "${q}"</h2>
    <div id="search-content" class="opacity-60 italic">Ricerca in corso...</div>
  </div>
  <script>
  const QUERY = ${JSON.stringify(q)};
  async function doSearch() {
    const el = document.getElementById('search-content');
    if (!QUERY.trim()) { el.innerHTML = '<p class="opacity-60 italic">Inserisci un termine.</p>'; return; }
    const res = await fetch('/api/search?q=' + encodeURIComponent(QUERY));
    const data = await res.json();
    const total = data.blacklist.length + data.notes.length + data.logs.length + data.tickets.length;
    if (!total) { el.innerHTML = '<p class="opacity-60 italic">Nessun risultato.</p>'; return; }
    let html = '';
    if (data.blacklist.length) {
      html += '<h3 class="text-base font-semibold mt-4 mb-2">🚫 Blacklist (' + data.blacklist.length + ')</h3>';
      html += '<table><thead><tr><th>Utente</th><th>Motivo</th><th>Aggiunto da</th></tr></thead><tbody>' +
        data.blacklist.map(e => '<tr><td><a class="user-link" href="/user/' + e.user_id + '">' + e.username + '</a></td><td>' + e.reason + '</td><td>' + e.moderator_tag + '</td></tr>').join('') + '</tbody></table>';
    }
    if (data.notes.length) {
      html += '<h3 class="text-base font-semibold mt-4 mb-2">📝 Note (' + data.notes.length + ')</h3>';
      html += '<table><thead><tr><th>#</th><th>Utente</th><th>Contenuto</th></tr></thead><tbody>' +
        data.notes.map(n => '<tr><td>' + n.id + '</td><td><a class="user-link" href="/user/' + n.user_id + '">' + n.user_id + '</a></td><td>' + n.content + '</td></tr>').join('') + '</tbody></table>';
    }
    if (data.logs.length) {
      html += '<h3 class="text-base font-semibold mt-4 mb-2">📋 Logs (' + data.logs.length + ')</h3>';
      html += '<table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th></tr></thead><tbody>' +
        data.logs.slice(0, 50).map(l => '<tr><td>' + new Date(l.timestamp).toLocaleString('it-IT') + '</td><td><span class="badge ' + (l.type || 'default').toLowerCase() + '">' + (l.type || '-') + '</span></td><td>' + (l.target_id ? '<a class="user-link" href="/user/' + l.target_id + '">' + (l.target || l.target_id) + '</a>' : (l.target || '-')) + '</td><td>' + (l.moderator || '-') + '</td><td>' + (l.reason || '-') + '</td></tr>').join('') + '</tbody></table>';
    }
    if (data.tickets.length) {
      html += '<h3 class="text-base font-semibold mt-4 mb-2">🎫 Ticket (' + data.tickets.length + ')</h3>';
      html += '<table><thead><tr><th>Server</th><th>Canale</th></tr></thead><tbody>' +
        data.tickets.map(t => '<tr><td>' + t.guild + '</td><td>#' + t.channel + '</td></tr>').join('') + '</tbody></table>';
    }
    el.innerHTML = html;
  }
  doSearch();
  </script>`;
}

function renderAccessLogsContent() {
  return `
  <div class="card-bg border rounded-xl p-5">
    <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
      <h2 class="text-lg font-semibold">🔐 Log Accessi Dashboard</h2>
      <a href="/api/export/access-logs.csv" class="text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white">📥 CSV</a>
    </div>
    <p class="text-sm opacity-60 mb-4">Ultimi 500 accessi alla dashboard.</p>
    <div id="access-content" class="opacity-60 italic">Caricamento...</div>
  </div>
  <script>
  async function loadAccess() {
    const res = await fetch('/api/access-logs');
    const logs = await res.json();
    const el = document.getElementById('access-content');
    if (!logs.length) { el.innerHTML = '<p class="opacity-60 italic">Nessun accesso registrato.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Data</th><th>Utente</th><th>IP</th><th>User Agent</th></tr></thead><tbody>' +
      logs.map(l => '<tr><td>' + new Date(l.timestamp).toLocaleString('it-IT') + '</td><td><a class="user-link" href="/user/' + l.user_id + '">' + l.username + '</a></td><td><code>' + (l.ip || '-') + '</code></td><td class="text-xs opacity-60">' + (l.user_agent || '-').slice(0, 80) + '</td></tr>').join('') + '</tbody></table>';
  }
  loadAccess();
  </script>`;
}

module.exports = { createWebServer };
