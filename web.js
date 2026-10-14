// web.js — Dashboard web per il bot (indipendente dalla logica Discord)
const express = require('express');
const session = require('express-session');
const axios = require('axios');

function createWebServer({ storage, client, log, botStartTime }) {
  const app = express();
  const PORT = parseInt(process.env.PORT) || 3000;
  const HOST = process.env.WEB_HOST || '0.0.0.0';

  const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
  const CLIENT_SECRET = (process.env.DISCORD_CLIENT_SECRET || '').trim();
  const DASHBOARD_URL = (process.env.DASHBOARD_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
  const SESSION_SECRET = process.env.SESSION_SECRET || 'cambia-questo-segreto-ora';
  const ADMIN_IDS = (process.env.DASHBOARD_ADMIN_IDS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));

  // ==================== MIDDLEWARE ====================
  function requireAuth(req, res, next) {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Non autenticato' });
      return res.redirect('/auth/login');
    }
    if (!ADMIN_IDS.includes(req.session.user.id)) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Non autorizzato' });
      return res.status(403).send('Non sei autorizzato ad accedere alla dashboard.');
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
    res.json({
      message: 'Bot Dashboard',
      version: '1.0.0',
      loggedIn: !!req.session.user,
      loginUrl: '/auth/login'
    });
  });

  // ==================== OAUTH2 ====================
  app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID || !CLIENT_SECRET) {
      return res.status(500).send('OAuth2 non configurato (mancano CLIENT_ID o DISCORD_CLIENT_SECRET).');
    }
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: `${DASHBOARD_URL}/auth/callback`,
      response_type: 'code',
      scope: 'identify'
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });

  app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Codice mancante');

    try {
      const tokenRes = await axios.post(
        'https://discord.com/api/oauth2/token',
        new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${DASHBOARD_URL}/auth/callback`
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const userRes = await axios.get('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
      });

      const user = userRes.data;

      if (!ADMIN_IDS.includes(user.id)) {
        return res.status(403).send('Non sei autorizzato ad accedere alla dashboard.');
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || user.username,
        avatar: user.avatar
      };

      res.redirect('/dashboard');
    } catch (err) {
      log.err('OAuth2 callback', err.response?.data || err.message);
      res.status(500).send('Errore durante il login');
    }
  });

  app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  app.get('/auth/me', (req, res) => {
    res.json({ user: req.session.user || null });
  });

  // ==================== API PROTETTE ====================
  app.get('/api/stats', requireAuth, (req, res) => {
    const s = storage.getStats();
    res.json({
      logs: s.total,
      blacklist: s.blacklist,
      guilds: client.guilds.cache.size,
      ping: client.ws.ping,
      uptime: Math.floor((Date.now() - botStartTime) / 1000),
      byType: s.byType
    });
  });

  app.get('/api/blacklist', requireAuth, (req, res) => {
    res.json(storage.getAllBlacklist());
  });

  app.post('/api/blacklist', requireAuth, async (req, res) => {
    const { userId, username, reason } = req.body || {};
    if (!userId || !username || !reason) {
      return res.status(400).json({ error: 'userId, username e reason sono obbligatori' });
    }
    if (storage.isBlacklisted(userId)) {
      return res.status(409).json({ error: 'Utente già in blacklist' });
    }

    storage.addToBlacklist(
      userId, username, reason,
      req.session.user.id, req.session.user.username
    );
    res.json({ ok: true });
  });

  app.delete('/api/blacklist/:userId', requireAuth, (req, res) => {
    const ok = storage.removeFromBlacklist(req.params.userId);
    res.json({ ok });
  });

  app.get('/api/logs/:userId', requireAuth, (req, res) => {
    res.json(storage.getLogsForUser(req.params.userId));
  });

  app.get('/api/config/:guildId', requireAuth, (req, res) => {
    res.json(storage.getGuildConfig(req.params.guildId));
  });

  // ==================== DASHBOARD ====================
  app.get('/dashboard', requireAuth, (req, res) => {
    res.send(renderDashboard(req.session.user));
  });

  // ==================== AVVIO ====================
  const server = app.listen(PORT, HOST, () => {
    log.ok(`🌐 Dashboard web su http://${HOST}:${PORT}`);
    if (ADMIN_IDS.length === 0) {
      log.warn('⚠️  DASHBOARD_ADMIN_IDS vuoto: nessuno potrà accedere alla dashboard');
    }
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      log.warn(`Porta ${PORT} occupata, provo ${PORT + 1}...`);
      server.listen(PORT + 1, HOST);
    } else {
      log.err('Web server', err);
    }
  });

  return server;
}

// ==================== HTML ====================
function renderDashboard(user) {
  const name = user.global_name || user.username;
  const avatarUrl = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`
    : `https://cdn.discordapp.com/embed/avatars/0.png`;

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Dashboard Bot</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, "Segoe UI", sans-serif; background: #1a1a1a; color: #eee; padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; padding-bottom: 18px; border-bottom: 1px solid #333; }
  h1 { font-size: 22px; }
  .user { display: flex; align-items: center; gap: 12px; }
  .user img { width: 40px; height: 40px; border-radius: 50%; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .card { background: #252525; border: 1px solid #333; border-radius: 10px; padding: 18px; }
  .card h2 { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .card .value { font-size: 30px; font-weight: bold; color: #5865F2; }
  .section { background: #252525; border: 1px solid #333; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  .section h2 { font-size: 18px; margin-bottom: 14px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #333; font-size: 14px; }
  th { color: #888; font-size: 11px; text-transform: uppercase; }
  button { background: #5865F2; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  button:hover { background: #4752c4; }
  button.danger { background: #ed4245; }
  button.danger:hover { background: #c93b3e; }
  .loading { color: #888; font-style: italic; }
  a { color: #5865F2; text-decoration: none; }
</style>
</head>
<body>
  <header>
    <h1>🤖 Dashboard Bot</h1>
    <div class="user">
      <img src="${avatarUrl}" alt="avatar">
      <span>${name}</span>
      <a href="/auth/logout"><button class="danger">Logout</button></a>
    </div>
  </header>

  <div class="grid">
    <div class="card"><h2>Log Totali</h2><div class="value" id="stat-logs">...</div></div>
    <div class="card"><h2>Blacklist</h2><div class="value" id="stat-bl">...</div></div>
    <div class="card"><h2>Server</h2><div class="value" id="stat-guilds">...</div></div>
    <div class="card"><h2>Ping</h2><div class="value" id="stat-ping">...</div></div>
    <div class="card"><h2>Uptime</h2><div class="value" id="stat-uptime">...</div></div>
  </div>

  <div class="section">
    <h2>🚫 Blacklist Globale</h2>
    <div id="blacklist-content" class="loading">Caricamento...</div>
  </div>

<script>
async function loadStats() {
  const res = await fetch('/api/stats');
  if (!res.ok) return;
  const s = await res.json();
  document.getElementById('stat-logs').textContent = s.logs;
  document.getElementById('stat-bl').textContent = s.blacklist;
  document.getElementById('stat-guilds').textContent = s.guilds;
  document.getElementById('stat-ping').textContent = s.ping + 'ms';
  const h = Math.floor(s.uptime / 3600);
  const m = Math.floor((s.uptime % 3600) / 60);
  document.getElementById('stat-uptime').textContent = h + 'h ' + m + 'm';
}

async function loadBlacklist() {
  const res = await fetch('/api/blacklist');
  const list = await res.json();
  const el = document.getElementById('blacklist-content');
  if (!list.length) { el.innerHTML = '<p class="loading">Nessun utente in blacklist.</p>'; return; }
  el.innerHTML = '<table><thead><tr><th>Utente</th><th>Motivo</th><th>Aggiunto da</th><th></th></tr></thead><tbody>' +
    list.map(e => '<tr><td>' + e.username + '<br><small style="color:#666">' + e.user_id + '</small></td><td>' + e.reason + '</td><td>' + e.moderator_tag + '</td><td><button class="danger" onclick="removeBL(\\'' + e.user_id + '\\')">Rimuovi</button></td></tr>').join('') +
    '</tbody></table>';
}

async function removeBL(userId) {
  if (!confirm('Rimuovere ' + userId + ' dalla blacklist?')) return;
  await fetch('/api/blacklist/' + userId, { method: 'DELETE' });
  loadBlacklist();
}

loadStats();
loadBlacklist();
setInterval(loadStats, 10000);
</script>
</body>
</html>`;
}

module.exports = { createWebServer };
