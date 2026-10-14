// web.js — Dashboard web completa (tutte le pagine in un unico file)
const express = require('express');
const session = require('express-session');
const axios = require('axios');

function createWebServer({ storage, client, log, botStartTime }) {
  const app = express();
  const PORT = parseInt(process.env.PORT) || 3000;
  const HOST = process.env.WEB_HOST || '0.0.0.0';

  app.set('trust proxy', 1);

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
    proxy: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));

  function requireAuth(req, res, next) {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Non autenticato' });
      return res.redirect('/auth/login');
    }
    if (!ADMIN_IDS.includes(req.session.user.id)) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Non autorizzato' });
      return res.status(403).send('Non sei autorizzato.');
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
    res.json({ message: 'Bot Dashboard', version: '2.0.0', loggedIn: !!req.session.user });
  });

  // ==================== OAUTH2 ====================
  app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID || !CLIENT_SECRET) return res.status(500).send('OAuth2 non configurato.');
    const redirectUri = `${DASHBOARD_URL}/auth/callback`;
    const params = new URLSearchParams({
      client_id: CLIENT_ID, redirect_uri: redirectUri,
      response_type: 'code', scope: 'identify'
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });

  app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Codice mancante');
    const redirectUri = `${DASHBOARD_URL}/auth/callback`;
    try {
      const tokenRes = await axios.post('https://discord.com/api/oauth2/token',
        new URLSearchParams({
          client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
          grant_type: 'authorization_code', code, redirect_uri: redirectUri
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const userRes = await axios.get('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
      });
      const user = userRes.data;
      if (!ADMIN_IDS.includes(user.id)) return res.status(403).send('Non autorizzato.');
      req.session.user = {
        id: user.id, username: user.username,
        global_name: user.global_name || user.username, avatar: user.avatar
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

  // --- BLACKLIST ---
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

  // --- MOD LOGS ---
  app.get('/api/logs/all', requireAuth, (req, res) => {
    try {
      const rows = storage.db.prepare('SELECT * FROM mod_logs ORDER BY id DESC LIMIT 500').all();
      res.json(rows);
    } catch (e) { res.json([]); }
  });
  app.get('/api/logs/:userId', requireAuth, (req, res) => {
    res.json(storage.getLogsForUser(req.params.userId));
  });

  // --- NOTE ---
  app.get('/api/notes/all', requireAuth, (req, res) => {
    try { res.json(storage.getAllNotes()); } catch (e) { res.json([]); }
  });

  // --- CONFIG ---
  app.get('/api/config/:guildId', requireAuth, (req, res) => {
    res.json(storage.getGuildConfig(req.params.guildId));
  });

  // --- TICKET ---
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

  // --- COMANDI CUSTOM ---
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

  // --- GRAFICI ---
  app.get('/api/charts', requireAuth, (req, res) => {
    try {
      const byType = storage.db.prepare('SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type').all();
      const byDay = storage.db.prepare(
        "SELECT substr(timestamp,1,10) as day, COUNT(*) as c FROM mod_logs GROUP BY day ORDER BY day DESC LIMIT 30"
      ).all();
      res.json({ byType, byDay });
    } catch (e) { res.json({ byType: [], byDay: [] }); }
  });

  // ==================== PAGINE HTML ====================
  app.get('/dashboard', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'dashboard')));
  app.get('/modlogs', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'modlogs')));
  app.get('/notes', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'notes')));
  app.get('/tickets', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'tickets')));
  app.get('/commands', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'commands')));
  app.get('/charts', requireAuth, (req, res) => res.send(renderLayout(req.session.user, 'charts')));

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
// ============== HTML — TUTTE LE PAGINE IN UNA ===============
// ============================================================
function renderLayout(user, page) {
  const name = user.global_name || user.username;
  const avatar = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`
    : `https://cdn.discordapp.com/embed/avatars/0.png`;

  const pages = {
    dashboard: renderDashboardContent(),
    modlogs: renderModlogsContent(),
    notes: renderNotesContent(),
    tickets: renderTicketsContent(),
    commands: renderCommandsContent(),
    charts: renderChartsContent()
  };

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard - ${page}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, "Segoe UI", sans-serif; background: #1a1a1a; color: #eee; padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid #333; }
  h1 { font-size: 22px; }
  .user { display: flex; align-items: center; gap: 12px; }
  .user img { width: 40px; height: 40px; border-radius: 50%; }
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
  input, select, textarea { background: #1a1a1a; border: 1px solid #444; color: #eee; padding: 8px 12px; border-radius: 6px; font-size: 14px; width: 100%; margin-bottom: 10px; font-family: inherit; }
  .form-row { display: flex; gap: 10px; align-items: flex-start; flex-wrap: wrap; }
  .form-row input, .form-row select { flex: 1; min-width: 150px; }
  .loading { color: #888; font-style: italic; }
  a { color: #5865F2; text-decoration: none; }
  .filter-bar { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-bar select, .filter-bar input { max-width: 250px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge.kick { background: #faa61a; color: #000; }
  .badge.ban { background: #ed4245; color: #fff; }
  .badge.warn { background: #faa61a; color: #000; }
  .badge.timeout { background: #5865F2; color: #fff; }
  .badge.default { background: #444; color: #eee; }
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 768px) { .charts-grid { grid-template-columns: 1fr; } }
  .chart-box { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; }
</style>
</head>
<body>
  <header>
    <h1>🤖 Dashboard Bot</h1>
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
    <a href="/charts" class="${page === 'charts' ? 'active' : ''}">📊 Grafici</a>
  </nav>

  ${pages[page] || '<p>Pagina non trovata</p>'}
</body>
</html>`;
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
      <input type="text" id="bl-userId" placeholder="ID utente (17-20 cifre)">
      <input type="text" id="bl-username" placeholder="Username">
      <input type="text" id="bl-reason" placeholder="Motivo">
      <button onclick="addBL()">Aggiungi</button>
    </div>
    <div id="bl-msg" style="margin-top:8px;font-size:13px;"></div>
  </div>

  <div class="section">
    <h2>🚫 Blacklist Globale</h2>
    <div id="blacklist-content" class="loading">Caricamento...</div>
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
    if (!list.length) { el.innerHTML = '<p class="loading">Nessun utente in blacklist.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Utente</th><th>Motivo</th><th>Aggiunto da</th><th></th></tr></thead><tbody>' +
      list.map(e => '<tr><td>' + e.username + '<br><small style="color:#666">' + e.user_id + '</small></td><td>' + e.reason + '</td><td>' + e.moderator_tag + '</td><td><button class="danger small" onclick="removeBL(\\'' + e.user_id + '\\')">Rimuovi</button></td></tr>').join('') +
      '</tbody></table>';
  }
  async function addBL() {
    const userId = document.getElementById('bl-userId').value.trim();
    const username = document.getElementById('bl-username').value.trim();
    const reason = document.getElementById('bl-reason').value.trim();
    const msg = document.getElementById('bl-msg');
    if (!userId || !username || !reason) { msg.textContent = '❌ Compila tutti i campi'; msg.style.color = '#ed4245'; return; }
    const res = await fetch('/api/blacklist', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, username, reason })
    });
    const data = await res.json();
    if (res.ok) {
      msg.textContent = '✅ Aggiunto'; msg.style.color = '#00FF00';
      document.getElementById('bl-userId').value = '';
      document.getElementById('bl-username').value = '';
      document.getElementById('bl-reason').value = '';
      loadBlacklist(); loadStats();
    } else {
      msg.textContent = '❌ ' + (data.error || 'Errore'); msg.style.color = '#ed4245';
    }
  }
  async function removeBL(userId) {
    if (!confirm('Rimuovere ' + userId + ' dalla blacklist?')) return;
    await fetch('/api/blacklist/' + userId, { method: 'DELETE' });
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
      <input type="text" id="filter-user" placeholder="Filtra per ID utente" oninput="loadLogs()">
    </div>
    <div id="logs-content" class="loading">Caricamento...</div>
  </div>

  <script>
  async function loadLogs() {
    const type = document.getElementById('filter-type').value;
    const userId = document.getElementById('filter-user').value.trim();
    const res = await fetch('/api/logs/all');
    let logs = await res.json();
    if (type) logs = logs.filter(l => l.type === type);
    if (userId) logs = logs.filter(l => (l.target_id || '').includes(userId));
    const el = document.getElementById('logs-content');
    if (!logs.length) { el.innerHTML = '<p class="loading">Nessun log trovato.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      logs.map(l => '<tr>' +
        '<td>' + new Date(l.timestamp).toLocaleString('it-IT') + '</td>' +
        '<td><span class="badge ' + (l.type || 'default').toLowerCase() + '">' + (l.type || '-') + '</span></td>' +
        '<td>' + (l.target || '-') + '</td>' +
        '<td>' + (l.moderator || '-') + '</td>' +
        '<td>' + (l.reason || '-') + '</td>' +
        '<td>' + (l.duration || '-') + '</td>' +
      '</tr>').join('') +
      '</tbody></table>';
  }
  loadLogs();
  </script>`;
}

// ---------- NOTE ----------
function renderNotesContent() {
  return `
  <div class="section">
    <h2>📝 Note Staff</h2>
    <div id="notes-content" class="loading">Caricamento...</div>
  </div>

  <script>
  async function loadNotes() {
    const res = await fetch('/api/notes/all');
    const notes = await res.json();
    const el = document.getElementById('notes-content');
    if (!notes.length) { el.innerHTML = '<p class="loading">Nessuna nota.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>#</th><th>Utente</th><th>Autore</th><th>Contenuto</th><th>Data</th></tr></thead><tbody>' +
      notes.map(n => '<tr>' +
        '<td>' + n.id + '</td>' +
        '<td>' + n.user_id + '</td>' +
        '<td>' + n.author_tag + '</td>' +
        '<td>' + n.content + '</td>' +
        '<td>' + new Date(n.created_at).toLocaleString('it-IT') + '</td>' +
      '</tr>').join('') +
      '</tbody></table>';
  }
  loadNotes();
  </script>`;
}

// ---------- TICKET ----------
function renderTicketsContent() {
  return `
  <div class="section">
    <h2>🎫 Ticket Aperti</h2>
    <div id="tickets-content" class="loading">Caricamento...</div>
  </div>

  <script>
  async function loadTickets() {
    const res = await fetch('/api/tickets');
    const tickets = await res.json();
    const el = document.getElementById('tickets-content');
    if (!tickets.length) { el.innerHTML = '<p class="loading">Nessun ticket aperto.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th>Utente</th></tr></thead><tbody>' +
      tickets.map(t => '<tr>' +
        '<td>' + t.guild + '</td>' +
        '<td>#' + t.channel + '</td>' +
        '<td>' + t.userId + '</td>' +
      '</tr>').join('') +
      '</tbody></table>';
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
      <input type="text" id="cmd-name" placeholder="Nome (es. regole)">
      <input type="text" id="cmd-response" placeholder="Risposta">
      <button onclick="addCmd()">Aggiungi</button>
    </div>
    <div id="cmd-msg" style="margin-top:8px;font-size:13px;"></div>
  </div>

  <div class="section">
    <h2>🔧 Comandi Custom</h2>
    <div id="commands-content" class="loading">Caricamento...</div>
  </div>

  <script>
  async function loadCmds() {
    const res = await fetch('/api/commands');
    const cmds = await res.json();
    const el = document.getElementById('commands-content');
    if (!cmds.length) { el.innerHTML = '<p class="loading">Nessun comando custom.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Comando</th><th>Risposta</th><th></th></tr></thead><tbody>' +
      cmds.map(c => '<tr>' +
        '<td><code>-' + c.name + '</code></td>' +
        '<td>' + c.response + '</td>' +
        '<td><button class="danger small" onclick="removeCmd(\\'' + c.name + '\\')">Elimina</button></td>' +
      '</tr>').join('') +
      '</tbody></table>';
  }
  async function addCmd() {
    const name = document.getElementById('cmd-name').value.trim();
    const response = document.getElementById('cmd-response').value.trim();
    const msg = document.getElementById('cmd-msg');
    if (!name || !response) { msg.textContent = '❌ Compila tutti i campi'; msg.style.color = '#ed4245'; return; }
    const res = await fetch('/api/commands', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, response })
    });
    if (res.ok) {
      msg.textContent = '✅ Aggiunto'; msg.style.color = '#00FF00';
      document.getElementById('cmd-name').value = '';
      document.getElementById('cmd-response').value = '';
      loadCmds();
    } else { msg.textContent = '❌ Errore'; msg.style.color = '#ed4245'; }
  }
  async function removeCmd(name) {
    if (!confirm('Eliminare il comando -' + name + '?')) return;
    await fetch('/api/commands/' + name, { method: 'DELETE' });
    loadCmds();
  }
  loadCmds();
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
    const res = await fetch('/api/charts');
    const data = await res.json();
    const colors = ['#5865F2','#ed4245','#faa61a','#00FF00','#9B59B6','#1ABC9C'];

    new Chart(document.getElementById('chart-types'), {
      type: 'doughnut',
      data: {
        labels: data.byType.map(t => t.type),
        datasets: [{ data: data.byType.map(t => t.c), backgroundColor: colors }]
      },
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

module.exports = { createWebServer };
