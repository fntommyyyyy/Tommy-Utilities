// lobbies.js — Mappa lobby per il dashboard (stile server custom: host, chat, vocale, stato)
const { ChannelType, PermissionsBitField } = require('discord.js');
const { z } = require('zod');

const LOBBY_PREFIX = 'lobby-';
const RECENT_CHAT_MS = 10 * 60 * 1000;
const STATUS_LABEL = { free: 'Libera', live: 'In corso', full: 'Piena', chat: 'Chat attiva' };
const STATUS_ORDER = { live: 0, full: 1, chat: 2, free: 3 };
const LOBBY_NAME_RE = /^[\p{L}\p{N} _-]+$/u;
const ID_RE = /^\d{17,20}$/;

function snowflakeToMs(id) {
  if (!id) return null;
  try { return Number((BigInt(id) >> 22n) + 1420070400000n); }
  catch { return null; }
}

function slugify(name) {
  return name.toLowerCase().replace(/\s+/g, '-').slice(0, 90);
}

function isLobbyCategory(c) {
  return c.type === ChannelType.GuildCategory && typeof c.name === 'string' && c.name.startsWith(LOBBY_PREFIX);
}

// Host = primo permission overwrite di tipo "membro" (1) con ViewChannel, diverso dal bot.
// Il bot crea la categoria dando ViewChannel solo all'utente che ha aperto la lobby.
function findHostId(category, botId) {
  for (const ow of category.permissionOverwrites.cache.values()) {
    if (ow.type !== 1 || ow.id === botId) continue;
    if (ow.allow.has(PermissionsBitField.Flags.ViewChannel)) return ow.id;
  }
  return null;
}

function computeStatus(voiceCount, limit, lastChatMs, now) {
  if (limit > 0 && voiceCount >= limit) return 'full';
  if (voiceCount > 0) return 'live';
  if (lastChatMs && now - lastChatMs < RECENT_CHAT_MS) return 'chat';
  return 'free';
}

function buildLobby(guild, category, now) {
  const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
  const text = children.find(c => c.type === ChannelType.GuildText) || null;
  const voice = children.find(c => c.type === ChannelType.GuildVoice) || null;

  const hostId = findHostId(category, guild.client.user.id);
  const hostMember = hostId ? guild.members.cache.get(hostId) : null;
  const voiceMembers = voice ? [...voice.members.values()] : [];
  const limit = voice?.userLimit || 0;
  const lastChatMs = text ? snowflakeToMs(text.lastMessageId) : null;
  const status = computeStatus(voiceMembers.length, limit, lastChatMs, now);

  return {
    id: category.id,
    name: category.name.slice(LOBBY_PREFIX.length),
    status,
    statusLabel: STATUS_LABEL[status],
    host: hostId ? { id: hostId, name: hostMember ? hostMember.displayName : hostId } : null,
    capacity: { count: voiceMembers.length, limit },
    members: voiceMembers.slice(0, 20).map(m => ({
      id: m.id,
      name: m.displayName,
      avatar: m.displayAvatarURL({ size: 32 })
    })),
    url: voice ? `https://discord.com/channels/${guild.id}/${voice.id}` : null,
    createdAt: snowflakeToMs(category.id),
    lastChatAt: lastChatMs
  };
}

function mountLobbies(app, deps) {
  const {
    client, log, requireAuth, actionLimiter, parseOrFail, apiError,
    assertGuildAccess, canManageGuild, logMod, dashMod
  } = deps;

  const schemaLobbyCreate = z.object({
    name: z.string().min(1).max(30),
    userLimit: z.number().int().min(0).max(99).optional().default(0)
  });

  // Mappa: tutte le lobby del server
  app.get('/api/lobbies/:guildId', requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, guildId))) return;
    try {
      const guild = client.guilds.cache.get(guildId);
      const now = Date.now();
      const lobbies = [...guild.channels.cache.values()]
        .filter(isLobbyCategory)
        .map(c => buildLobby(guild, c, now))
        .sort((a, b) => (STATUS_ORDER[a.status] - STATUS_ORDER[b.status]) || a.name.localeCompare(b.name));
      res.json({ guildName: guild.name, lobbies });
    } catch (e) { apiError(res, e, 'Errore mappa lobby'); }
  });

  // Creazione lobby (categoria + chat + vocale), host = utente del dashboard
  app.post('/api/lobbies/:guildId', actionLimiter, requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const data = parseOrFail(schemaLobbyCreate, req.body || {}, res);
    if (!data) return;

    const name = data.name.trim().replace(/\s+/g, ' ');
    if (!name || !LOBBY_NAME_RE.test(name)) {
      return res.status(400).json({ error: 'Nome non valido: usa lettere, numeri, spazi, - e _' });
    }
    if (!(await assertGuildAccess(req, res, guildId))) return;

    try {
      const guild = client.guilds.cache.get(guildId);
      if (!guild.members.me.permissions.has(PermissionsBitField.Flags.ManageChannels)) {
        return res.status(403).json({ error: 'Il bot non ha "Gestisci Canali"' });
      }

      const categoryName = LOBBY_PREFIX + name;
      if (guild.channels.cache.some(c => c.type === ChannelType.GuildCategory && c.name === categoryName)) {
        return res.status(409).json({ error: 'Esiste già una lobby con questo nome' });
      }

      const hostMember = await guild.members.fetch(req.session.user.id).catch(() => null);
      const overwrites = [{ id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] }];
      if (hostMember) {
        overwrites.push({
          id: hostMember.id,
          allow: [
            PermissionsBitField.Flags.ViewChannel,
            PermissionsBitField.Flags.SendMessages,
            PermissionsBitField.Flags.ReadMessageHistory,
            PermissionsBitField.Flags.Connect,
            PermissionsBitField.Flags.Speak
          ]
        });
      }

      const category = await guild.channels.create({
        name: categoryName,
        type: ChannelType.GuildCategory,
        permissionOverwrites: overwrites,
        reason: `Lobby creata dalla dashboard (${req.session.user.username})`
      });

      try {
        await guild.channels.create({
          name: 'chat-' + slugify(name),
          type: ChannelType.GuildText,
          parent: category.id,
          permissionOverwrites: overwrites
        });
        await guild.channels.create({
          name: categoryName,
          type: ChannelType.GuildVoice,
          parent: category.id,
          userLimit: data.userLimit,
          permissionOverwrites: overwrites
        });
      } catch (err) {
        await category.delete('Creazione lobby incompleta').catch(() => {});
        throw err;
      }

      await logMod(guild, {
        type: 'Lobby Creata',
        title: 'Lobby Creata',
        moderator: dashMod(req),
        channel: categoryName,
        reason: data.userLimit ? `Limite ${data.userLimit} giocatori` : undefined
      });
      res.status(201).json({ ok: true, id: category.id });
    } catch (e) { apiError(res, e, 'Errore creazione lobby'); }
  });

  // Eliminazione lobby: prima chat e vocale, poi la categoria
  app.delete('/api/lobbies/:categoryId', actionLimiter, requireAuth, async (req, res) => {
    const categoryId = req.params.categoryId;
    if (!ID_RE.test(categoryId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const category = await client.channels.fetch(categoryId).catch(() => null);
      if (!category || !category.guild || !isLobbyCategory(category)) {
        return res.status(404).json({ error: 'Lobby non trovata' });
      }
      if (!(await canManageGuild(req.session.user.id, category.guild))) {
        return res.status(403).json({ error: 'Non hai i permessi su questo server' });
      }

      const children = [...category.guild.channels.cache.values()].filter(c => c.parentId === category.id);
      for (const ch of children) {
        await ch.delete(`Lobby eliminata dalla dashboard (${req.session.user.username})`)
          .catch(err => log.warn(`Impossibile eliminare ${ch.name}: ${err.message}`));
      }
      await category.delete(`Lobby eliminata dalla dashboard (${req.session.user.username})`);

      await logMod(category.guild, {
        type: 'Lobby Eliminata',
        title: 'Lobby Eliminata',
        moderator: dashMod(req),
        channel: category.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore eliminazione lobby'); }
  });
}

function renderLobbiesContent() {
  return `
  <style>
    .lobby-toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
    .lobby-toolbar select { max-width: 320px; margin: 0; }
    .lobby-create { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
    .lobby-create input { width: auto; flex: 0 0 auto; margin: 0; max-width: 240px; }
    .lobby-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 14px; }
    .lobby-tile { background: #1a1a1a; border: 1px solid #333; border-top: 4px solid #444; border-radius: 10px; padding: 14px; display: flex; flex-direction: column; gap: 8px; }
    .lobby-tile.st-free { border-top-color: #43b581; }
    .lobby-tile.st-live { border-top-color: #5865F2; }
    .lobby-tile.st-chat { border-top-color: #faa61a; }
    .lobby-tile.st-full { border-top-color: #ed4245; }
    .lobby-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .lobby-name { font-weight: bold; font-size: 15px; word-break: break-word; }
    .lobby-badge { font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: bold; text-transform: uppercase; white-space: nowrap; color: #000; }
    .lobby-badge.st-free { background: #43b581; }
    .lobby-badge.st-live { background: #5865F2; color: #fff; }
    .lobby-badge.st-chat { background: #faa61a; }
    .lobby-badge.st-full { background: #ed4245; color: #fff; }
    .lobby-meta { font-size: 12px; color: #888; }
    .lobby-members { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .lobby-member { display: flex; align-items: center; gap: 4px; font-size: 12px; background: #252525; border-radius: 14px; padding: 2px 8px 2px 2px; }
    .lobby-member img { width: 20px; height: 20px; border-radius: 50%; }
    .lobby-actions { display: flex; gap: 8px; margin-top: auto; flex-wrap: wrap; }
    .lobby-empty { color: #888; font-style: italic; padding: 30px; text-align: center; border: 1px dashed #333; border-radius: 10px; }
  </style>

  <div class="section">
    <h2>🗺️ Mappa Lobby</h2>
    <p style="color:#888;font-size:13px;margin-bottom:14px;">Stato delle lobby del server, aggiornato ogni 5 secondi. Una lobby è <b>Piena</b> quando il vocale ha raggiunto il limite di giocatori, <b>In corso</b> quando c'è qualcuno dentro.</p>

    <div class="lobby-toolbar">
      <label style="font-size:13px;color:#888;">Server</label>
      <select id="lb-guild" onchange="lbLoad()"></select>
      <span id="lb-updated" style="font-size:12px;color:#666;margin-left:auto;"></span>
    </div>

    <div class="lobby-create">
      <input id="lb-new-name" placeholder="Nome lobby (es. Custom 1)" maxlength="30">
      <input id="lb-new-limit" type="number" min="0" max="99" value="0" placeholder="Max giocatori (0 = libero)">
      <button onclick="lbCreate()">➕ Crea lobby</button>
    </div>

    <div id="lb-result"></div>
    <div id="lb-grid" class="lobby-grid" style="margin-top:12px;"><p class="lobby-empty">Caricamento...</p></div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let lbTimer = null;

  function lbRel(ms) {
    if (!ms) return 'mai';
    const m = Math.floor(Math.max(0, Date.now() - ms) / 60000);
    if (m < 1) return 'ora';
    if (m < 60) return m + ' min fa';
    const h = Math.floor(m / 60);
    if (h < 24) return h + ' h fa';
    return Math.floor(h / 24) + ' g fa';
  }

  function lbShow(html) { document.getElementById('lb-result').innerHTML = html; }

  function lbTile(l) {
    const count = l.capacity.count;
    const cap = l.capacity.limit > 0 ? count + '/' + l.capacity.limit : String(count);
    const members = l.members.map(m => '<span class="lobby-member"><img src="' + esc(m.avatar) + '" alt="">' + esc(m.name) + '</span>').join('');
    const more = count > l.members.length ? '<span class="lobby-meta">+' + (count - l.members.length) + '</span>' : '';
    const host = l.host ? esc(l.host.name) : '<span style="color:#666">nessun host</span>';
    const open = l.url ? '<a href="' + esc(l.url) + '" target="_blank" rel="noopener"><button class="secondary small">🔗 Apri</button></a>' : '';
    const chat = l.lastChatAt ? 'ultima chat ' + esc(lbRel(l.lastChatAt)) : 'nessuna attività in chat';
    return '<div class="lobby-tile st-' + esc(l.status) + '">' +
      '<div class="lobby-head"><span class="lobby-name">' + esc(l.name) + '</span>' +
      '<span class="lobby-badge st-' + esc(l.status) + '">' + esc(l.statusLabel) + '</span></div>' +
      '<div class="lobby-meta">👑 Host: ' + host + '</div>' +
      '<div class="lobby-meta">👥 ' + esc(cap) + ' in vocale</div>' +
      '<div class="lobby-meta">💬 ' + chat + '</div>' +
      '<div class="lobby-meta">🕒 creata ' + esc(lbRel(l.createdAt)) + '</div>' +
      '<div class="lobby-members">' + (members || '<span class="lobby-meta">vocale vuoto</span>') + more + '</div>' +
      '<div class="lobby-actions">' + open +
        '<button class="danger small" onclick="lbDelete(\\'' + esc(l.id) + '\\')">🗑️ Elimina</button>' +
      '</div>' +
    '</div>';
  }

  async function lbLoad() {
    const guildId = document.getElementById('lb-guild').value;
    const grid = document.getElementById('lb-grid');
    if (!guildId) { grid.innerHTML = '<p class="lobby-empty">Nessun server disponibile.</p>'; return; }
    const res = await apiFetch('/api/lobbies/' + encodeURIComponent(guildId));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { grid.innerHTML = '<p class="lobby-empty">❌ ' + esc(data.error || 'Errore') + '</p>'; return; }
    grid.innerHTML = data.lobbies.length
      ? data.lobbies.map(lbTile).join('')
      : '<p class="lobby-empty">Nessuna lobby. Creane una dal pannello sopra.</p>';
    document.getElementById('lb-updated').textContent = 'Aggiornato alle ' + new Date().toLocaleTimeString('it-IT');
  }

  async function lbCreate() {
    const guildId = document.getElementById('lb-guild').value;
    const name = document.getElementById('lb-new-name').value.trim();
    const limit = parseInt(document.getElementById('lb-new-limit').value, 10) || 0;
    if (!guildId) return lbShow('<span class="error">❌ Seleziona un server</span>');
    if (!name) return lbShow('<span class="error">❌ Inserisci un nome</span>');
    const r = await postJson('/api/lobbies/' + encodeURIComponent(guildId), { name: name, userLimit: limit });
    if (r.ok) {
      document.getElementById('lb-new-name').value = '';
      lbShow('<span class="success">✅ Lobby creata</span>');
      lbLoad();
    } else {
      lbShow('<span class="error">❌ [' + r.status + '] ' + esc((r.data && r.data.error) || 'Errore') + '</span>');
    }
  }

  async function lbDelete(categoryId) {
    if (!confirm('Eliminare questa lobby? Verranno cancellati anche chat e vocale.')) return;
    const res = await apiFetch('/api/lobbies/' + encodeURIComponent(categoryId), { method: 'DELETE' });
    const d = await res.json().catch(() => ({}));
    if (res.ok) lbShow('<span class="success">✅ Lobby eliminata</span>');
    else lbShow('<span class="error">❌ [' + res.status + '] ' + esc(d.error || 'Errore') + '</span>');
    lbLoad();
  }

  async function lbLoadGuilds() {
    const res = await apiFetch('/api/guilds');
    const guilds = await res.json().catch(() => []);
    document.getElementById('lb-guild').innerHTML = guilds.length
      ? guilds.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('')
      : '<option value="">Nessun server</option>';
    await lbLoad();
    if (!lbTimer) lbTimer = setInterval(lbLoad, 5000);
  }

  lbLoadGuilds();
  </script>`;
}

module.exports = { mountLobbies, renderLobbiesContent };
