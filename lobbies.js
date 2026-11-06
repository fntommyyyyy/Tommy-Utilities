// lobbies.js — Lobby custom per il dashboard: iscrizioni, dropmap, codice, riempimento, staff
const { ChannelType, PermissionsBitField, EmbedBuilder } = require('discord.js');
const { z } = require('zod');

const LOBBY_PREFIX = 'lobby-';
const RECENT_CHAT_MS = 10 * 60 * 1000;
const VOICE_LABEL = { free: 'Libera', live: 'In corso', full: 'Vocale pieno', chat: 'Chat attiva' };
const VOICE_ORDER = { live: 0, full: 1, chat: 2, free: 3 };
const REG_LABEL = { open: 'Iscrizioni aperte', closed: 'Iscrizioni chiuse', full: 'Lobby piena' };
const LOBBY_NAME_RE = /^[\p{L}\p{N} _-]+$/u;
const CODE_RE = /^[A-Za-z0-9-]{1,30}$/;
const ID_RE = /^\d{17,20}$/;

// Permessi dati a iscritti e staff sui canali della lobby
const PLAYER_PERMS = { ViewChannel: true, SendMessages: true, ReadMessageHistory: true, Connect: true, Speak: true };
const STAFF_PERMS = { ...PLAYER_PERMS, ManageMessages: true };

const SCHEMA = `
CREATE TABLE IF NOT EXISTS lobby_meta (
  category_id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  host_id TEXT,
  dropmap TEXT,
  code TEXT,
  slots INTEGER NOT NULL DEFAULT 0,
  reg_open INTEGER NOT NULL DEFAULT 1,
  staff TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lobby_registrations (
  category_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  PRIMARY KEY (category_id, user_id)
);
`;

// ==================== HELPER GENERICI ====================
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

// Host di una lobby creata dal bot: primo overwrite "membro" con ViewChannel
// che non sia il bot, né staff, né iscritto.
function findHostId(category, excluded) {
  for (const ow of category.permissionOverwrites.cache.values()) {
    if (ow.type !== 1 || excluded.has(ow.id)) continue;
    if (ow.allow.has(PermissionsBitField.Flags.ViewChannel)) return ow.id;
  }
  return null;
}

function computeVoiceStatus(voiceCount, limit, lastChatMs, now) {
  if (limit > 0 && voiceCount >= limit) return 'full';
  if (voiceCount > 0) return 'live';
  if (lastChatMs && now - lastChatMs < RECENT_CHAT_MS) return 'chat';
  return 'free';
}

function regState(meta, count) {
  if (meta.slots > 0 && count >= meta.slots) return 'full';
  return meta.regOpen ? 'open' : 'closed';
}

function accessLevel(meta, userId, registered) {
  if (meta.staff.some(s => s.id === userId)) return 'staff';
  return registered ? 'player' : 'none';
}

function lobbyEmbed(title, description) {
  return new EmbedBuilder()
    .setTitle(title)
    .setDescription(description.slice(0, 4000))
    .setColor(0x5865F2)
    .setTimestamp();
}

// ==================== DATABASE ====================
function readMeta(db, categoryId) {
  const row = db.prepare('SELECT * FROM lobby_meta WHERE category_id = ?').get(categoryId);
  let staff = [];
  try { staff = row ? JSON.parse(row.staff || '[]') : []; } catch { staff = []; }
  return {
    hostId: row?.host_id || null,
    dropmap: row?.dropmap || null,
    code: row?.code || null,
    slots: row?.slots || 0,
    regOpen: row ? !!row.reg_open : true,
    staff
  };
}

// patch contiene solo le chiavi da cambiare
function saveMeta(db, categoryId, guildId, patch) {
  const next = { ...readMeta(db, categoryId), ...patch };
  db.prepare(`
    INSERT INTO lobby_meta (category_id, guild_id, host_id, dropmap, code, slots, reg_open, staff, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(category_id) DO UPDATE SET
      host_id = excluded.host_id,
      dropmap = excluded.dropmap,
      code = excluded.code,
      slots = excluded.slots,
      reg_open = excluded.reg_open,
      staff = excluded.staff,
      updated_at = excluded.updated_at
  `).run(
    categoryId, guildId, next.hostId, next.dropmap, next.code, next.slots,
    next.regOpen ? 1 : 0, JSON.stringify(next.staff), new Date().toISOString()
  );
  return next;
}

function listRegistrations(db, categoryId) {
  return db.prepare('SELECT user_id, username FROM lobby_registrations WHERE category_id = ? ORDER BY registered_at ASC').all(categoryId);
}

function hasRegistration(db, categoryId, userId) {
  return !!db.prepare('SELECT 1 FROM lobby_registrations WHERE category_id = ? AND user_id = ?').get(categoryId, userId);
}

function addRegistration(db, categoryId, userId, username) {
  db.prepare('INSERT OR IGNORE INTO lobby_registrations (category_id, user_id, username, registered_at) VALUES (?, ?, ?, ?)')
    .run(categoryId, userId, username, new Date().toISOString());
}

function removeRegistration(db, categoryId, userId) {
  return db.prepare('DELETE FROM lobby_registrations WHERE category_id = ? AND user_id = ?').run(categoryId, userId).changes > 0;
}

function deleteLobbyData(db, categoryId) {
  db.prepare('DELETE FROM lobby_registrations WHERE category_id = ?').run(categoryId);
  db.prepare('DELETE FROM lobby_meta WHERE category_id = ?').run(categoryId);
}

// ==================== DISCORD ====================
function lobbyChannels(guild, category) {
  const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
  return [category, ...children];
}

function textChannelOf(guild, category) {
  return [...guild.channels.cache.values()].find(c => c.parentId === category.id && c.type === ChannelType.GuildText) || null;
}

// level: 'staff' | 'player' | 'none' (none rimuove l'overwrite dell'utente)
async function applyAccess(guild, category, member, level, reason, log) {
  const perms = level === 'staff' ? STAFF_PERMS : level === 'player' ? PLAYER_PERMS : null;
  for (const ch of lobbyChannels(guild, category)) {
    try {
      if (perms) await ch.permissionOverwrites.edit(member, perms, { reason });
      else await ch.permissionOverwrites.delete(member, reason);
    } catch (err) {
      log.warn(`Permessi lobby su ${ch.name}: ${err.message}`);
    }
  }
}

function buildLobby(guild, category, now, db) {
  const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
  const text = children.find(c => c.type === ChannelType.GuildText) || null;
  const voice = children.find(c => c.type === ChannelType.GuildVoice) || null;

  const meta = readMeta(db, category.id);
  const regs = listRegistrations(db, category.id);
  const excluded = new Set([guild.client.user.id, ...meta.staff.map(s => s.id), ...regs.map(r => r.user_id)]);
  const hostId = meta.hostId || findHostId(category, excluded);
  const hostMember = hostId ? guild.members.cache.get(hostId) : null;

  const voiceMembers = voice ? [...voice.members.values()] : [];
  const limit = voice?.userLimit || 0;
  const lastChatMs = text ? snowflakeToMs(text.lastMessageId) : null;
  const vStatus = computeVoiceStatus(voiceMembers.length, limit, lastChatMs, now);
  const rState = regState(meta, regs.length);

  return {
    id: category.id,
    name: category.name.slice(LOBBY_PREFIX.length),
    voice: { status: vStatus, label: VOICE_LABEL[vStatus], count: voiceMembers.length, limit },
    reg: { state: rState, label: REG_LABEL[rState], count: regs.length },
    slots: meta.slots,
    regOpen: meta.regOpen,
    host: hostId ? { id: hostId, name: hostMember ? hostMember.displayName : hostId } : null,
    members: voiceMembers.slice(0, 20).map(m => ({
      id: m.id,
      name: m.displayName,
      avatar: m.displayAvatarURL({ size: 32 })
    })),
    registrations: regs.map(r => ({ id: r.user_id, name: r.username })),
    staff: meta.staff,
    dropmap: meta.dropmap,
    code: meta.code,
    url: voice ? `https://discord.com/channels/${guild.id}/${voice.id}` : null,
    createdAt: snowflakeToMs(category.id),
    lastChatAt: lastChatMs
  };
}

// ==================== ROTTE ====================
function mountLobbies(app, deps) {
  const {
    client, storage, log, requireAuth, actionLimiter, parseOrFail, apiError,
    assertGuildAccess, canManageGuild, logMod, dashMod
  } = deps;

  const db = storage.db;
  db.exec(SCHEMA);

  const schemaLobbyCreate = z.object({
    name: z.string().min(1).max(30),
    userLimit: z.number().int().min(0).max(99).optional().default(0)
  });
  const schemaSettings = z.object({
    dropmap: z.string().max(60).nullable().optional(),
    code: z.string().max(30).nullable().optional(),
    slots: z.number().int().min(0).max(99).optional(),
    regOpen: z.boolean().optional()
  });
  const schemaUserId = z.object({ userId: z.string().regex(ID_RE, 'ID utente non valido') });
  const schemaAnnounce = z.object({ kind: z.enum(['code', 'dropmap', 'fill']) });

  // Carica la categoria lobby e verifica i permessi; in caso di errore risponde e ritorna null
  async function loadCategoryOrFail(req, res, categoryId) {
    if (!ID_RE.test(categoryId)) { res.status(400).json({ error: 'ID non valido' }); return null; }
    const category = await client.channels.fetch(categoryId).catch(() => null);
    if (!category || !category.guild || !isLobbyCategory(category)) {
      res.status(404).json({ error: 'Lobby non trovata' });
      return null;
    }
    if (!(await canManageGuild(req.session.user.id, category.guild))) {
      res.status(403).json({ error: 'Non hai i permessi su questo server' });
      return null;
    }
    return category;
  }

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
        .map(c => buildLobby(guild, c, now, db))
        .sort((a, b) => (VOICE_ORDER[a.voice.status] - VOICE_ORDER[b.voice.status]) || a.name.localeCompare(b.name));
      res.json({ guildName: guild.name, lobbies });
    } catch (e) { apiError(res, e, 'Errore mappa lobby'); }
  });

  // Ricerca membri del server (per iscrizioni e staff)
  app.get('/api/lobbies/:guildId/members/search', requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const q = String(req.query.q || '').trim().slice(0, 32);
    if (q.length < 2) return res.json([]);
    if (!(await assertGuildAccess(req, res, guildId))) return;
    try {
      const guild = client.guilds.cache.get(guildId);
      let found;
      try {
        found = [...(await guild.members.search({ query: q, limit: 10 })).values()];
      } catch {
        const needle = q.toLowerCase();
        found = [...guild.members.cache.values()].filter(m =>
          m.user.username.toLowerCase().includes(needle) || m.displayName.toLowerCase().includes(needle)
        );
      }
      res.json(found.filter(m => !m.user.bot).slice(0, 10).map(m => ({
        id: m.id,
        name: m.displayName,
        username: m.user.username,
        avatar: m.displayAvatarURL({ size: 32 })
      })));
    } catch (e) { apiError(res, e, 'Errore ricerca membri'); }
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

      saveMeta(db, category.id, guild.id, { hostId: hostMember ? hostMember.id : null });

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

  // Impostazioni: dropmap, codice, massimo iscritti, iscrizioni aperte/chiuse
  app.patch('/api/lobbies/:categoryId/settings', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaSettings, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;

    const patch = {};
    if (data.dropmap !== undefined) {
      const dm = data.dropmap ? data.dropmap.trim() : '';
      patch.dropmap = dm || null;
    }
    if (data.code !== undefined) {
      const code = data.code ? data.code.trim() : '';
      if (code && !CODE_RE.test(code)) {
        return res.status(400).json({ error: 'Codice non valido: solo lettere, numeri e trattini (max 30)' });
      }
      patch.code = code || null;
    }
    if (data.slots !== undefined) patch.slots = data.slots;
    if (data.regOpen !== undefined) patch.regOpen = data.regOpen;

    try {
      saveMeta(db, category.id, category.guild.id, patch);
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore impostazioni lobby'); }
  });

  // Iscrizione: aggiunge il membro e gli dà accesso a chat e vocale
  app.post('/api/lobbies/:categoryId/registrations', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaUserId, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const guild = category.guild;

    try {
      const meta = readMeta(db, category.id);
      const count = listRegistrations(db, category.id).length;
      if (!meta.regOpen) return res.status(409).json({ error: 'Iscrizioni chiuse' });
      if (meta.slots > 0 && count >= meta.slots) return res.status(409).json({ error: 'Lobby piena' });
      if (hasRegistration(db, category.id, data.userId)) return res.status(409).json({ error: 'Già iscritto' });

      const member = await guild.members.fetch(data.userId).catch(() => null);
      if (!member) return res.status(404).json({ error: 'Utente non nel server' });
      if (member.user.bot) return res.status(400).json({ error: 'Un bot non può iscriversi' });

      addRegistration(db, category.id, member.id, member.displayName);
      await applyAccess(guild, category, member, accessLevel(meta, member.id, true), 'Iscrizione lobby', log);

      await logMod(guild, {
        type: 'Lobby Iscrizione',
        title: 'Iscrizione Lobby',
        targetId: member.id,
        target: `${member.user.username} (${member.id})`,
        moderator: dashMod(req),
        channel: category.name
      });
      res.status(201).json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore iscrizione'); }
  });

  // Rimozione iscrizione: toglie l'accesso (lo staff mantiene i suoi permessi)
  app.delete('/api/lobbies/:categoryId/registrations/:userId', actionLimiter, requireAuth, async (req, res) => {
    if (!ID_RE.test(req.params.userId)) return res.status(400).json({ error: 'ID utente non valido' });
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    try {
      if (!removeRegistration(db, category.id, req.params.userId)) {
        return res.status(404).json({ error: 'Non iscritto' });
      }
      const meta = readMeta(db, category.id);
      const member = await category.guild.members.fetch(req.params.userId).catch(() => null);
      if (member) {
        await applyAccess(category.guild, category, member, accessLevel(meta, member.id, false), 'Rimozione iscrizione', log);
      }
      await logMod(category.guild, {
        type: 'Lobby Rimozione',
        title: 'Rimozione Iscritto',
        targetId: req.params.userId,
        target: req.params.userId,
        moderator: dashMod(req),
        channel: category.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore rimozione iscritto'); }
  });

  // Nomina staff: permessi di gestione messaggi nella chat della lobby
  app.post('/api/lobbies/:categoryId/staff', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaUserId, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const guild = category.guild;

    try {
      const meta = readMeta(db, category.id);
      if (meta.staff.some(s => s.id === data.userId)) return res.status(409).json({ error: 'Già staff di questa lobby' });
      const member = await guild.members.fetch(data.userId).catch(() => null);
      if (!member) return res.status(404).json({ error: 'Utente non nel server' });
      if (member.user.bot) return res.status(400).json({ error: 'Un bot non può essere staff' });

      saveMeta(db, category.id, guild.id, { staff: [...meta.staff, { id: member.id, name: member.displayName }] });
      await applyAccess(guild, category, member, 'staff', 'Staff lobby', log);

      await logMod(guild, {
        type: 'Lobby Staff',
        title: 'Staff Lobby Assegnato',
        targetId: member.id,
        target: `${member.user.username} (${member.id})`,
        moderator: dashMod(req),
        channel: category.name
      });
      res.status(201).json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore nomina staff'); }
  });

  // Rimozione staff: torna ad avere l'accesso di iscritto, se iscritto
  app.delete('/api/lobbies/:categoryId/staff/:userId', actionLimiter, requireAuth, async (req, res) => {
    if (!ID_RE.test(req.params.userId)) return res.status(400).json({ error: 'ID utente non valido' });
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const guild = category.guild;

    try {
      const meta = readMeta(db, category.id);
      if (!meta.staff.some(s => s.id === req.params.userId)) return res.status(404).json({ error: 'Non è staff di questa lobby' });
      const staff = meta.staff.filter(s => s.id !== req.params.userId);
      saveMeta(db, category.id, guild.id, { staff });

      const member = await guild.members.fetch(req.params.userId).catch(() => null);
      if (member) {
        const registered = hasRegistration(db, category.id, member.id);
        await applyAccess(guild, category, member, accessLevel({ staff }, member.id, registered), 'Rimozione staff lobby', log);
      }
      await logMod(guild, {
        type: 'Lobby Staff Rimosso',
        title: 'Staff Lobby Rimosso',
        targetId: req.params.userId,
        target: req.params.userId,
        moderator: dashMod(req),
        channel: category.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore rimozione staff'); }
  });

  // Pubblica in chat codice, dropmap o iscritti
  app.post('/api/lobbies/:categoryId/announce', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaAnnounce, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const guild = category.guild;

    try {
      const text = textChannelOf(guild, category);
      if (!text) return res.status(404).json({ error: 'Chat della lobby non trovata' });
      if (!text.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(403).json({ error: 'Il bot non può scrivere nella chat della lobby' });
      }

      const meta = readMeta(db, category.id);
      const regs = listRegistrations(db, category.id);
      let embed;
      if (data.kind === 'code') {
        if (!meta.code) return res.status(400).json({ error: 'Nessun codice impostato' });
        embed = lobbyEmbed('🔑 Codice lobby', `**Codice:** \`${meta.code}\``);
      } else if (data.kind === 'dropmap') {
        if (!meta.dropmap) return res.status(400).json({ error: 'Nessuna dropmap impostata' });
        embed = lobbyEmbed('🗺️ Dropmap', `**${meta.dropmap}**`);
      } else {
        const fill = meta.slots > 0 ? `${regs.length}/${meta.slots}` : `${regs.length}`;
        const list = regs.map(r => '• ' + r.username).join('\n') || '_nessun iscritto_';
        embed = lobbyEmbed('👥 Iscritti', `**Iscritti:** ${fill}\n${list}`);
      }

      await text.send({ embeds: [embed] });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore invio in chat'); }
  });

  // Eliminazione lobby: prima chat e vocale, poi la categoria, poi i dati
  app.delete('/api/lobbies/:categoryId', actionLimiter, requireAuth, async (req, res) => {
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    try {
      const guild = category.guild;
      const reason = `Lobby eliminata dalla dashboard (${req.session.user.username})`;
      const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
      for (const ch of children) {
        await ch.delete(reason).catch(err => log.warn(`Impossibile eliminare ${ch.name}: ${err.message}`));
      }
      await category.delete(reason);
      deleteLobbyData(db, category.id);

      await logMod(guild, {
        type: 'Lobby Eliminata',
        title: 'Lobby Eliminata',
        moderator: dashMod(req),
        channel: category.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore eliminazione lobby'); }
  });
}

// ==================== PAGINA ====================
function renderLobbiesContent() {
  return `
  <style>
    .lobby-toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
    .lobby-toolbar select { max-width: 320px; margin: 0; }
    .lobby-create { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
    .lobby-create input { width: auto; flex: 0 0 auto; margin: 0; max-width: 240px; }
    .lobby-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 14px; }
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
    .lobby-actions { display: flex; gap: 8px; margin-top: auto; flex-wrap: wrap; align-items: center; }
    .lobby-empty { color: #888; font-style: italic; padding: 30px; text-align: center; border: 1px dashed #333; border-radius: 10px; }
    .lb-fill { height: 8px; background: #1a1a1a; border: 1px solid #333; border-radius: 4px; overflow: hidden; }
    .lb-fill > div { height: 100%; background: #43b581; }
    .lb-fill.warn > div { background: #faa61a; }
    .lb-fill.full > div { background: #ed4245; }
    .lb-badges { display: flex; gap: 6px; flex-wrap: wrap; }
    .lb-tag { font-size: 11px; padding: 2px 8px; border-radius: 4px; background: #252525; color: #bbb; border: 1px solid #333; }
    .lb-tag.open { border-color: #43b581; color: #43b581; }
    .lb-tag.closed { border-color: #888; color: #888; }
    .lb-tag.full { border-color: #ed4245; color: #ed4245; }
    .lb-detail { background: #1a1a1a; border: 1px solid #333; border-radius: 10px; padding: 16px; margin-top: 16px; }
    .lb-detail h3 { font-size: 15px; margin-bottom: 10px; color: #bbb; }
    .lb-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    @media (max-width: 768px) { .lb-grid2 { grid-template-columns: 1fr; } }
    .lb-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 0; border-bottom: 1px solid #252525; font-size: 13px; }
    .lb-row > span { overflow: hidden; text-overflow: ellipsis; }
    .lb-code { font-family: monospace; background: #1a1a1a; padding: 2px 6px; border-radius: 4px; }
  </style>

  <div class="section">
    <h2>🗺️ Mappa Lobby</h2>
    <p style="color:#888;font-size:13px;margin-bottom:14px;">Iscrizioni, dropmap, codice, riempimento e staff di ogni lobby. Aggiornato ogni 5 secondi. Gli iscritti ricevono accesso a chat e vocale, lo staff può moderare la chat.</p>

    <div class="lobby-toolbar">
      <label style="font-size:13px;color:#888;">Server</label>
      <select id="lb-guild" onchange="lbGuildChanged()"></select>
      <span id="lb-updated" style="font-size:12px;color:#666;margin-left:auto;"></span>
    </div>

    <div class="lobby-create">
      <input id="lb-new-name" placeholder="Nome lobby (es. Custom 1)" maxlength="30">
      <input id="lb-new-limit" type="number" min="0" max="99" value="0" placeholder="Limite vocale (0 = libero)">
      <button onclick="lbCreate()">➕ Crea lobby</button>
    </div>

    <div id="lb-result"></div>
    <div id="lb-grid" class="lobby-grid" style="margin-top:12px;"><p class="lobby-empty">Caricamento...</p></div>
    <div id="lb-detail"></div>
  </div>

  <datalist id="lb-maps">
    <option value="Pleasant Park"></option>
    <option value="Retail Row"></option>
    <option value="Tilted Towers"></option>
    <option value="Salty Springs"></option>
    <option value="Lazy Links"></option>
    <option value="Dusty Depot"></option>
    <option value="Frenzy Farm"></option>
    <option value="Snobby Shores"></option>
    <option value="Lucky Landing"></option>
    <option value="Fatal Fields"></option>
  </datalist>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  const lbState = { lobbies: [], selected: null };

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

  function lbReport(r, okText) {
    if (r.ok) lbShow('<span class="success">✅ ' + esc(okText) + '</span>');
    else lbShow('<span class="error">❌ [' + r.status + '] ' + esc((r.data && r.data.error) || 'Errore') + '</span>');
  }

  async function lbSend(method, url, body) {
    const opts = { method: method };
    if (body !== undefined) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    const res = await apiFetch(url, opts);
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data: data };
  }

  function lbCurrent() { return lbState.lobbies.find(x => x.id === lbState.selected) || null; }

  function lbNeedSel() {
    const l = lbCurrent();
    if (!l) lbShow('<span class="error">❌ Seleziona una lobby</span>');
    return l;
  }

  function lbTile(l) {
    const v = l.voice;
    const regText = l.slots > 0 ? l.reg.count + '/' + l.slots + ' iscritti' : l.reg.count + ' iscritti';
    const pct = l.slots > 0 ? Math.min(100, Math.round(l.reg.count / l.slots * 100)) : 0;
    const fillCls = l.reg.state === 'full' ? 'full' : (pct >= 70 ? 'warn' : '');
    const fill = l.slots > 0 ? '<div class="lb-fill ' + fillCls + '"><div style="width:' + pct + '%"></div></div>' : '';
    const host = l.host ? esc(l.host.name) : '<span style="color:#666">nessun host</span>';
    const members = l.members.slice(0, 8).map(m => '<span class="lobby-member"><img src="' + esc(m.avatar) + '" alt="">' + esc(m.name) + '</span>').join('');
    const staff = l.staff.length ? l.staff.map(s => esc(s.name)).join(', ') : 'nessuno';
    const code = l.code
      ? '<span class="lb-code">' + esc(l.code) + '</span> <button class="secondary small" onclick="lbCopy(\\'' + esc(l.id) + '\\')">📋</button>'
      : '<span class="lobby-meta">non impostato</span>';
    const drop = l.dropmap ? esc(l.dropmap) : '<span class="lobby-meta">non impostata</span>';
    const open = l.url ? '<a href="' + esc(l.url) + '" target="_blank" rel="noopener"><button class="secondary small">🔗 Apri</button></a>' : '';
    return '<div class="lobby-tile st-' + esc(v.status) + '">' +
      '<div class="lobby-head"><span class="lobby-name">' + esc(l.name) + '</span>' +
      '<span class="lobby-badge st-' + esc(v.status) + '">' + esc(v.label) + '</span></div>' +
      '<div class="lb-badges"><span class="lb-tag ' + esc(l.reg.state) + '">' + esc(l.reg.label) + '</span><span class="lb-tag">' + esc(v.count) + ' in vocale</span></div>' +
      fill +
      '<div class="lobby-meta">👥 ' + esc(regText) + '</div>' +
      '<div class="lobby-meta">👑 Host: ' + host + '</div>' +
      '<div class="lobby-meta">🗺️ Dropmap: ' + drop + '</div>' +
      '<div class="lobby-meta">🔑 Codice: ' + code + '</div>' +
      '<div class="lobby-meta">🛡️ Staff: ' + staff + '</div>' +
      '<div class="lobby-members">' + (members || '<span class="lobby-meta">vocale vuoto</span>') + '</div>' +
      '<div class="lobby-actions">' +
        '<button class="small" onclick="lbOpen(\\'' + esc(l.id) + '\\')">⚙️ Gestisci</button>' + open +
        '<button class="danger small" onclick="lbDelete(\\'' + esc(l.id) + '\\')">🗑️</button>' +
      '</div>' +
    '</div>';
  }

  function lbRenderDetail() {
    const box = document.getElementById('lb-detail');
    const l = lbCurrent();
    if (!l) { box.innerHTML = ''; lbState.selected = null; return; }

    const regsHtml = l.registrations.length
      ? l.registrations.map(r => '<div class="lb-row"><span>' + esc(r.name) + '</span><button class="danger small" onclick="lbUnregister(\\'' + esc(r.id) + '\\')">Rimuovi</button></div>').join('')
      : '<p class="lobby-meta">Nessun iscritto.</p>';
    const staffHtml = l.staff.length
      ? l.staff.map(s => '<div class="lb-row"><span>🛡️ ' + esc(s.name) + '</span><button class="danger small" onclick="lbRemoveStaff(\\'' + esc(s.id) + '\\')">Rimuovi</button></div>').join('')
      : '<p class="lobby-meta">Nessuno staff assegnato.</p>';

    box.innerHTML =
      '<div class="lb-detail">' +
        '<h3>⚙️ ' + esc(l.name) + '</h3>' +
        '<div class="lb-grid2">' +
          '<div>' +
            '<h3>Impostazioni</h3>' +
            '<label style="font-size:13px;color:#888;">Dropmap</label>' +
            '<input id="lbd-dropmap" list="lb-maps" maxlength="60" value="' + esc(l.dropmap || '') + '" placeholder="Es. Pleasant Park">' +
            '<label style="font-size:13px;color:#888;">Codice lobby</label>' +
            '<input id="lbd-code" maxlength="30" value="' + esc(l.code || '') + '" placeholder="Es. CUSTOM-01">' +
            '<label style="font-size:13px;color:#888;">Max iscritti (0 = illimitato)</label>' +
            '<input id="lbd-slots" type="number" min="0" max="99" value="' + esc(l.slots) + '">' +
            '<label style="font-size:13px;color:#888;">Iscrizioni</label>' +
            '<select id="lbd-regopen"><option value="1"' + (l.regOpen ? ' selected' : '') + '>Aperte</option><option value="0"' + (l.regOpen ? '' : ' selected') + '>Chiuse</option></select>' +
            '<button onclick="lbSave()">💾 Salva</button>' +
            '<h3 style="margin-top:16px;">📣 Pubblica in chat</h3>' +
            '<div class="form-row">' +
              '<button class="secondary small" onclick="lbAnnounce(\\'code\\')">🔑 Codice</button>' +
              '<button class="secondary small" onclick="lbAnnounce(\\'dropmap\\')">🗺️ Dropmap</button>' +
              '<button class="secondary small" onclick="lbAnnounce(\\'fill\\')">👥 Iscritti</button>' +
            '</div>' +
          '</div>' +
          '<div>' +
            '<h3>Iscrizioni (' + l.reg.count + ')</h3>' + regsHtml +
            '<h3 style="margin-top:14px;">Cerca membro</h3>' +
            '<div class="form-row"><input id="lbd-q" placeholder="Nome o username (min 2 caratteri)" maxlength="32"><button class="secondary" onclick="lbSearch()">🔍 Cerca</button></div>' +
            '<div id="lbd-results"></div>' +
            '<h3 style="margin-top:14px;">Staff della lobby</h3>' + staffHtml +
          '</div>' +
        '</div>' +
      '</div>';
  }

  async function lbLoad(redraw) {
    const guildId = document.getElementById('lb-guild').value;
    const grid = document.getElementById('lb-grid');
    if (!guildId) {
      lbState.lobbies = [];
      grid.innerHTML = '<p class="lobby-empty">Nessun server disponibile.</p>';
      lbRenderDetail();
      return;
    }
    const res = await apiFetch('/api/lobbies/' + encodeURIComponent(guildId));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { grid.innerHTML = '<p class="lobby-empty">❌ ' + esc(data.error || 'Errore') + '</p>'; return; }
    lbState.lobbies = data.lobbies || [];
    grid.innerHTML = lbState.lobbies.length
      ? lbState.lobbies.map(lbTile).join('')
      : '<p class="lobby-empty">Nessuna lobby. Creane una dal pannello sopra.</p>';
    document.getElementById('lb-updated').textContent = 'Aggiornato alle ' + new Date().toLocaleTimeString('it-IT');
    if (redraw || (lbState.selected && !lbCurrent())) lbRenderDetail();
  }

  function lbGuildChanged() { lbState.selected = null; lbLoad(true); }

  function lbOpen(id) {
    lbState.selected = id;
    lbRenderDetail();
    document.getElementById('lb-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function lbCreate() {
    const guildId = document.getElementById('lb-guild').value;
    const name = document.getElementById('lb-new-name').value.trim();
    const limit = parseInt(document.getElementById('lb-new-limit').value, 10) || 0;
    if (!guildId) return lbShow('<span class="error">❌ Seleziona un server</span>');
    if (!name) return lbShow('<span class="error">❌ Inserisci un nome</span>');
    const r = await lbSend('POST', '/api/lobbies/' + encodeURIComponent(guildId), { name: name, userLimit: limit });
    if (r.ok) document.getElementById('lb-new-name').value = '';
    lbReport(r, 'Lobby creata');
    lbLoad(false);
  }

  async function lbDelete(id) {
    if (!confirm('Eliminare questa lobby? Verranno cancellati anche chat, vocale e iscrizioni.')) return;
    const r = await lbSend('DELETE', '/api/lobbies/' + encodeURIComponent(id));
    if (lbState.selected === id) lbState.selected = null;
    lbReport(r, 'Lobby eliminata');
    lbLoad(true);
  }

  async function lbSave() {
    const l = lbNeedSel();
    if (!l) return;
    const body = {
      dropmap: document.getElementById('lbd-dropmap').value.trim(),
      code: document.getElementById('lbd-code').value.trim(),
      slots: parseInt(document.getElementById('lbd-slots').value, 10) || 0,
      regOpen: document.getElementById('lbd-regopen').value === '1'
    };
    const r = await lbSend('PATCH', '/api/lobbies/' + encodeURIComponent(l.id) + '/settings', body);
    lbReport(r, 'Impostazioni salvate');
    lbLoad(true);
  }

  async function lbAnnounce(kind) {
    const l = lbNeedSel();
    if (!l) return;
    const r = await lbSend('POST', '/api/lobbies/' + encodeURIComponent(l.id) + '/announce', { kind: kind });
    lbReport(r, 'Messaggio inviato in chat');
  }

  async function lbSearch() {
    const l = lbNeedSel();
    if (!l) return;
    const guildId = document.getElementById('lb-guild').value;
    const q = document.getElementById('lbd-q').value.trim();
    const out = document.getElementById('lbd-results');
    if (q.length < 2) { out.innerHTML = '<p class="lobby-meta">Scrivi almeno 2 caratteri.</p>'; return; }
    const res = await apiFetch('/api/lobbies/' + encodeURIComponent(guildId) + '/members/search?q=' + encodeURIComponent(q));
    const data = await res.json().catch(() => null);
    if (!res.ok) { out.innerHTML = '<p class="error">❌ ' + esc((data && data.error) || 'Errore') + '</p>'; return; }
    const list = Array.isArray(data) ? data : [];
    const regIds = l.registrations.map(r => r.id);
    const staffIds = l.staff.map(s => s.id);
    out.innerHTML = list.length
      ? list.map(m => {
          const inReg = regIds.indexOf(m.id) !== -1;
          const inStaff = staffIds.indexOf(m.id) !== -1;
          return '<div class="lb-row"><span><img src="' + esc(m.avatar) + '" alt="" style="width:18px;height:18px;border-radius:50%;vertical-align:middle;"> ' +
            esc(m.name) + ' <small style="color:#666">@' + esc(m.username) + '</small></span><span style="display:flex;gap:6px;">' +
            (inReg ? '<span class="lb-tag open">iscritto</span>' : '<button class="secondary small" onclick="lbRegister(\\'' + esc(m.id) + '\\')">➕ Iscrivi</button>') +
            (inStaff ? '' : '<button class="secondary small" onclick="lbAddStaff(\\'' + esc(m.id) + '\\')">🛡️ Staff</button>') +
            '</span></div>';
        }).join('')
      : '<p class="lobby-meta">Nessun risultato.</p>';
  }

  async function lbRegister(uid) {
    const l = lbNeedSel();
    if (!l) return;
    const r = await lbSend('POST', '/api/lobbies/' + encodeURIComponent(l.id) + '/registrations', { userId: uid });
    lbReport(r, 'Iscritto');
    lbLoad(true);
  }

  async function lbUnregister(uid) {
    const l = lbNeedSel();
    if (!l) return;
    const r = await lbSend('DELETE', '/api/lobbies/' + encodeURIComponent(l.id) + '/registrations/' + encodeURIComponent(uid));
    lbReport(r, 'Iscrizione rimossa');
    lbLoad(true);
  }

  async function lbAddStaff(uid) {
    const l = lbNeedSel();
    if (!l) return;
    const r = await lbSend('POST', '/api/lobbies/' + encodeURIComponent(l.id) + '/staff', { userId: uid });
    lbReport(r, 'Staff nominato');
    lbLoad(true);
  }

  async function lbRemoveStaff(uid) {
    const l = lbNeedSel();
    if (!l) return;
    const r = await lbSend('DELETE', '/api/lobbies/' + encodeURIComponent(l.id) + '/staff/' + encodeURIComponent(uid));
    lbReport(r, 'Staff rimosso');
    lbLoad(true);
  }

  function lbCopy(id) {
    const l = lbState.lobbies.find(x => x.id === id);
    if (!l || !l.code) return;
    if (!navigator.clipboard) { lbShow('<span class="error">❌ Copia non disponibile</span>'); return; }
    navigator.clipboard.writeText(l.code)
      .then(() => lbShow('<span class="success">✅ Codice copiato</span>'))
      .catch(() => lbShow('<span class="error">❌ Copia non riuscita</span>'));
  }

  async function lbLoadGuilds() {
    const res = await apiFetch('/api/guilds');
    const guilds = await res.json().catch(() => []);
    document.getElementById('lb-guild').innerHTML = guilds.length
      ? guilds.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('')
      : '<option value="">Nessun server</option>';
    await lbLoad(true);
    setInterval(() => lbLoad(false), 5000);
  }

  lbLoadGuilds();
  </script>`;
}

module.exports = { mountLobbies, renderLobbiesContent };
