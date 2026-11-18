// web.js — Dashboard web (sicurezza + azioni di moderazione allineate al bot)
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const {
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ChannelType,
  PermissionsBitField
} = require('discord.js');

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { doubleCsrf } = require('csrf-csrf');
const { z } = require('zod');

// IMPORT LOBBY
const { mountLobbies, renderLobbiesContent } = require('./lobbies');

function createWebServer({ storage, client, log, botStartTime, buildTranscriptHtml, modLog: modLogFn }) {
  const app = express();
  const PORT = parseInt(process.env.PORT) || 3000;
  const HOST = process.env.WEB_HOST || '0.0.0.0';
  const IS_PROD = process.env.NODE_ENV === 'production';

  app.set('trust proxy', parseInt(process.env.TRUST_PROXY, 10) || 1);
  app.disable('x-powered-by');

  const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
  const CLIENT_SECRET = (process.env.DISCORD_CLIENT_SECRET || '').trim();
  const DASHBOARD_URL = (process.env.DASHBOARD_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
  if (IS_PROD && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
    throw new Error('SESSION_SECRET mancante o troppo corto (minimo 32 caratteri) in produzione');
  }
  const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-non-usare-in-produzione';
  const ENV_ADMIN_IDS = (process.env.DASHBOARD_ADMIN_IDS || '')
    .split(',')
    .map(s => s.trim().replace(/^["']|["']$/g, ''))
    .filter(Boolean);
  const BLACKLIST_ADMIN_SERVERS = (process.env.BLACKLIST_ADMIN_SERVERS || '').split(',').map(s => s.trim()).filter(Boolean);
  const DASHBOARD_ROLES = ['Senior Admin'];
  const DASHBOARD_FEATURES = [
    'overview', 'moderation', 'global_blacklist', 'tickets', 'settings',
    'analytics', 'communications', 'lobbies', 'audit'
  ];

  const AUTH_CACHE_TTL = 60 * 1000;
  const authCache = new Map();

  async function getDashboardAccess(userId) {
    const now = Date.now();
    const cached = authCache.get(userId);
    if (cached && cached.expires > now) return cached;

    const isEnvAdministrator = ENV_ADMIN_IDS.includes(userId);
    const permissions = new Set(isEnvAdministrator ? DASHBOARD_FEATURES : []);
    const guildPermissions = new Map();
    let manager = isEnvAdministrator;
    if (isEnvAdministrator) {
      const access = { authorized: true, manager: true, permissions, guildPermissions, expires: now + AUTH_CACHE_TTL };
      authCache.set(userId, access);
      return access;
    }

    for (const guild of client.guilds.cache.values()) {
      const member = await guild.members.fetch(userId).catch(err => {
        log.err('dashboard access member lookup', err);
        return null;
      });
      if (!member) continue;

      const granted = new Set();
      if (member.roles.cache.some(role => DASHBOARD_ROLES.includes(role.name))) {
        manager = true;
        DASHBOARD_FEATURES.forEach(feature => granted.add(feature));
      } else {
        for (const grant of storage.getDashboardRolePermissions(guild.id)) {
          if (!member.roles.cache.has(grant.role_id)) continue;
          for (const feature of grant.permissions) {
            if (DASHBOARD_FEATURES.includes(feature)) granted.add(feature);
          }
        }
      }

      if (granted.size) {
        guildPermissions.set(guild.id, granted);
        granted.forEach(feature => permissions.add(feature));
      }
    }

    const access = {
      authorized: isEnvAdministrator || permissions.size > 0,
      manager,
      permissions,
      guildPermissions,
      expires: now + AUTH_CACHE_TTL
    };
    authCache.set(userId, access);
    return access;
  }

  // ==================== AUTORIZZAZIONE PER SERVER ====================
  async function canManageGuild(userId, guild, feature) {
    if (ENV_ADMIN_IDS.includes(userId)) return true;
    const access = await getDashboardAccess(userId);
    const granted = access.guildPermissions.get(guild.id);
    return !!feature && !!granted && granted.has(feature);
  }

  async function canManageDashboardRolesInGuild(userId, guild) {
    if (ENV_ADMIN_IDS.includes(userId)) return true;
    const member = await guild.members.fetch(userId).catch(err => {
      log.err('dashboard role manager lookup', err);
      return null;
    });
    return !!member && member.roles.cache.some(role => DASHBOARD_ROLES.includes(role.name));
  }

  async function allowedGuildIds(userId, feature) {
    const ids = new Set();
    if (ENV_ADMIN_IDS.includes(userId)) {
      for (const guild of client.guilds.cache.values()) ids.add(guild.id);
      return ids;
    }
    const access = await getDashboardAccess(userId);
    for (const g of client.guilds.cache.values()) {
      const granted = access.guildPermissions.get(g.id);
      if (granted && (feature ? granted.has(feature) : granted.size > 0)) ids.add(g.id);
    }
    return ids;
  }

  function dashboardLandingPath(access) {
    const routes = [
      ['overview', '/dashboard'],
      ['moderation', '/modlogs'],
      ['tickets', '/tickets'],
      ['settings', '/config'],
      ['analytics', '/charts'],
      ['communications', '/messages'],
      ['lobbies', '/lobbies'],
      ['audit', '/access-logs'],
      ['global_blacklist', '/dashboard']
    ];
    const first = routes.find(([feature]) => access.permissions.has(feature));
    return first ? first[1] : '/dashboard';
  }

  async function assertGuildAccess(req, res, guildId) {
    const guild = client.guilds.cache.get(guildId);
    if (!guild) { res.status(404).json({ error: 'Server non trovato' }); return false; }
    const feature = requiredDashboardAccess(req.path);
    if (!feature || feature === 'dashboard' || feature === 'manager' ||
        !(await canManageGuild(req.session.user.id, guild, feature))) {
      res.status(403).json({ error: 'Non hai i permessi su questo server' });
      return false;
    }
    return true;
  }

  // Note dei soli server autorizzati, lette direttamente dal DB (nessun limite a 500)
  function notesForGuilds(allowed, limit = 1000) {
    const ids = [...allowed];
    if (!ids.length) return [];
    const placeholders = ids.map(() => '?').join(',');
    return storage.db
      .prepare(`SELECT * FROM member_notes WHERE guild_id IN (${placeholders}) ORDER BY id DESC LIMIT ?`)
      .all(...ids, limit);
  }

  function isEnvAdmin(userId) {
    return ENV_ADMIN_IDS.includes(userId);
  }

  // I log scritti prima della colonna guild_id hanno il campo vuoto: vanno contati lo stesso.
  function legacyGuildSql(ids) {
    if (!ids.length) return { sql: '1=0', params: [] };
    const ph = ids.map(() => '?').join(',');
    return { sql: `(guild_id IN (${ph}) OR guild_id IS NULL OR guild_id = '')`, params: ids };
  }

  function logsForViewer(userId, allowed, limit = 500) {
    if (isEnvAdmin(userId)) return storage.getAllLogs(limit);
    const scope = legacyGuildSql([...allowed]);
    if (scope.sql === '1=0') return [];
    return storage.db.prepare(
      `SELECT * FROM mod_logs WHERE ${scope.sql} ORDER BY id DESC LIMIT ?`
    ).all(...scope.params, limit);
  }

  function logsForUserViewer(actorId, targetId, allowed) {
    if (isEnvAdmin(actorId)) return storage.getLogsForUser(targetId);
    const scope = legacyGuildSql([...allowed]);
    if (scope.sql === '1=0') return [];
    return storage.db.prepare(
      `SELECT * FROM mod_logs WHERE target_id = ? AND ${scope.sql} ORDER BY id DESC`
    ).all(targetId, ...scope.params);
  }

  function transcriptsForViewer(userId, allowed) {
    if (isEnvAdmin(userId)) return storage.getAllTranscripts ? storage.getAllTranscripts() : [];
    const scope = legacyGuildSql([...allowed]);
    if (scope.sql === '1=0') return [];
    return storage.db.prepare(
      `SELECT id, channel_id, channel_name, user_id, claimed_by, priority, created_at
       FROM ticket_transcripts WHERE ${scope.sql} ORDER BY id DESC LIMIT 100`
    ).all(...scope.params);
  }

  function countWhereGuilds(table, allowed, userId) {
    if (isEnvAdmin(userId)) {
      const row = storage.db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get();
      return row?.c || 0;
    }
    const scope = legacyGuildSql([...allowed]);
    if (scope.sql === '1=0') return 0;
    const row = storage.db.prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE ${scope.sql}`).get(...scope.params);
    return row?.c || 0;
  }

  // ==================== HELPER AZIONI (allineati al bot) ====================
  function dashActor(req) {
    const u = req.session.user;
    return { id: u.id, name: u.username, label: `${u.username} (${u.id}) [dashboard]` };
  }
  function dashMod(req) {
    return dashActor(req).label;
  }

  // Scrive nel DB e, se disponibile, nel canale mod-log (stessa logica del bot)
  async function logMod(guild, data) {
    const payload = { ...data, guildId: data.guildId || guild?.id || null };
    try {
      if (typeof modLogFn === 'function') await modLogFn(guild, payload);
      else storage.saveLog(payload);
    } catch (err) { log.err('logMod', err); }
  }

  async function dmUser(userId, payload) {
    try {
      const user = await client.users.fetch(userId).catch(() => null);
      if (!user) return false;
      await user.send(payload);
      return true;
    } catch { return false; }
  }

  // Il dashboard agisce con i permessi gerarchici dell'utente loggato
  async function actorCanActOn(guild, actorId, target) {
    if (ENV_ADMIN_IDS.includes(actorId)) return true;
    const actor = await guild.members.fetch(actorId).catch(() => null);
    if (!actor) return false;
    if (guild.ownerId === actor.id) return true;
    if (target.id === guild.ownerId) return false;
    return actor.roles.highest.position > target.roles.highest.position;
  }

  async function actorCanGrantRole(guild, actorId, role) {
    if (ENV_ADMIN_IDS.includes(actorId)) return true;
    const actor = await guild.members.fetch(actorId).catch(() => null);
    if (!actor) return false;
    if (guild.ownerId === actor.id) return true;
    return role.position < actor.roles.highest.position;
  }

  async function actorHas(guild, actorId, flag) {
    if (ENV_ADMIN_IDS.includes(actorId)) return true;
    const actor = await guild.members.fetch(actorId).catch(() => null);
    return !!actor && actor.permissions.has(flag);
  }

  async function canUseGlobalBlacklist(userId) {
    if (ENV_ADMIN_IDS.includes(userId)) return true;
    const access = await getDashboardAccess(userId);
    if (!access.manager && !access.permissions.has('global_blacklist')) return false;
    if (!BLACKLIST_ADMIN_SERVERS.length) return true;
    for (const id of BLACKLIST_ADMIN_SERVERS) {
      const guild = client.guilds.cache.get(id);
      if (guild && await canManageGuild(userId, guild, 'global_blacklist')) return true;
    }
    return false;
  }

  async function createSingleUseInvite(guild, reason) {
    const botMember = guild.members.me;
    const ch = guild.channels.cache.find(c =>
      c.type === ChannelType.GuildText &&
      c.permissionsFor(botMember)?.has(PermissionsBitField.Flags.CreateInstantInvite)
    );
    if (!ch) return null;
    try {
      const invite = await ch.createInvite({ maxUses: 1, maxAge: 3600, unique: true, reason });
      return invite.url;
    } catch (e) {
      log.warn(`Impossibile creare invito: ${e.message}`);
      return null;
    }
  }

  // Sban + invito monouso + DM con bottone (identico al comando -unban del bot)
  async function unbanWithInvite(guild, targetId, moderatorName) {
    await guild.bans.remove(targetId, `Sbannato dalla dashboard (${moderatorName})`);
    const inviteUrl = await createSingleUseInvite(guild, `Invito per utente sbannato (${targetId})`);
    const description = inviteUrl
      ? `Sei stato sbannato dal server **${guild.name}**.\n\nUsa il pulsante qui sotto per rientrare. L'invito è valido per 1 utilizzo e scade tra 60 minuti.`
      : `Sei stato sbannato dal server **${guild.name}**.`;
    const payload = { embeds: [makeEmbed('Sei stato sbannato', description, 0x00FF00)] };
    if (inviteUrl) {
      payload.components = [
        new ActionRowBuilder().addComponents(
          new ButtonBuilder().setLabel('Rientra nel server').setStyle(ButtonStyle.Link).setURL(inviteUrl)
        )
      ];
    }
    await dmUser(targetId, payload);
    return inviteUrl;
  }

  // Blacklist globale: DB + DM + ban su tutti i server dove l'utente è presente (come il bot)
  async function blacklistAddFull(targetId, username, reason, mod) {
    storage.addToBlacklist(targetId, username, reason, mod.id, mod.name);
    await dmUser(targetId, { embeds: [makeEmbed('Aggiunto alla Blacklist Globale', `Sei stato aggiunto alla blacklist globale.\n**Motivo:** ${reason}`, 0x8B0000)] });
    let bannedIn = 0;
    for (const guild of client.guilds.cache.values()) {
      try {
        const member = await guild.members.fetch(targetId).catch(() => null);
        if (!member) continue;
        await guild.members.ban(targetId, { reason: `[BLACKLIST GLOBALE] ${reason}` });
        await logMod(guild, {
          type: 'Blacklist Ban', title: 'Ban Globale (Blacklist)', targetId,
          target: `${username} (${targetId})`, moderator: mod.label, reason
        });
        bannedIn++;
      } catch (err) { log.err(`ban ${guild.name}`, err); }
    }
    return bannedIn;
  }

  // Rimozione dalla blacklist: DB + unban su tutti i server + DM (come il bot)
  async function blacklistRemoveFull(targetId, mod) {
    const entry = storage.getBlacklistEntry(targetId);
    storage.removeFromBlacklist(targetId);
    const targetLabel = `${entry?.username || targetId} (${targetId})`;
    let unbannedIn = 0;
    for (const guild of client.guilds.cache.values()) {
      try {
        const ban = await guild.bans.fetch(targetId).catch(() => null);
        if (!ban) continue;
        await guild.bans.remove(targetId, `[BLACKLIST RIMOSSA] ${mod.name}`);
        await logMod(guild, {
          type: 'Blacklist Unban', title: 'Unban Globale (Blacklist Rimossa)', targetId,
          target: targetLabel, moderator: mod.label, reason: 'Blacklist globale rimossa'
        });
        unbannedIn++;
      } catch (err) { log.err(`unban ${guild.name}`, err); }
    }
    await dmUser(targetId, { embeds: [makeEmbed('Rimosso dalla Blacklist Globale', 'Sei stato rimosso dalla blacklist globale.', 0x00FF00)] });
    return unbannedIn;
  }

  // Recupera un canale ticket e verifica i permessi; in caso di errore risponde e ritorna null
  async function ticketChannelOrFail(req, res) {
    const channelId = req.params.channelId;
    if (!/^\d{17,20}$/.test(channelId)) { res.status(400).json({ error: 'ID canale non valido' }); return null; }
    const ch = await client.channels.fetch(channelId).catch(() => null);
    if (!ch || !ch.guild) { res.status(404).json({ error: 'Canale non trovato' }); return null; }
    if (!ch.name?.startsWith('ticket-')) { res.status(400).json({ error: 'Non è un canale ticket' }); return null; }
    if (!(await canManageGuild(req.session.user.id, ch.guild, 'tickets'))) {
      res.status(403).json({ error: 'Non hai i permessi su questo server' });
      return null;
    }
    return ch;
  }

  // ==================== HELMET ====================
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        'script-src-attr': ["'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https://cdn.discordapp.com"],
        'connect-src': ["'self'", "https://cdn.jsdelivr.net"],
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

  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));

  // ==================== COOKIE PARSER ====================
  app.use(cookieParser());

  // ==================== SESSION ====================
  const SESSION_DIR = path.join(__dirname, 'data', 'sessions');
  try { if (!fs.existsSync(SESSION_DIR)) fs.mkdirSync(SESSION_DIR, { recursive: true }); } catch {}

  app.use(session({
    store: new FileStore({ path: SESSION_DIR, ttl: 7 * 24 * 60 * 60, retries: 0 }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: IS_PROD,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));

  // ==================== CSRF ====================
  const CSRF_SECRET = process.env.CSRF_SECRET || SESSION_SECRET;

  const {
    doubleCsrfProtection,
    generateCsrfToken
  } = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier: (req) => {
      if (!req.sessionID) {
        throw new Error('Sessione non inizializzata: req.sessionID mancante');
      }
      return req.sessionID;
    },
    cookieName: 'x-csrf-token',
    cookieOptions: {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
      path: '/'
    },
    size: 32,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    getCsrfTokenFromRequest: (req) => {
      const h = req.headers['x-csrf-token'];
      const b = req.body && req.body._csrf;
      return h ? String(h) : (b ? String(b) : '');
    }
  });

  app.use(doubleCsrfProtection);

  app.get('/api/csrf-token', (req, res) => {
    if (!req.sessionID) {
      return res.status(500).json({ error: 'Sessione non inizializzata (sessionID mancante)' });
    }
    req.session.save((err) => {
      if (err) { log.err('csrf session save', err); return res.status(500).json({ error: 'Errore sessione' }); }
      try {
        const token = generateCsrfToken(req, res);
        if (!token) return res.status(500).json({ error: 'Token CSRF vuoto' });
        res.json({ csrfToken: token });
      } catch (e) {
        log.err('csrf-token', e);
        res.status(500).json({ error: 'Errore CSRF' });
      }
    });
  });

  // ==================== RATE LIMIT ====================
  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Troppe richieste di login, riprova più tardi.' } });
  const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false, message: { error: 'Troppe richieste, riprova più tardi.' } });
  const actionLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Troppe azioni distruttive, riprova tra un minuto.' } });
  const messageLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Troppi messaggi inviati, riprova tra un minuto.' } });

  app.use('/auth', authLimiter);
  app.use('/api', apiLimiter);

  // ==================== ZOD ====================
  const userIdSchema = z.string().regex(/^\d{17,20}$/, 'ID utente non valido');
  const guildIdSchema = z.string().regex(/^\d{17,20}$/, 'ID server non valido');
  const channelIdSchema = z.string().regex(/^\d{17,20}$/, 'ID canale non valido');
  const roleIdSchema = z.string().regex(/^\d{17,20}$/, 'ID ruolo non valido');
  const reasonSchema = z.string().max(512).optional().default('');

  const schemaBlacklistAdd = z.object({ userId: userIdSchema, username: z.string().min(1).max(64), reason: z.string().min(1).max(500) });
  const schemaBulkDelete = z.object({ ids: z.array(z.union([z.string(), z.number()])).min(1).max(500) });
  const schemaConfig = z.object({ autoroleId: z.string().regex(/^\d{17,20}$/).nullable().optional(), logChannelId: z.string().regex(/^\d{17,20}$/).nullable().optional() });
  const schemaWelcome = z.object({ channelId: z.string().regex(/^\d{17,20}$/).nullable().optional(), message: z.string().max(2000).nullable().optional(), embedEnabled: z.boolean().optional() });
  const schemaCommandAdd = z.object({
    name: z.string().min(1).max(50).regex(/^[a-z0-9_-]+$/i),
    response: z.string().min(1).max(4096)
  }).refine(d => !/@(everyone|here)\b/i.test(d.response), { message: 'La risposta non può menzionare everyone o here' });
  const schemaPublicResource = z.object({
    title: z.string().trim().min(1).max(100),
    category: z.string().trim().max(40).optional().default('Generale').transform(value => value || 'Generale'),
    description: z.string().trim().max(500).optional().default(''),
    url: z.string().trim().url().max(2048).refine(value => /^https?:\/\//i.test(value), {
      message: 'Il link deve iniziare con http:// o https://'
    })
  });
  const schemaGuildResourceOverride = z.object({
    title: z.string().trim().min(1).max(100),
    category: z.string().trim().max(40).optional().default('Server Discord').transform(value => value || 'Server Discord'),
    description: z.string().trim().max(500).optional().default(''),
    url: z.union([
      z.literal(''),
      z.string().trim().url().max(2048).refine(value => /^https?:\/\//i.test(value), {
        message: 'Il link deve iniziare con http:// o https://'
      })
    ]).optional().default(''),
    inviteUrl: z.union([
      z.literal(''),
      z.string().trim().url().max(2048).refine(value => {
        const invite = new URL(value);
        return invite.protocol === 'https:' && (
          (invite.hostname === 'discord.gg' && /^\/[a-z0-9_-]+\/?$/i.test(invite.pathname)) ||
          (['discord.com', 'discordapp.com'].includes(invite.hostname) && /^\/invite\/[a-z0-9_-]+\/?$/i.test(invite.pathname))
        );
      }, { message: 'Inserisci un link invito Discord valido' })
    ]).optional().default('')
  });
  const schemaMessagesSend = z.object({
    channelId: z.string().regex(/^\d{17,20}$/),
    content: z.string().max(2000).optional(),
    allowMentions: z.boolean().optional().default(true),
    allowMassMentions: z.boolean().optional().default(false),
    embed: z.object({
      title: z.string().max(256).optional(),
      description: z.string().max(4096).optional(),
      color: z.string().max(20).optional(),
      image: z.string().url().max(500).optional(),
      thumbnail: z.string().url().max(500).optional(),
      footer: z.string().max(2048).optional()
    }).optional()
  }).refine(d => (d.content && d.content.length > 0) || (d.embed && (d.embed.title || d.embed.description)), { message: 'Testo o embed obbligatorio' });
  const schemaUserAction = z.object({
    action: z.enum(['kick', 'ban', 'unban']),
    userId: userIdSchema,
    guildId: guildIdSchema,
    reason: z.string().max(512).optional().default('')
  });
  const schemaReminder = z.object({
    guildId: guildIdSchema,
    channelId: z.string().regex(/^\d{17,20}$/),
    content: z.string().min(1).max(500),
    hours: z.number().int().min(0).max(720),
    minutes: z.number().int().min(0).max(59)
  });
  const schemaModWarn = z.object({ guildId: guildIdSchema, userId: userIdSchema, reason: reasonSchema });
  const schemaModTimeout = z.object({ guildId: guildIdSchema, userId: userIdSchema, seconds: z.number().int().min(1).max(2419200), reason: reasonSchema });
  const schemaModClear = z.object({ guildId: guildIdSchema, channelId: channelIdSchema, amount: z.number().int().min(1).max(100) });
  const schemaModLock = z.object({ guildId: guildIdSchema, channelId: channelIdSchema, reason: reasonSchema });
  const schemaModUnlock = z.object({ guildId: guildIdSchema, channelId: channelIdSchema });
  const schemaModInvite = z.object({ guildId: guildIdSchema, channelId: channelIdSchema, userId: userIdSchema });
  const schemaModRole = z.object({ guildId: guildIdSchema, userId: userIdSchema, roleId: roleIdSchema, action: z.enum(['add', 'remove']) });
  const schemaNoteAdd = z.object({ guildId: guildIdSchema, userId: userIdSchema, content: z.string().min(2).max(1000) });
  const schemaTicketPriority = z.object({ priority: z.enum(['low', 'med', 'high', 'urgent']) });
  const schemaDashboardRolePermissions = z.object({
    permissions: z.array(z.enum(DASHBOARD_FEATURES)).max(DASHBOARD_FEATURES.length)
  });

  function parseOrFail(schema, data, res) {
    const r = schema.safeParse(data);
    if (!r.success) {
      const issues = r.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
      log.warn(`Validazione fallita: ${issues} — body: ${JSON.stringify(data)}`);
      res.status(400).json({ error: `Dati non validi — ${issues}`, issues: r.error.issues });
      return null;
    }
    return r.data;
  }

  function apiError(res, e, msg = 'Errore interno') {
    try { log.err('api-error', e); } catch {}
    res.status(500).json(IS_PROD ? { error: msg } : { error: msg, detail: e?.message });
  }

  function requiredDashboardAccess(pathname) {
    if (pathname === '/dashboard') return 'dashboard';
    if (pathname === '/permissions' || pathname === '/api/dashboard/managed-guilds' ||
        pathname.startsWith('/api/dashboard/role-permissions/')) return 'manager';
    const routes = [
      ['overview', ['/api/stats', '/api/status']],
      ['moderation', [
        '/modlogs', '/notes', '/search', '/user', '/user-actions',
        '/api/logs', '/api/notes', '/api/user',
        '/api/user-lookup', '/api/user-action', '/api/mod', '/api/search',
        '/api/export/notes', '/api/export/logs'
      ]],
      ['global_blacklist', ['/api/blacklist', '/api/export/blacklist']],
      ['tickets', ['/tickets', '/api/tickets', '/api/ticketpanel']],
      ['settings', ['/commands', '/config', '/api/commands', '/api/config', '/api/welcome']],
      ['analytics', ['/charts', '/top', '/api/charts', '/api/top']],
      ['communications', ['/messages', '/reminders', '/api/messages', '/api/reminders']],
      ['lobbies', ['/lobbies', '/api/lobbies']],
      ['audit', ['/access-logs', '/api/access-logs', '/api/export/access-logs', '/api/export/full-backup']]
    ];
    for (const [feature, prefixes] of routes) {
      if (prefixes.some(prefix => pathname === prefix || pathname.startsWith(`${prefix}/`) || pathname.startsWith(`${prefix}.`))) {
        return feature;
      }
    }
    return null;
  }

  async function requireAuth(req, res, next) {
    if (!req.session.user) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Non autenticato' });
      return res.redirect('/auth/login');
    }
    if (!req.session.user.dashboardAuthorized) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Non autorizzato' });
      return res.status(403).send('Accesso negato.');
    }
    let access;
    try {
      access = await getDashboardAccess(req.session.user.id);
    } catch (e) {
      log.err('requireAuth permission lookup', e);
      if (req.path.startsWith('/api/')) return res.status(503).json({ error: 'Permessi temporaneamente non disponibili' });
      return res.status(503).send('Permessi temporaneamente non disponibili.');
    }
    if (!access.authorized) {
      if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Ruolo non più valido' });
      return res.status(403).send('Accesso negato.');
    }
    req.dashboardAccess = access;
    const required = requiredDashboardAccess(req.path);
    if (required === 'manager' && !access.manager) {
      return req.path.startsWith('/api/')
        ? res.status(403).json({ error: 'Solo gli amministratori dashboard possono gestire i permessi' })
        : res.status(403).send('Solo gli amministratori dashboard possono gestire i permessi.');
    }
    const hasFeature = required === 'dashboard'
      ? access.permissions.has('overview') || access.permissions.has('global_blacklist')
      : access.permissions.has(required);
    if (required && required !== 'manager' && !hasFeature) {
      return req.path.startsWith('/api/')
        ? res.status(403).json({ error: 'Non hai il permesso per questa sezione' })
        : res.status(403).send('Non hai il permesso per questa sezione.');
    }
    next();
  }

  // ==================== LOBBY (API) ====================
  mountLobbies(app, {
    client, storage, log, requireAuth, actionLimiter, parseOrFail, apiError,
    assertGuildAccess, canManageGuild: (userId, guild) => canManageGuild(userId, guild, 'lobbies'), logMod, dashMod
  });

  // ==================== PUBBLICI ====================
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: Math.floor((Date.now() - botStartTime) / 1000), guilds: client.guilds.cache.size, ping: client.ws.ping, timestamp: new Date().toISOString() });
  });
  app.get('/', (req, res) => {
    res.json({ message: 'Bot Dashboard', version: '5.4.4', loggedIn: !!req.session.user });
  });

  // ==================== OAUTH ====================
  app.get('/auth/login', (req, res) => {
    if (!CLIENT_ID || !CLIENT_SECRET) return res.status(500).send('OAuth2 non configurato.');
    const state = crypto.randomBytes(24).toString('hex');
    req.session.oauthState = state;
    req.session.save((err) => {
      if (err) return res.status(500).send('Errore sessione');
      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: `${DASHBOARD_URL}/auth/callback`,
        response_type: 'code',
        scope: 'identify',
        state
      });
      res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
    });
  });

  app.get('/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    const expected = req.session.oauthState;
    delete req.session.oauthState;
    if (!code || !state || !expected || !safeEqual(state, expected)) {
      return res.status(403).send('Richiesta di login non valida, riprova dalla dashboard.');
    }
    try {
      const tokenRes = await axios.post('https://discord.com/api/oauth2/token',
        new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: `${DASHBOARD_URL}/auth/callback` }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
      );
      const userRes = await axios.get('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }, timeout: 10000 });
      const user = userRes.data;

      const dashboardAccess = await getDashboardAccess(user.id);
      if (!dashboardAccess.authorized) {
        return res.status(403).send('Accesso negato.');
      }
      log.ok(`OAuth login: ${user.username} (${user.id})`);

      try {
        const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'sconosciuto';
        storage.saveDashboardAccess(user.id, user.username, ip, (req.headers['user-agent'] || '').slice(0, 300));
      } catch (e) { log.err('saveDashboardAccess', e); }

      req.session.regenerate((err) => {
        if (err) return res.status(500).send('Errore login');
        req.session.user = { id: user.id, username: user.username, global_name: user.global_name || user.username, avatar: user.avatar, dashboardAuthorized: true };
        req.session.save(() => res.redirect(dashboardLandingPath(dashboardAccess)));
      });
    } catch (err) {
      log.err('OAuth', err.response?.data || err.message);
      res.status(500).send('Errore login');
    }
  });

  app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
  app.get('/auth/me', (req, res) => res.json({ user: req.session.user || null }));

  app.post('/api/logout-all', requireAuth, (req, res) => {
    const userId = req.session.user.id;
    try {
      const files = fs.readdirSync(SESSION_DIR);
      let removed = 0;
      for (const f of files) {
        try {
          const content = JSON.parse(fs.readFileSync(path.join(SESSION_DIR, f), 'utf8'));
          if (content?.user?.id === userId) { fs.unlinkSync(path.join(SESSION_DIR, f)); removed++; }
        } catch {}
      }
      authCache.delete(userId);
      req.session.destroy(() => res.json({ ok: true, removed }));
    } catch (e) { apiError(res, e, 'Errore logout globale'); }
  });

  // ==================== API ====================
  app.get('/api/status', requireAuth, (req, res) => {
    let databaseReady = false;
    try {
      databaseReady = storage.db.prepare('SELECT 1 AS ok').get()?.ok === 1;
    } catch (err) {
      log.err('api/status database check', err);
    }
    const botOnline = typeof client.isReady === 'function' && client.isReady();
    const ping = Number.isFinite(client.ws?.ping) ? client.ws.ping : null;
    const uptime = Math.max(0, Math.floor((Date.now() - botStartTime) / 1000));
    res.json({
      status: botOnline && databaseReady ? 'operational' : 'degraded',
      api: true,
      botOnline,
      ping,
      uptime,
      databaseReady,
      checkedAt: new Date().toISOString()
    });
  });

  app.get('/api/stats', requireAuth, async (req, res) => {
    try {
      const s = storage.getStats();
      const userId = req.session.user.id;
      const canViewGlobalBlacklist = await canUseGlobalBlacklist(userId);
      const hasModeration = req.dashboardAccess.permissions.has('moderation');
      const hasTickets = req.dashboardAccess.permissions.has('tickets');
      const hasCommunications = req.dashboardAccess.permissions.has('communications');
      const moderationGuilds = hasModeration ? await allowedGuildIds(userId, 'moderation') : new Set();
      const ticketGuilds = hasTickets ? await allowedGuildIds(userId, 'tickets') : new Set();
      const communicationGuilds = hasCommunications ? await allowedGuildIds(userId, 'communications') : new Set();
      const overviewGuilds = await allowedGuildIds(userId, 'overview');
      let ticketsCount = 0;
      for (const guild of client.guilds.cache.values()) {
        if (!ticketGuilds.has(guild.id)) continue;
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-')) ticketsCount++;
        }
      }
      let notesCount = 0, transcriptsCount = 0, remindersCount = 0;
      try {
        const perGuild = storage.db.prepare('SELECT guild_id, COUNT(*) AS c FROM member_notes GROUP BY guild_id').all();
        notesCount = perGuild.filter(r => moderationGuilds.has(r.guild_id)).reduce((sum, r) => sum + r.c, 0);
      } catch {}
      try { transcriptsCount = countWhereGuilds('ticket_transcripts', ticketGuilds, userId); } catch {}
      try { remindersCount = countWhereGuilds('reminders', communicationGuilds, userId); } catch {}
      const logCount = hasModeration
        ? (isEnvAdmin(userId) ? s.total : countWhereGuilds('mod_logs', moderationGuilds, userId))
        : null;
      const byType = hasModeration
        ? (isEnvAdmin(userId)
          ? s.byType
          : (() => {
            const scope = logScope(userId, moderationGuilds);
            return storage.db.prepare(`SELECT type, COUNT(*) AS c FROM mod_logs WHERE 1=1${scope.sql} GROUP BY type`).all(...scope.params);
          })())
        : [];
      res.json({
        logs: logCount,
        blacklist: canViewGlobalBlacklist ? s.blacklist : null,
        guilds: overviewGuilds.size, ping: client.ws.ping,
        uptime: Math.floor((Date.now() - botStartTime) / 1000), byType,
        tickets: hasTickets ? ticketsCount : null,
        notes: hasModeration ? notesCount : null,
        transcripts: hasTickets ? transcriptsCount : null,
        reminders: hasCommunications ? remindersCount : null
      });
    } catch (e) { apiError(res, e, 'Errore statistiche'); }
  });

  app.get('/api/blacklist', requireAuth, async (req, res) => {
    try {
      if (!(await canUseGlobalBlacklist(req.session.user.id))) return res.status(403).json({ error: 'Non puoi vedere la blacklist globale' });
      res.json(storage.getAllBlacklist());
    } catch (e) { apiError(res, e); }
  });
  app.post('/api/blacklist', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaBlacklistAdd, req.body || {}, res);
    if (!data) return;
    if (!(await canUseGlobalBlacklist(req.session.user.id))) return res.status(403).json({ error: 'Non puoi gestire la blacklist globale' });
    if (data.userId === client.user.id) return res.status(400).json({ error: 'Non puoi mettere in blacklist il bot' });
    if (data.userId === req.session.user.id) return res.status(400).json({ error: 'Non puoi mettere in blacklist te stesso' });
    try {
      if (storage.isBlacklisted(data.userId)) return res.status(409).json({ error: 'Già in blacklist' });
      const bannedIn = await blacklistAddFull(data.userId, data.username, data.reason, dashActor(req));
      res.json({ ok: true, bannedIn });
    } catch (e) { apiError(res, e); }
  });
  app.delete('/api/blacklist/:userId', actionLimiter, requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).json({ error: 'ID non valido' });
    if (!(await canUseGlobalBlacklist(req.session.user.id))) return res.status(403).json({ error: 'Non puoi gestire la blacklist globale' });
    try {
      if (!storage.isBlacklisted(req.params.userId)) return res.status(404).json({ error: 'Utente non in blacklist' });
      const unbannedIn = await blacklistRemoveFull(req.params.userId, dashActor(req));
      res.json({ ok: true, unbannedIn });
    } catch (e) { apiError(res, e); }
  });
  app.post('/api/blacklist/bulk-delete', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaBulkDelete, req.body || {}, res);
    if (!data) return;
    if (!(await canUseGlobalBlacklist(req.session.user.id))) return res.status(403).json({ error: 'Non puoi gestire la blacklist globale' });
    try {
      const mod = dashActor(req);
      let count = 0;
      for (const raw of data.ids) {
        const id = String(raw);
        if (!/^\d{17,20}$/.test(id) || !storage.isBlacklisted(id)) continue;
        await blacklistRemoveFull(id, mod);
        count++;
      }
      res.json({ ok: true, count });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/logs/all', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      res.json(logsForViewer(req.session.user.id, allowed, 500));
    } catch (e) { res.json([]); }
  });
  app.get('/api/logs/:userId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.userId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      res.json(logsForUserViewer(req.session.user.id, req.params.userId, allowed));
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/notes/all', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      res.json(notesForGuilds(allowed));
    } catch (e) { apiError(res, e); }
  });
  app.post('/api/notes', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaNoteAdd, req.body || {}, res);
    if (!data) return;
    const content = data.content.trim();
    if (content.length < 2) return res.status(400).json({ error: 'Il contenuto della nota è troppo corto' });
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const target = await client.users.fetch(data.userId).catch(() => null);
      if (!target) return res.status(404).json({ error: 'Utente non trovato' });
      const id = storage.addNote(data.guildId, data.userId, req.session.user.id, req.session.user.username, content);
      await logMod(guild, {
        type: 'Nota Aggiunta', title: 'Nota Staff', targetId: data.userId,
        target: `${target.username} (${target.id})`, moderator: dashMod(req), reason: content.slice(0, 500)
      });
      res.json({ ok: true, id });
    } catch (e) { apiError(res, e, 'Errore salvataggio nota'); }
  });
  app.delete('/api/notes/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'ID non valido' });
    try {
      const note = storage.db.prepare('SELECT id, guild_id FROM member_notes WHERE id = ?').get(id);
      if (!note) return res.status(404).json({ error: 'Nota non trovata' });
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      if (!allowed.has(note.guild_id)) return res.status(403).json({ error: 'Non hai i permessi su questo server' });
      res.json({ ok: storage.deleteNoteById(id) });
    } catch (e) { apiError(res, e); }
  });
  app.post('/api/notes/bulk-delete', requireAuth, async (req, res) => {
    const data = parseOrFail(schemaBulkDelete, req.body || {}, res);
    if (!data) return;
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const lookup = storage.db.prepare('SELECT id, guild_id FROM member_notes WHERE id = ?');
      let count = 0;
      for (const raw of data.ids) {
        const id = parseInt(raw, 10);
        if (!Number.isInteger(id) || id <= 0) continue;
        const note = lookup.get(id);
        if (note && allowed.has(note.guild_id) && storage.deleteNoteById(id)) count++;
      }
      res.json({ ok: true, count });
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/config/:guildId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, req.params.guildId))) return;
    try { res.json(storage.getGuildConfig(req.params.guildId)); } catch (e) { apiError(res, e); }
  });
  app.post('/api/config/:guildId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, req.params.guildId))) return;
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

  app.get('/api/welcome/:guildId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, req.params.guildId))) return;
    try { res.json(storage.getWelcomeConfig(req.params.guildId) || {}); } catch (e) { apiError(res, e); }
  });
  app.post('/api/welcome/:guildId', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, req.params.guildId))) return;
    const data = parseOrFail(schemaWelcome, req.body || {}, res);
    if (!data) return;
    const guildId = req.params.guildId;
    try {
      if (data.channelId !== undefined) {
        if (data.channelId) storage.setWelcomeChannel(guildId, data.channelId);
        else storage.disableWelcome(guildId);
      }
      if (data.message !== undefined && data.message !== null) {
        if (data.message.trim()) storage.setWelcomeMessage(guildId, data.message);
        else storage.clearWelcomeMessage(guildId);
      }
      if (data.embedEnabled !== undefined) {
        const current = storage.getWelcomeConfig(guildId);
        storage.setWelcomeConfig(guildId, { channelId: current?.channel_id ?? null, message: current?.message ?? null, embedEnabled: data.embedEnabled });
      }
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/welcome/:guildId/test', requireAuth, async (req, res) => {
    if (!/^\d{17,20}$/.test(req.params.guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, req.params.guildId))) return;
    const guild = client.guilds.cache.get(req.params.guildId);

    const config = storage.getWelcomeConfig(req.params.guildId);
    if (!config || !config.channel_id) return res.status(400).json({ error: 'Canale welcome non configurato' });

    const channel = guild.channels.cache.get(config.channel_id);
    if (!channel || !channel.isTextBased()) return res.status(400).json({ error: 'Canale welcome non valido' });

    try {
      const user = req.session.user;
      const fill = (t) => String(t || 'Benvenuto {user} in {server}!')
        .replace(/{user}/g, `<@${user.id}>`)
        .replace(/{username}/g, user.username)
        .replace(/{server}/g, guild.name)
        .replace(/{memberCount}/g, guild.memberCount);

      const text = fill(config.message);
      if (config.embed_enabled) {
        const avatarUrl = user.avatar
          ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
          : `https://cdn.discordapp.com/embed/avatars/0.png`;
        const embed = new EmbedBuilder()
          .setTitle('👋 Benvenuto!').setDescription(text).setColor(0x00FF00)
          .setThumbnail(avatarUrl).setFooter({ text: `Sei il membro #${guild.memberCount}` }).setTimestamp();
        await channel.send({ embeds: [embed] });
      } else {
        await channel.send({ content: text, allowedMentions: { parse: ['users'] } });
      }
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore test welcome'); }
  });

  app.get('/api/tickets', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'tickets');
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        if (!allowed.has(guild.id)) continue;
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-')) {
            const meta = storage.getTicketMeta ? (storage.getTicketMeta(ch.id) || {}) : {};
            tickets.push({
              guild: guild.name, guildId: guild.id,
              channel: ch.name, channelId: ch.id,
              userId: ch.name.replace('ticket-', ''),
              claimedBy: meta.claimed_by_tag || null,
              priority: meta.priority || null
            });
          }
        }
      }
      res.json(tickets);
    } catch (e) { apiError(res, e); }
  });

  app.delete('/api/tickets/:channelId', requireAuth, async (req, res) => {
    try {
      const ch = await ticketChannelOrFail(req, res);
      if (!ch) return;
      const userId = ch.name.replace('ticket-', '');
      const html = await buildTranscriptHtml(ch);
      const meta = storage.getTicketMeta ? storage.getTicketMeta(ch.id) : null;
      if (html && storage.saveTranscript) {
        storage.saveTranscript(
          ch.id, ch.name, userId,
          meta?.claimed_by_tag || 'N/D', meta?.priority || 'N/D', html, ch.guild.id
        );
      }
      await logMod(ch.guild, {
        type: 'Ticket Chiuso', title: 'Ticket Chiuso', targetId: userId,
        target: userId, moderator: dashMod(req), channel: ch.name
      });
      await ch.delete('Chiuso dalla dashboard web');
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/tickets/:channelId/claim', actionLimiter, requireAuth, async (req, res) => {
    try {
      const ch = await ticketChannelOrFail(req, res);
      if (!ch) return;
      storage.setTicketMeta(ch.id, { claimedById: req.session.user.id, claimedByTag: req.session.user.username });
      await logMod(ch.guild, {
        type: 'Ticket Claim', title: 'Ticket preso in carico', targetId: ch.name.replace('ticket-', ''),
        target: ch.name, moderator: dashMod(req), channel: ch.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/tickets/:channelId/priority', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaTicketPriority, req.body || {}, res);
    if (!data) return;
    try {
      const ch = await ticketChannelOrFail(req, res);
      if (!ch) return;
      storage.setTicketMeta(ch.id, { priority: data.priority });
      await logMod(ch.guild, {
        type: 'Ticket Priorità', title: 'Priorità ticket', targetId: ch.name.replace('ticket-', ''),
        target: ch.name, moderator: dashMod(req), channel: ch.name,
        reason: `Priorità: ${data.priority.toUpperCase()}`
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/ticketpanel', requireAuth, async (req, res) => {
    const schema = z.object({ channelId: z.string().regex(/^\d{17,20}$/) });
    const data = parseOrFail(schema, req.body || {}, res);
    if (!data) return;
    try {
      const channel = await client.channels.fetch(data.channelId).catch(() => null);
      if (!channel || !channel.isTextBased()) return res.status(404).json({ error: 'Canale non valido' });
      if (!channel.guild || !(await canManageGuild(req.session.user.id, channel.guild, 'tickets'))) {
        return res.status(403).json({ error: 'Non hai i permessi su questo server' });
      }
      const panelActor = await channel.guild.members.fetch(req.session.user.id).catch(() => null);
      if (!isEnvAdmin(req.session.user.id) && !channel.permissionsFor(panelActor)?.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(403).json({ error: 'Non puoi scrivere in questo canale' });
      }

      const embed = new EmbedBuilder().setTitle('Pannello Ticket').setDescription('Premi il bottone qui sotto per aprire un ticket.').setColor(0x0099FF).setTimestamp();
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('create_ticket').setLabel('Apri Ticket').setStyle(ButtonStyle.Primary)
      );
      await channel.send({ embeds: [embed], components: [row] });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore creazione pannello'); }
  });

  app.get('/api/tickets/transcripts', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'tickets');
      res.json(transcriptsForViewer(req.session.user.id, allowed));
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/tickets/transcripts/:id', requireAuth, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).send('ID non valido');
    try {
      const t = storage.getTranscript ? storage.getTranscript(id) : null;
      if (!t) return res.status(404).send('Transcript non trovato');
      if (t.guild_id) {
        if (!(await assertGuildAccess(req, res, t.guild_id))) return;
      } else if (!isEnvAdmin(req.session.user.id)) {
        return res.status(403).send('Transcript senza server: visibile solo agli admin dashboard');
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.send(t.html_content);
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
    try { storage.saveCommand(data.name.toLowerCase(), data.response); res.json({ ok: true }); }
    catch (e) { apiError(res, e); }
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

  function logScope(userId, allowed) {
    if (isEnvAdmin(userId)) return { sql: '', params: [] };
    const ids = [...allowed];
    if (!ids.length) return { sql: ' AND 1=0', params: [] };
    const scope = legacyGuildSql(ids);
    return { sql: ` AND ${scope.sql}`, params: scope.params };
  }

  app.get('/api/charts', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'analytics');
      const scope = logScope(req.session.user.id, allowed);
      const where = scope.sql ? `WHERE 1=1${scope.sql}` : '';
      const byType = storage.db.prepare(`SELECT type, COUNT(*) as c FROM mod_logs ${where} GROUP BY type`).all(...scope.params);
      const byDay = storage.db.prepare(`SELECT substr(timestamp,1,10) as day, COUNT(*) as c FROM mod_logs ${where} GROUP BY day ORDER BY day DESC LIMIT 30`).all(...scope.params);
      res.json({ byType, byDay });
    } catch (e) { res.json({ byType: [], byDay: [] }); }
  });

  app.get('/api/top', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'analytics');
      const scope = logScope(req.session.user.id, allowed);
      const moderators = storage.db.prepare(`SELECT moderator, COUNT(*) as c FROM mod_logs WHERE moderator IS NOT NULL AND moderator != 'Sistema Automatico'${scope.sql} GROUP BY moderator ORDER BY c DESC LIMIT 10`).all(...scope.params);
      const targets = storage.db.prepare(`SELECT target_id, target, COUNT(*) as c FROM mod_logs WHERE target_id IS NOT NULL${scope.sql} GROUP BY target_id ORDER BY c DESC LIMIT 10`).all(...scope.params);
      const types = storage.db.prepare(`SELECT type, COUNT(*) as c FROM mod_logs WHERE 1=1${scope.sql} GROUP BY type ORDER BY c DESC`).all(...scope.params);
      const byMonth = storage.db.prepare(`SELECT substr(timestamp,1,7) as month, COUNT(*) as c FROM mod_logs WHERE 1=1${scope.sql} GROUP BY month ORDER BY month DESC LIMIT 12`).all(...scope.params);
      res.json({ moderators, targets, types, byMonth });
    } catch (e) { log.err('api/top', e); res.json({ moderators: [], targets: [], types: [], byMonth: [] }); }
  });

  app.get('/api/guilds', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id);
      const guilds = [...client.guilds.cache.values()]
        .filter(g => allowed.has(g.id))
        .map(g => {
          const permissions = ENV_ADMIN_IDS.includes(req.session.user.id)
            ? new Set(DASHBOARD_FEATURES)
            : req.dashboardAccess.guildPermissions.get(g.id) || new Set();
          return {
            id: g.id, name: g.name,
            roles: ['moderation', 'settings', 'tickets', 'communications', 'lobbies'].some(feature => permissions.has(feature))
              ? g.roles.cache.filter(r => r.name !== '@everyone').map(r => ({ id: r.id, name: r.name }))
              : [],
            channels: ['settings', 'tickets', 'communications', 'lobbies'].some(feature => permissions.has(feature))
              ? g.channels.cache.filter(c => c.type === 0).map(c => ({ id: c.id, name: c.name }))
              : []
          };
        });
      res.json(guilds);
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/resources', async (req, res) => {
    let access = null;
    if (req.session.user) {
      try {
        access = await getDashboardAccess(req.session.user.id);
      } catch (e) {
        log.err('api/resources access lookup', e);
      }
    }
    try {
      const guildOverrides = new Map(
        storage.getGuildResourceOverrides().map(override => [override.guild_id, override])
      );
      const resources = [...client.guilds.cache.values()]
        .map(guild => {
          const override = guildOverrides.get(guild.id);
          return {
            kind: 'guild',
            id: guild.id,
            name: override?.title || guild.name,
            category: override ? override.category : 'Server Discord',
            description: override
              ? override.description
              : 'Server Discord collegato al bot. Le funzioni di gestione richiedono un account autorizzato.',
            resourceUrl: override?.url || null,
            inviteUrl: override?.invite_url || (guild.vanityURLCode ? `https://discord.gg/${guild.vanityURLCode}` : null),
            iconUrl: guild.iconURL({ size: 128 }),
            memberCount: guild.memberCount,
            permissions: access?.authorized && ENV_ADMIN_IDS.includes(req.session.user.id)
              ? DASHBOARD_FEATURES
              : access?.authorized
                ? [...(access.guildPermissions.get(guild.id) || [])]
                : []
          };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
      const customResources = storage.getPublicResources().map(resource => ({
        kind: 'custom',
        ...resource
      }));
      res.json([...customResources, ...resources]);
    } catch (e) { apiError(res, e, 'Impossibile caricare le risorse'); }
  });

  app.post('/api/resources', actionLimiter, requireAuth, (req, res) => {
    if (!req.dashboardAccess.manager) return res.status(403).json({ error: 'Solo gli amministratori dashboard possono aggiungere risorse' });
    const data = parseOrFail(schemaPublicResource, req.body || {}, res);
    if (!data) return;
    try {
      const id = storage.addPublicResource({ ...data, createdBy: req.session.user.id });
      res.status(201).json({ ok: true, id });
    } catch (e) { apiError(res, e, 'Impossibile aggiungere la risorsa'); }
  });

  app.put('/api/resources/:id', actionLimiter, requireAuth, (req, res) => {
    if (!req.dashboardAccess.manager) return res.status(403).json({ error: 'Solo gli amministratori dashboard possono modificare risorse' });
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'ID risorsa non valido' });
    const data = parseOrFail(schemaPublicResource, req.body || {}, res);
    if (!data) return;
    try {
      if (!storage.updatePublicResource(id, data)) return res.status(404).json({ error: 'Risorsa non trovata' });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Impossibile modificare la risorsa'); }
  });

  app.put('/api/resources/guild/:guildId', actionLimiter, requireAuth, (req, res) => {
    if (!req.dashboardAccess.manager) return res.status(403).json({ error: 'Solo gli amministratori dashboard possono modificare le schede server' });
    const guildId = req.params.guildId;
    if (!/^\d{17,20}$/.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!client.guilds.cache.has(guildId)) return res.status(404).json({ error: 'Server non trovato' });
    const data = parseOrFail(schemaGuildResourceOverride, req.body || {}, res);
    if (!data) return;
    try {
      storage.saveGuildResourceOverride(guildId, { ...data, updatedBy: req.session.user.id });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Impossibile modificare la scheda server'); }
  });

  app.delete('/api/resources/guild/:guildId', actionLimiter, requireAuth, (req, res) => {
    if (!req.dashboardAccess.manager) return res.status(403).json({ error: 'Solo gli amministratori dashboard possono ripristinare le schede server' });
    const guildId = req.params.guildId;
    if (!/^\d{17,20}$/.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    try {
      storage.deleteGuildResourceOverride(guildId);
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Impossibile ripristinare la scheda server'); }
  });

  app.delete('/api/resources/:id', actionLimiter, requireAuth, (req, res) => {
    if (!req.dashboardAccess.manager) return res.status(403).json({ error: 'Solo gli amministratori dashboard possono rimuovere risorse' });
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'ID risorsa non valido' });
    try {
      if (!storage.deletePublicResource(id)) return res.status(404).json({ error: 'Risorsa non trovata' });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Impossibile rimuovere la risorsa'); }
  });

  app.get('/api/dashboard/managed-guilds', requireAuth, async (req, res) => {
    const guilds = [];
    for (const guild of client.guilds.cache.values()) {
      if (await canManageDashboardRolesInGuild(req.session.user.id, guild)) {
        guilds.push({ id: guild.id, name: guild.name });
      }
    }
    res.json(guilds);
  });

  app.get('/api/dashboard/role-permissions/:guildId', requireAuth, async (req, res) => {
    const guild = client.guilds.cache.get(req.params.guildId);
    if (!guild) return res.status(404).json({ error: 'Server non trovato' });
    if (!(await canManageDashboardRolesInGuild(req.session.user.id, guild))) {
      return res.status(403).json({ error: 'Puoi gestire i permessi solo nei server dove sei Senior Admin' });
    }
    try {
      const saved = new Map(storage.getDashboardRolePermissions(guild.id).map(item => [item.role_id, item.permissions]));
      const roles = guild.roles.cache
        .filter(role => role.id !== guild.id && !role.managed)
        .map(role => ({ id: role.id, name: role.name, permissions: saved.get(role.id) || [] }));
      res.json(roles);
    } catch (e) { apiError(res, e, 'Impossibile caricare i permessi dei ruoli'); }
  });

  app.put('/api/dashboard/role-permissions/:guildId/:roleId', requireAuth, async (req, res) => {
    const data = parseOrFail(schemaDashboardRolePermissions, req.body || {}, res);
    if (!data) return;
    const guild = client.guilds.cache.get(req.params.guildId);
    if (!guild) return res.status(404).json({ error: 'Server non trovato' });
    if (!(await canManageDashboardRolesInGuild(req.session.user.id, guild))) {
      return res.status(403).json({ error: 'Puoi gestire i permessi solo nei server dove sei Senior Admin' });
    }
    const role = guild.roles.cache.get(req.params.roleId);
    if (!role || role.id === guild.id || role.managed) return res.status(404).json({ error: 'Ruolo non valido' });
    try {
      const permissions = [...new Set(data.permissions)];
      storage.setDashboardRolePermissions(guild.id, role.id, permissions, req.session.user.id);
      authCache.clear();
      res.json({ ok: true, permissions });
    } catch (e) { apiError(res, e, 'Impossibile salvare i permessi del ruolo'); }
  });

  app.get('/api/user/:userId', requireAuth, async (req, res) => {
    const userId = req.params.userId;
    if (!/^\d{17,20}$/.test(userId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const ticketGuilds = await allowedGuildIds(req.session.user.id, 'tickets');
      const logs = logsForUserViewer(req.session.user.id, userId, allowed);
      const notes = storage.db.prepare('SELECT * FROM member_notes WHERE user_id = ? ORDER BY id DESC LIMIT 1000').all(userId)
        .filter(n => allowed.has(n.guild_id))
        .slice(0, 100);
      const blacklistEntry = (await canUseGlobalBlacklist(req.session.user.id)) ? storage.getBlacklistEntry(userId) : null;
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        if (!ticketGuilds.has(guild.id)) continue;
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name === `ticket-${userId}`) {
            const meta = storage.getTicketMeta ? (storage.getTicketMeta(ch.id) || {}) : {};
            tickets.push({ guild: guild.name, guildId: guild.id, channel: ch.name, channelId: ch.id, claimedBy: meta.claimed_by_tag || null, priority: meta.priority || null });
          }
        }
      }
      const byTypeMap = logs.reduce((acc, l) => { acc[l.type] = (acc[l.type] || 0) + 1; return acc; }, {});
      res.json({ userId, logs, notes, blacklist: blacklistEntry, tickets, byType: Object.entries(byTypeMap).map(([type, c]) => ({ type, c })) });
    } catch (e) { apiError(res, e, 'Errore caricamento utente'); }
  });

  app.get('/api/search', requireAuth, async (req, res) => {
    const q = (req.query.q || '').toString().trim().toLowerCase().slice(0, 100);
    if (!q) return res.json({ blacklist: [], notes: [], logs: [], tickets: [] });
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const ticketGuilds = await allowedGuildIds(req.session.user.id, 'tickets');
      const blacklist = (await canUseGlobalBlacklist(req.session.user.id))
        ? storage.getAllBlacklist().filter(e => (e.user_id || '').toLowerCase().includes(q) || (e.username || '').toLowerCase().includes(q) || (e.reason || '').toLowerCase().includes(q))
        : [];
      const notes = notesForGuilds(allowed, 5000).filter(n => (n.user_id || '').toLowerCase().includes(q) || (n.content || '').toLowerCase().includes(q) || (n.author_tag || '').toLowerCase().includes(q));
      const logs = logsForViewer(req.session.user.id, allowed, 500).filter(l => (l.target_id || '').toLowerCase().includes(q) || (l.target || '').toLowerCase().includes(q) || (l.moderator || '').toLowerCase().includes(q) || (l.reason || '').toLowerCase().includes(q));
      const tickets = [];
      for (const guild of client.guilds.cache.values()) {
        if (!ticketGuilds.has(guild.id)) continue;
        for (const ch of guild.channels.cache.values()) {
          if (ch.name && ch.name.startsWith('ticket-') && ch.name.toLowerCase().includes(q)) {
            tickets.push({ guild: guild.name, channel: ch.name, channelId: ch.id, userId: ch.name.replace('ticket-', '') });
          }
        }
      }
      res.json({ blacklist, notes, logs, tickets });
    } catch (e) { apiError(res, e, 'Errore ricerca'); }
  });

  function sanitizeCsvCell(v) {
    const s = (v === null || v === undefined) ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
    return s;
  }
  function toCsv(rows, headers) {
    if (!rows.length) return headers.join(',');
    const esc = (v) => {
      const s = sanitizeCsvCell(v);
      return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return headers.join(',') + '\n' + rows.map(r => headers.map(h => esc(r[h])).join(',')).join('\n');
  }

  app.get('/api/export/blacklist.csv', requireAuth, async (req, res) => {
    if (!(await canUseGlobalBlacklist(req.session.user.id))) return res.status(403).json({ error: 'Non puoi esportare la blacklist globale' });
    try {
      const csv = toCsv(storage.getAllBlacklist(), ['user_id', 'username', 'reason', 'moderator_tag', 'added_at']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="blacklist.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/notes.csv', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const csv = toCsv(
        notesForGuilds(allowed, 100000),
        ['id', 'guild_id', 'user_id', 'author_tag', 'content', 'created_at']
      );
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="notes.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/logs.csv', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const csv = toCsv(logsForViewer(req.session.user.id, allowed, 5000), ['id', 'type', 'target_id', 'target', 'moderator', 'reason', 'duration', 'channel', 'guild_id', 'timestamp']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="modlogs.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });
  app.get('/api/export/access-logs.csv', requireAuth, (req, res) => {
    if (ENV_ADMIN_IDS.length && !isEnvAdmin(req.session.user.id)) return res.status(403).json({ error: 'Solo gli admin dashboard vedono gli IP' });
    try {
      const csv = toCsv(storage.getDashboardAccessLogs(), ['id', 'user_id', 'username', 'ip', 'user_agent', 'timestamp']);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="access-logs.csv"');
      res.send(csv);
    } catch (e) { apiError(res, e); }
  });

  app.get('/api/export/full-backup', requireAuth, async (req, res) => {
    if (!isEnvAdmin(req.session.user.id)) {
      return res.status(403).json({ error: 'Il backup completo è riservato agli admin configurati in DASHBOARD_ADMIN_IDS' });
    }

    let tempDir;
    const cleanup = () => {
      if (!tempDir) return;
      fs.rm(tempDir, { recursive: true, force: true }, err => {
        if (err) log.err('full database backup cleanup', err);
      });
    };

    try {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tommy-utilities-backup-'));
      const backupPath = path.join(tempDir, 'bot.sqlite');
      await storage.db.backup(backupPath);
      res.setHeader('Cache-Control', 'no-store');
      res.download(backupPath, `tommy-utilities-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.sqlite`, err => {
        cleanup();
        if (!err) return;
        log.err('full database backup download', err);
        if (!res.headersSent) return apiError(res, err, 'Errore invio backup');
        res.destroy(err);
      });
    } catch (e) {
      cleanup();
      apiError(res, e, 'Impossibile creare il backup completo');
    }
  });

  app.get('/api/access-logs', requireAuth, (req, res) => {
    if (ENV_ADMIN_IDS.length && !isEnvAdmin(req.session.user.id)) return res.status(403).json({ error: 'Solo gli admin dashboard vedono gli IP' });
    try { res.json(storage.getDashboardAccessLogs()); } catch (e) { res.json([]); }
  });

  app.get('/api/messages/channels', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'communications');
      const out = [];
      for (const guild of client.guilds.cache.values()) {
        if (!allowed.has(guild.id)) continue;
        for (const ch of guild.channels.cache.values()) {
          if (ch.type === 0) out.push({ guildId: guild.id, guildName: guild.name, channelId: ch.id, channelName: ch.name });
        }
      }
      out.sort((a, b) => a.guildName.localeCompare(b.guildName) || a.channelName.localeCompare(b.channelName));
      res.json(out);
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/messages/send', messageLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaMessagesSend, req.body || {}, res);
    if (!data) return;
    try {
      const channel = await client.channels.fetch(data.channelId).catch(() => null);
      if (!channel || !channel.isTextBased()) return res.status(404).json({ error: 'Canale non valido' });
      if (!channel.guild || !(await canManageGuild(req.session.user.id, channel.guild, 'communications'))) {
        return res.status(403).json({ error: 'Non hai i permessi su questo server' });
      }
      const sender = await channel.guild.members.fetch(req.session.user.id).catch(() => null);
      if (!isEnvAdmin(req.session.user.id) && !channel.permissionsFor(sender)?.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(403).json({ error: 'Non puoi scrivere in questo canale' });
      }
      const botMember = channel.guild?.members?.me;
      if (botMember && !channel.permissionsFor(botMember)?.has('SendMessages')) return res.status(403).json({ error: 'Il bot non può scrivere in questo canale' });

      const payload = { allowedMentions: { parse: [
        ...(data.allowMentions ? ['users', 'roles'] : []),
        ...(data.allowMassMentions ? ['everyone'] : [])
      ] } };
      if (data.content) payload.content = data.content;
      if (data.embed && (data.embed.title || data.embed.description)) {
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

  // ---------- Moderazione canale (come -clear, -lock, -unlock del bot) ----------
  app.post('/api/mod/clear', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModClear, req.body || {}, res);
    if (!data) return;
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const channel = guild.channels.cache.get(data.channelId);
      if (!channel || !channel.isTextBased()) return res.status(404).json({ error: 'Canale testuale non valido' });
      if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.ManageMessages))) {
        return res.status(403).json({ error: 'Ti manca "Gestisci Messaggi"' });
      }
      if (!channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.ManageMessages)) {
        return res.status(403).json({ error: 'Il bot non può gestire i messaggi in questo canale' });
      }
      const deleted = await channel.bulkDelete(data.amount, true);
      await logMod(guild, {
        type: 'Clear', title: 'Clear Messaggi', moderator: dashMod(req),
        channel: channel.name, reason: `Cancellati ${deleted.size} messaggi`
      });
      res.json({ ok: true, count: deleted.size });
    } catch (e) {
      if (e?.code === 50034) return res.status(400).json({ error: 'Non posso cancellare messaggi più vecchi di 14 giorni' });
      apiError(res, e, 'Errore pulizia messaggi');
    }
  });

  app.post('/api/mod/lock', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModLock, req.body || {}, res);
    if (!data) return;
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const channel = guild.channels.cache.get(data.channelId);
      if (!channel) return res.status(404).json({ error: 'Canale non trovato' });
      if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.ManageChannels))) {
        return res.status(403).json({ error: 'Ti manca "Gestisci Canali"' });
      }
      if (!channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.ManageChannels)) {
        return res.status(403).json({ error: 'Il bot non può gestire questo canale' });
      }
      const everyone = guild.roles.everyone;
      const current = channel.permissionOverwrites.cache.get(everyone.id);
      if (current && current.deny.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(409).json({ error: 'Questo canale è già bloccato' });
      }
      await channel.permissionOverwrites.edit(everyone, { SendMessages: false });
      await logMod(guild, {
        type: 'Lock', title: 'Canale Bloccato', moderator: dashMod(req),
        channel: channel.name, reason: data.reason || 'Nessun motivo'
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore blocco canale'); }
  });

  app.post('/api/mod/unlock', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModUnlock, req.body || {}, res);
    if (!data) return;
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const channel = guild.channels.cache.get(data.channelId);
      if (!channel) return res.status(404).json({ error: 'Canale non trovato' });
      if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.ManageChannels))) {
        return res.status(403).json({ error: 'Ti manca "Gestisci Canali"' });
      }
      if (!channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.ManageChannels)) {
        return res.status(403).json({ error: 'Il bot non può gestire questo canale' });
      }
      const everyone = guild.roles.everyone;
      const current = channel.permissionOverwrites.cache.get(everyone.id);
      if (!current || !current.deny.has(PermissionsBitField.Flags.SendMessages)) {
        return res.status(409).json({ error: 'Questo canale non è bloccato' });
      }
      await channel.permissionOverwrites.edit(everyone, { SendMessages: null });
      await logMod(guild, {
        type: 'Unlock', title: 'Canale Sbloccato', moderator: dashMod(req), channel: channel.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore sblocco canale'); }
  });

  // ---------- Azioni su utente (come -warn, -timeout, -invite, -giverole, -removerole) ----------
  app.post('/api/mod/warn', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModWarn, req.body || {}, res);
    if (!data) return;
    if (data.userId === req.session.user.id) return res.status(400).json({ error: 'Non puoi eseguire azioni su te stesso' });
    if (data.userId === client.user.id) return res.status(400).json({ error: 'Non puoi warnare il bot' });
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const member = await guild.members.fetch(data.userId).catch(() => null);
      if (!member) return res.status(404).json({ error: 'Utente non nel server' });
      if (member.permissions.has(PermissionsBitField.Flags.Administrator)) return res.status(403).json({ error: 'Non puoi warnare un admin' });
      if (!(await actorCanActOn(guild, req.session.user.id, member))) return res.status(403).json({ error: 'Ruolo troppo alto per il tuo account' });
      await logMod(guild, {
        type: 'Warn', title: 'Warn', targetId: member.id, target: `${member.user.username} (${member.id})`,
        moderator: dashMod(req), reason: data.reason || 'Nessun motivo specificato'
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore warn'); }
  });

  app.post('/api/mod/timeout', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModTimeout, req.body || {}, res);
    if (!data) return;
    if (data.userId === req.session.user.id) return res.status(400).json({ error: 'Non puoi eseguire azioni su te stesso' });
    if (data.userId === client.user.id) return res.status(400).json({ error: 'Non puoi fare timeout al bot' });
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const member = await guild.members.fetch(data.userId).catch(() => null);
      if (!member) return res.status(404).json({ error: 'Utente non nel server' });
      if (member.permissions.has(PermissionsBitField.Flags.Administrator)) return res.status(403).json({ error: 'Non puoi fare timeout a un admin' });
      if (!guild.members.me.permissions.has(PermissionsBitField.Flags.ModerateMembers)) return res.status(403).json({ error: 'Il bot non ha "Modera Membri"' });
      if (!member.moderatable) return res.status(403).json({ error: 'Non posso fare timeout a questo utente' });
      if (!(await actorCanActOn(guild, req.session.user.id, member))) return res.status(403).json({ error: 'Ruolo troppo alto per il tuo account' });
      const reason = data.reason || 'Nessun motivo specificato';
      await member.timeout(data.seconds * 1000, reason);
      await logMod(guild, {
        type: 'Timeout', title: 'Timeout', targetId: member.id, target: `${member.user.username} (${member.id})`,
        moderator: dashMod(req), reason, duration: formatDuration(data.seconds)
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore timeout'); }
  });

  app.post('/api/mod/invite', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModInvite, req.body || {}, res);
    if (!data) return;
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const channel = guild.channels.cache.get(data.channelId);
      if (!channel || !channel.isTextBased()) return res.status(404).json({ error: 'Canale testuale non valido' });
      if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.CreateInstantInvite))) {
        return res.status(403).json({ error: 'Ti manca "Crea Invito"' });
      }
      if (!channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.CreateInstantInvite)) {
        return res.status(403).json({ error: 'Il bot non può creare inviti in questo canale' });
      }
      const target = await client.users.fetch(data.userId).catch(() => null);
      if (!target) return res.status(404).json({ error: 'Utente non trovato' });
      const invite = await channel.createInvite({
        maxUses: 1, maxAge: 3600, unique: true,
        reason: `Invito dalla dashboard (${req.session.user.username})`
      });
      const text = `${req.session.user.username} ti ha inviato un invito per il server **${guild.name}**\n${invite.url}\nValido per 1 utilizzo, scade tra 60 minuti.`;
      const sent = await dmUser(data.userId, { content: text });
      if (sent) return res.json({ ok: true, via: 'dm' });
      await channel.send({ content: `${target}\n${text}`, allowedMentions: { users: [data.userId] } }).catch(() => {});
      res.json({ ok: true, via: 'channel' });
    } catch (e) { apiError(res, e, 'Errore invito'); }
  });

  app.post('/api/mod/role', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaModRole, req.body || {}, res);
    if (!data) return;
    if (data.userId === req.session.user.id) return res.status(400).json({ error: 'Non puoi eseguire azioni su te stesso' });
    if (!(await assertGuildAccess(req, res, data.guildId))) return;
    try {
      const guild = client.guilds.cache.get(data.guildId);
      const botMember = guild.members.me;
      const role = guild.roles.cache.get(data.roleId);
      if (!role || role.name === '@everyone') return res.status(404).json({ error: 'Ruolo non trovato' });
      const member = await guild.members.fetch(data.userId).catch(() => null);
      if (!member) return res.status(404).json({ error: 'Utente non nel server' });
      if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.ManageRoles))) return res.status(403).json({ error: 'Ti manca "Gestisci Ruoli"' });
      if (!botMember.permissions.has(PermissionsBitField.Flags.ManageRoles)) return res.status(403).json({ error: 'Il bot non ha "Gestisci Ruoli"' });
      if (role.position >= botMember.roles.highest.position) return res.status(403).json({ error: 'Non posso gestire un ruolo più alto o uguale al mio' });
      if (!(await actorCanGrantRole(guild, req.session.user.id, role))) return res.status(403).json({ error: 'Non puoi gestire un ruolo più alto o uguale al tuo' });

      if (data.action === 'add') {
        if (member.roles.cache.has(role.id)) return res.status(409).json({ error: `L'utente ha già il ruolo ${role.name}` });
        await member.roles.add(role);
      } else {
        if (!member.roles.cache.has(role.id)) return res.status(409).json({ error: `L'utente non ha il ruolo ${role.name}` });
        await member.roles.remove(role);
      }
      await logMod(guild, {
        type: data.action === 'add' ? 'Ruolo Aggiunto' : 'Ruolo Rimosso',
        title: data.action === 'add' ? 'Ruolo assegnato' : 'Ruolo rimosso',
        targetId: member.id,
        target: `${member.user.username} (${member.id})`,
        moderator: dashMod(req),
        reason: role.name
      });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore gestione ruolo'); }
  });

  app.get('/api/user-lookup/:userId', requireAuth, async (req, res) => {
    const userId = req.params.userId;
    if (!/^\d{17,20}$/.test(userId)) return res.status(400).json({ error: 'ID non valido' });
    try {
      const user = await client.users.fetch(userId).catch(() => null);
      if (!user) return res.status(404).json({ error: 'Utente non trovato' });
      const allowed = await allowedGuildIds(req.session.user.id, 'moderation');
      const memberships = [];
      for (const guild of client.guilds.cache.values()) {
        if (!allowed.has(guild.id)) continue;
        const member = await guild.members.fetch(userId).catch(() => null);
        if (member) memberships.push({ guildId: guild.id, guildName: guild.name, joinedAt: member.joinedAt, roles: member.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name) });
      }
      res.json({ id: user.id, username: user.username, tag: user.tag, bot: user.bot, avatar: user.displayAvatarURL({ size: 128 }), createdAt: user.createdAt, memberships });
    } catch (e) { apiError(res, e, 'Errore lookup utente'); }
  });

  app.post('/api/user-action', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaUserAction, req.body || {}, res);
    if (!data) return;
    const { action, userId, guildId, reason } = data;
    if (userId === req.session.user.id) return res.status(400).json({ error: 'Non puoi eseguire azioni su te stesso' });
    if (userId === client.user.id) return res.status(400).json({ error: 'Non puoi eseguire azioni sul bot' });
    try {
      if (!(await assertGuildAccess(req, res, guildId))) return;
      const guild = client.guilds.cache.get(guildId);
      const botMember = guild.members.me;
      if (!botMember) return res.status(500).json({ error: 'Bot non nel server' });
      const r = (reason || `Azione da dashboard (${req.session.user.username})`).slice(0, 512);

      if (action === 'kick') {
        if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.KickMembers))) return res.status(403).json({ error: 'Ti manca "Espelli Membri"' });
        if (!botMember.permissions.has('KickMembers')) return res.status(403).json({ error: 'Il bot non ha "Espelli Membri"' });
        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) return res.status(404).json({ error: 'Utente non nel server' });
        if (member.id === guild.ownerId) return res.status(403).json({ error: 'Non puoi espellere il proprietario' });
        if (member.roles.highest.position >= botMember.roles.highest.position) return res.status(403).json({ error: 'Ruolo troppo alto per il bot' });
        if (!(await actorCanActOn(guild, req.session.user.id, member))) return res.status(403).json({ error: 'Ruolo troppo alto per il tuo account' });
        if (!member.kickable) return res.status(403).json({ error: 'Utente non espellibile' });
        await member.kick(r);
        await logMod(guild, { type: 'Kick (dashboard)', targetId: userId, target: `${member.user.tag} (${userId})`, moderator: dashMod(req), reason: r, channel: 'Web Dashboard' });
      }

      if (action === 'ban') {
        if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.BanMembers))) return res.status(403).json({ error: 'Ti manca "Banna Membri"' });
        if (!botMember.permissions.has('BanMembers')) return res.status(403).json({ error: 'Il bot non ha "Banna Membri"' });
        if (userId === guild.ownerId) return res.status(403).json({ error: 'Non puoi bannare il proprietario' });
        const member = await guild.members.fetch(userId).catch(() => null);
        if (member) {
          if (member.roles.highest.position >= botMember.roles.highest.position) return res.status(403).json({ error: 'Ruolo troppo alto per il bot' });
          if (!member.bannable) return res.status(403).json({ error: 'Utente non bannabile' });
          if (!(await actorCanActOn(guild, req.session.user.id, member))) return res.status(403).json({ error: 'Ruolo troppo alto per il tuo account' });
        }
        // DM prima del ban: dopo il ban il bot potrebbe non condividere più un server con l'utente
        const targetUser = await client.users.fetch(userId).catch(() => null);
        if (targetUser) {
          await dmUser(userId, { embeds: [makeEmbed('Sei stato bannato', `Sei stato bannato dal server **${guild.name}**.\n\n**Motivo:** ${r}`, 0xFF0000)] });
        }
        await guild.members.ban(userId, { reason: r });
        await logMod(guild, { type: 'Ban (dashboard)', targetId: userId, target: member ? `${member.user.tag} (${userId})` : userId, moderator: dashMod(req), reason: r, channel: 'Web Dashboard' });
      }

      if (action === 'unban') {
        if (!(await actorHas(guild, req.session.user.id, PermissionsBitField.Flags.BanMembers))) return res.status(403).json({ error: 'Ti manca "Banna Membri"' });
        if (!botMember.permissions.has('BanMembers')) return res.status(403).json({ error: 'Il bot non ha "Banna Membri"' });
        const ban = await guild.bans.fetch(userId).catch(e => { if (e.code === 10026) return null; throw e; });
        if (!ban) return res.status(404).json({ error: 'Utente non bannato' });
        await unbanWithInvite(guild, userId, req.session.user.username);
        await logMod(guild, { type: 'Unban (dashboard)', targetId: userId, target: `${ban.user.tag} (${userId})`, moderator: dashMod(req), reason: r, channel: 'Web Dashboard' });
      }

      try {
        storage.saveDashboardAccess(req.session.user.id, `${action.toUpperCase()} ${userId} su ${guild.name}`, (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '-', (req.headers['user-agent'] || '').slice(0, 300));
      } catch {}

      res.json({ ok: true, action, userId, guildId });
    } catch (e) { apiError(res, e, 'Errore azione utente'); }
  });

  app.get('/api/reminders', requireAuth, async (req, res) => {
    try {
      const allowed = await allowedGuildIds(req.session.user.id, 'communications');
      const rows = storage.getAllReminders
        ? storage.getAllReminders(200)
        : storage.db.prepare('SELECT * FROM reminders ORDER BY remind_at DESC LIMIT 200').all();
      res.json(rows.filter(r => allowed.has(r.guild_id)));
    } catch (e) { apiError(res, e); }
  });

  app.post('/api/reminders', requireAuth, async (req, res) => {
    const data = parseOrFail(schemaReminder, req.body || {}, res);
    if (!data) return;
    const guild = client.guilds.cache.get(data.guildId);
    if (!guild || !guild.channels.cache.has(data.channelId)) return res.status(400).json({ error: 'Server o canale non valido' });
    if (!(await canManageGuild(req.session.user.id, guild, 'communications'))) return res.status(403).json({ error: 'Non hai i permessi su questo server' });
    const ms = ((data.hours * 60) + data.minutes) * 60000;
    if (ms < 60000 || ms > 30 * 24 * 60 * 60 * 1000) return res.status(400).json({ error: 'Scegli ore e minuti: minimo 1 minuto, massimo 30 giorni' });
    try {
      const id = storage.addReminder(req.session.user.id, data.guildId, data.channelId, data.content, new Date(Date.now() + ms));
      res.json({ ok: true, id });
    } catch (e) { apiError(res, e); }
  });

  // ==================== PAGINE HTML ====================
  const pageHandler = (page, paramsFn) => (req, res, next) => {
    if (!req.sessionID) {
      return res.status(500).send('Errore: sessione non inizializzata');
    }
    req.session.save(async (saveErr) => {
      if (saveErr) { log.err('session save', saveErr); return res.status(500).send('Errore sessione'); }
      try {
        const params = paramsFn ? paramsFn(req) : {};
        let token = '';
        try {
          token = generateCsrfToken(req, res);
          if (!token) log.warn(`csrf token vuoto per ${page} (sessione: ${req.sessionID})`);
        } catch (e) { log.err(`csrf gen ${page}`, e); }
        const security = {
          csrfToken: token,
          permissions: [...req.dashboardAccess.permissions],
          isDashboardManager: req.dashboardAccess.manager
        };
        if (page === 'dashboard') {
          security.canUseGlobalBlacklist = await canUseGlobalBlacklist(req.session.user.id);
          security.canExportFullBackup = isEnvAdmin(req.session.user.id);
        }
        res.send(renderLayout(req.session.user, page, params, security));
      } catch (e) {
        log.err(`page ${page}`, e);
        res.status(500).send('Errore rendering');
      }
    });
  };

  app.get('/dashboard', requireAuth, pageHandler('dashboard'));
  app.get('/resources', async (req, res) => {
    let user = null;
    let security = { isPublicResources: true };
    if (req.session.user) {
      try {
        const access = await getDashboardAccess(req.session.user.id);
        if (access.authorized) {
          user = req.session.user;
          security = {
            permissions: [...access.permissions],
            isDashboardManager: access.manager
          };
        }
      } catch (e) {
        log.err('public resources access lookup', e);
      }
    }
    res.send(renderLayout(user, 'resources', {}, security));
  });
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
  app.get('/reminders', requireAuth, pageHandler('reminders'));
  app.get('/permissions', requireAuth, pageHandler('permissions'));
  
  // ROTTA LOBBY (HTML)
  app.get('/lobbies', requireAuth, pageHandler('lobbies'));

  app.use((err, req, res, next) => {
    log.err('web-error', err);
    if (req.path.startsWith('/api/')) return res.status(500).json({ error: 'Errore interno' });
    res.status(500).send('Errore interno');
  });

  const server = app.listen(PORT, HOST, () => {
    log.ok(`🌐 Dashboard web su http://${HOST}:${PORT}`);
    log.info(`   Login URL: ${DASHBOARD_URL}/auth/login`);
    log.info(`   Sicurezza: helmet ✓ rate-limit ✓ csrf ✓ zod ✓ cache-auth ✓ cookie-parser ✓`);
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
  const viewer = user || { id: '', global_name: '', username: 'Visitatore', avatar: null };
  const name = escapeHtml(viewer.global_name || viewer.username);
  const avatar = viewer.avatar ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(viewer.id)}/${encodeURIComponent(viewer.avatar)}.png?size=64` : `https://cdn.discordapp.com/embed/avatars/0.png`;
  const csrfToken = security.csrfToken || '';
  const safeQ = escapeHtml(params.q || '');
  const permissions = new Set(security.permissions || []);
  const canViewDashboard = permissions.has('overview') || permissions.has('global_blacklist');
  const canViewResources = security.isPublicResources || permissions.size > 0;
  const pageTitles = {
    dashboard: 'Dashboard',
    modlogs: 'Mod Logs',
    notes: 'Note',
    tickets: 'Ticket',
    commands: 'Comandi',
    config: 'Configurazione',
    charts: 'Grafici',
    top: 'Classifiche',
    user: 'Profilo utente',
    search: 'Ricerca',
    accesslogs: 'Log accessi',
    messages: 'Messaggi',
    userActions: 'Gestione utenti',
    reminders: 'Reminder',
    lobbies: 'Lobby',
    permissions: 'Permessi dashboard',
    resources: 'Resources'
  };
  const pageTitle = pageTitles[page] || 'Dashboard';
  const navSections = [
    { label: 'Workspace', items: [
      { href: '/dashboard', page: 'dashboard', feature: 'dashboard', icon: '◈', label: 'Dashboard' },
      { href: '/charts', page: 'charts', feature: 'analytics', icon: '📈', label: 'Grafici' },
      { href: '/top', page: 'top', feature: 'analytics', icon: '🏆', label: 'Top' },
      { href: '/resources', page: 'resources', feature: 'resources', icon: '🔗', label: 'Resources' }
    ] },
    { label: 'Moderazione', items: [
      { href: '/search', page: 'search', feature: 'moderation', icon: '🔎', label: 'Ricerca' },
      { href: '/modlogs', page: 'modlogs', feature: 'moderation', icon: '📋', label: 'Mod Logs' },
      { href: '/notes', page: 'notes', feature: 'moderation', icon: '📝', label: 'Note' },
      { href: '/user-actions', page: 'userActions', feature: 'moderation', icon: '🛠️', label: 'Gestione Utenti' },
      { href: '/access-logs', page: 'accesslogs', feature: 'audit', icon: '🔐', label: 'Accessi' }
    ] },
    { label: 'Bot', items: [
      { href: '/tickets', page: 'tickets', feature: 'tickets', icon: '🎫', label: 'Ticket' },
      { href: '/commands', page: 'commands', feature: 'settings', icon: '🔧', label: 'Comandi' },
      { href: '/config', page: 'config', feature: 'settings', icon: '⚙️', label: 'Config' },
      { href: '/reminders', page: 'reminders', feature: 'communications', icon: '⏰', label: 'Reminder' },
      { href: '/messages', page: 'messages', feature: 'communications', icon: '✉️', label: 'Messaggi' },
      { href: '/lobbies', page: 'lobbies', feature: 'lobbies', icon: '🗺️', label: 'Lobby' }
    ] },
    { label: 'Amministrazione', items: [
      { href: '/permissions', page: 'permissions', feature: 'manager', icon: '🔑', label: 'Permessi' }
    ] }
  ];
  const navItems = navSections.flatMap(section => section.items).filter(item =>
    item.feature === 'manager' ? security.isDashboardManager :
      item.feature === 'resources' ? canViewResources :
      item.feature === 'dashboard' ? canViewDashboard : permissions.has(item.feature)
  );
  const sidebarHome = navItems[0]?.href || '/dashboard';
  const searchControl = permissions.has('moderation') ? `
    <div class="search-box">
      <form action="/search" method="get">
        <input type="text" name="q" placeholder="Cerca utente, motivo, moderatore..." value="${safeQ}" maxlength="100">
        <button type="submit" class="secondary">Cerca</button>
      </form>
    </div>` : '';
  const sidebarNavigation = navSections.map(section => {
    const items = section.items.filter(item =>
      item.feature === 'manager' ? security.isDashboardManager :
        item.feature === 'resources' ? canViewResources :
        item.feature === 'dashboard' ? canViewDashboard : permissions.has(item.feature)
    );
    if (!items.length) return '';
    return `<div class="nav-label">${section.label}</div>${items.map(item =>
      `<a href="${item.href}" class="${page === item.page ? 'active' : ''}"><span class="nav-icon">${item.icon}</span>${item.label}</a>`
    ).join('')}`;
  }).join('');

  // Ogni pagina viene generata solo quando è quella richiesta
  const renderers = {
    dashboard: () => renderDashboardContent(security),
    resources: () => renderResourcesContent(!!security.isDashboardManager),
    modlogs: () => renderModlogsContent(),
    notes: () => renderNotesContent(),
    tickets: () => renderTicketsContent(),
    commands: () => renderCommandsContent(),
    config: () => renderConfigContent(),
    charts: () => renderChartsContent(),
    top: () => renderTopContent(),
    user: () => renderUserContent(params.userId),
    search: () => renderSearchContent(params.q || ''),
    accesslogs: () => renderAccessLogsContent(),
    messages: () => renderMessagesContent(),
    userActions: () => renderUserActionsContent(params.userId || ''),
    reminders: () => renderRemindersContent(),
    lobbies: () => renderLobbiesContent(),
    permissions: () => renderPermissionsContent()
  };
  const body = renderers[page] ? renderers[page]() : '<p>Pagina non trovata</p>';

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="${escapeHtml(csrfToken)}">
<title>Dashboard - ${escapeHtml(page)}</title>
<script>
  window.__CSRF__ = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  console.log('[csrf] iniziale:', window.__CSRF__ ? 'OK (' + window.__CSRF__.length + ' char)' : 'VUOTO');

  window.__refreshCsrf = async function () {
    try {
      const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
      if (res.ok) {
        const data = await res.json();
        window.__CSRF__ = data.csrfToken || '';
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) meta.content = window.__CSRF__;
        console.log('[csrf] refresh:', window.__CSRF__ ? 'OK (' + window.__CSRF__.length + ' char)' : 'VUOTO');
      } else {
        const err = await res.json().catch(() => ({}));
        console.error('[csrf] refresh HTTP', res.status, err);
      }
    } catch (e) { console.error('[csrf] refresh error', e); }
  };

  window.apiFetch = async function (url, options = {}) {
    if (!window.__CSRF__) await window.__refreshCsrf();

    const opts = Object.assign({}, options);
    opts.credentials = 'same-origin';
    opts.headers = Object.assign({}, opts.headers || {});

    const method = (opts.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      opts.headers['X-CSRF-Token'] = window.__CSRF__;
      if (opts.body && typeof opts.body === 'string' && !opts.headers['Content-Type']) {
        opts.headers['Content-Type'] = 'application/json';
      }
    }

    console.log('[apiFetch]', method, url, '| CSRF:', opts.headers['X-CSRF-Token'] ? 'sì' : 'NO');

    let res = await fetch(url, opts);
    console.log('[apiFetch]', method, url, '→', res.status);

    if (res.status === 403) {
      let body = null;
      try { body = await res.clone().json(); } catch {}
      if (body && /csrf/i.test(body.error || '')) {
        console.warn('[apiFetch] CSRF 403, rigenero token e riprovo');
        await window.__refreshCsrf();
        opts.headers['X-CSRF-Token'] = window.__CSRF__;
        res = await fetch(url, opts);
        console.log('[apiFetch] retry →', res.status);
      }
    }

    return res;
  };

  window.postJson = async function (url, body) {
    const res = await apiFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data: data };
  };

  async function logoutAll() {
    if (!confirm('Vuoi disconnetterti da TUTTE le sessioni?')) return;
    const res = await apiFetch('/api/logout-all', { method: 'POST' });
    if (res.ok) window.location.href = '/';
    else alert('Errore logout globale');
  }
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"></script>
<style>
  :root { color-scheme: dark; --bg: #090a12; --panel: #11131d; --panel-raised: #171a29; --border: #282b3c; --muted: #9298aa; --text: #f3f4fa; --accent: #7867f5; --accent-bright: #aa9dff; --accent-blue: #79a5ff; --danger: #f06478; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { min-height: 100vh; background: radial-gradient(ellipse at 70% -20%, rgba(107, 91, 237, .15), transparent 42%), radial-gradient(ellipse at 98% 20%, rgba(59, 117, 230, .07), transparent 36%), var(--bg); color: var(--text); font: 14px/1.55 Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  button, input, select, textarea { font: inherit; }
  button { cursor: pointer; }
  a { color: var(--accent-bright); text-decoration: none; }
  .app-sidebar { position: fixed; z-index: 20; inset: 0 auto 0 0; display: flex; flex-direction: column; width: 252px; padding: 25px 16px 18px; background: rgba(13, 14, 20, .96); border-right: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: 12px; padding: 0 10px 27px; color: var(--text); }
  .brand-mark { display: grid; width: 38px; height: 38px; place-items: center; border: 1px solid rgba(148, 131, 255, .48); border-radius: 12px; background: linear-gradient(145deg, #30265d, #171927); color: #d6ceff; font-size: 18px; box-shadow: 0 6px 24px rgba(99, 85, 235, .2); }
  .brand strong { display: block; font-size: 13px; letter-spacing: .11em; }
  .brand small { display: block; margin-top: 2px; color: #7e8396; font-size: 10px; letter-spacing: .12em; }
  .nav-label { padding: 12px 12px 8px; color: #71778a; font-size: 10px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
  .sidebar-nav { display: flex; flex: 1; flex-direction: column; gap: 4px; overflow-y: auto; }
  .sidebar-nav a { display: flex; align-items: center; gap: 12px; min-height: 42px; padding: 9px 12px; border: 1px solid transparent; border-radius: 10px; color: #9da2b2; font-size: 13px; transition: background .18s ease, color .18s ease, border-color .18s ease, transform .18s ease; }
  .sidebar-nav a:hover { transform: translateX(2px); background: #171923; color: #fff; }
  .sidebar-nav a.active { border-color: rgba(144, 126, 255, .28); background: linear-gradient(90deg, rgba(113, 92, 238, .23), rgba(66, 118, 236, .07)); color: #d8d1ff; box-shadow: inset 2px 0 #9383ff; }
  .nav-icon { width: 19px; text-align: center; font-size: 15px; }
  .sidebar-footer { margin-top: 16px; padding: 14px 12px 0; border-top: 1px solid var(--border); color: #777d90; font-size: 11px; }
  .sidebar-overlay { display: none; }
  .app-main { width: min(100% - 252px, 1700px); min-height: 100vh; margin-left: 252px; padding: 23px clamp(20px, 3.2vw, 52px) 48px; }
  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 22px; min-height: 66px; margin-bottom: 29px; padding-bottom: 20px; border-bottom: 1px solid rgba(46, 49, 65, .75); }
  .topbar-left, .topbar-actions, .user { display: flex; align-items: center; }
  .topbar-left { gap: 14px; min-width: 0; }
  .page-heading .eyebrow { color: #858ba0; font-size: 10px; font-weight: 700; letter-spacing: .14em; }
  h1 { margin-top: 2px; font-size: clamp(20px, 2vw, 25px); font-weight: 650; letter-spacing: -.035em; }
  .topbar-actions { justify-content: flex-end; gap: 20px; }
  .search-box { width: min(320px, 28vw); }
  .search-box form { display: flex; gap: 8px; }
  .search-box input, .search-box button { margin: 0; }
  .user { gap: 10px; white-space: nowrap; }
  .user img { width: 36px; height: 36px; border: 1px solid #343747; border-radius: 50%; object-fit: cover; }
  .user-name { max-width: 140px; overflow: hidden; color: #d7d9e3; font-size: 12px; text-overflow: ellipsis; }
  .user-actions { display: flex; gap: 7px; }
  .menu-toggle { display: none; width: 38px; height: 38px; border: 1px solid var(--border); border-radius: 10px; background: var(--panel); color: var(--text); font-size: 18px; }
  .content-area { width: 100%; min-width: 0; animation: enter .32s ease both; }
  @keyframes enter { from { opacity: 0; transform: translateY(7px); } to { opacity: 1; transform: translateY(0); } }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 190px), 1fr)); gap: 14px; width: 100%; margin: 0 0 24px; }
  .resources-hero { margin-bottom: 30px; }
  .resources-hero .eyebrow { color: var(--accent-bright); font-size: 10px; font-weight: 700; letter-spacing: .16em; }
  .resources-hero h2 { margin: 4px 0 6px; font-size: clamp(32px, 5vw, 52px); line-height: 1.08; letter-spacing: -.045em; }
  .resources-hero p:last-child { color: var(--muted); font-size: 14px; }
  .resources-section-heading { margin: 0 0 16px; }
  .resources-section-heading h2 { margin: 0 0 3px; font-size: 19px; }
  .resources-section-heading p { color: var(--muted); font-size: 12px; }
  .resources-grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); }
  .resource-card { display: flex; min-height: 250px; flex-direction: column; padding: 21px; }
  .resource-card-header { display: flex; align-items: center; gap: 13px; margin-bottom: 15px; }
  .resource-card-icon { display: grid; width: 48px; height: 48px; flex: 0 0 48px; place-items: center; overflow: hidden; border: 1px solid #37333a; border-radius: 50%; background: #191a20; color: var(--accent-bright); font-size: 18px; font-weight: 700; }
  .resource-card-icon img { width: 100%; height: 100%; object-fit: cover; }
  .resource-card-type { color: #888b98; font-size: 9px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; }
  .resource-card h3 { margin-top: 2px; font-size: 17px; line-height: 1.3; overflow-wrap: anywhere; }
  .resource-card-meta { display: flex; gap: 15px; margin: 0 0 12px; color: #b6b8c2; font-size: 11px; }
  .resource-card-meta strong { color: var(--accent-bright); }
  .resource-card-copy { min-height: 40px; margin-bottom: 14px; color: #999ca8; font-size: 12px; }
  .resource-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 19px; }
  .resource-tag { padding: 4px 9px; border: 1px solid #30313a; border-radius: 999px; color: #b5b7c1; font-size: 10px; }
  .resource-card-actions { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-top: auto; }
  .resource-card-actions .resource-server-link { padding: 7px 11px; border: 1px solid #343641; border-radius: 9px; background: #1c1e29; color: #d7d9e3; font-size: 11px; font-weight: 650; transition: background .16s ease, border-color .16s ease; }
  .resource-card-actions .resource-server-link:hover { border-color: #514b80; background: #262638; }
  .resource-card-actions .resource-link { color: var(--accent-blue); font-size: 11px; font-weight: 700; }
  .resources-empty { color: var(--muted); text-align: center; }
  .card, .section { border: 1px solid var(--border); background: linear-gradient(145deg, rgba(22, 24, 34, .96), rgba(15, 17, 24, .98)); box-shadow: 0 12px 35px rgba(0, 0, 0, .13); }
  .card { position: relative; min-height: 112px; overflow: hidden; padding: 18px 19px; border-radius: 15px; transition: transform .2s ease, border-color .2s ease, background .2s ease; }
  .card::after { position: absolute; right: -26px; bottom: -48px; width: 104px; height: 104px; border-radius: 50%; background: rgba(112, 99, 245, .1); content: ""; filter: blur(2px); }
  .card:hover { transform: translateY(-2px); border-color: #4a4680; }
  .card h2 { position: relative; z-index: 1; margin-bottom: 12px; color: #969bad; font-size: 10px; font-weight: 700; letter-spacing: .11em; text-transform: uppercase; }
  .card .value { position: relative; z-index: 1; color: var(--accent-bright); font-size: clamp(25px, 3vw, 32px); font-weight: 700; letter-spacing: -.04em; }
  .section { width: 100%; margin: 0 0 17px; padding: clamp(16px, 2.2vw, 24px); overflow-x: auto; border-radius: 15px; }
  .section h2 { margin-bottom: 15px; font-size: 16px; font-weight: 650; letter-spacing: -.015em; }
  table { width: 100%; min-width: 640px; border-collapse: collapse; }
  th, td { padding: 11px 10px; border-bottom: 1px solid #282b38; font-size: 13px; text-align: left; vertical-align: top; }
  th { color: #898fa2; font-size: 10px; letter-spacing: .1em; text-transform: uppercase; }
  tr:hover td { background: rgba(255, 255, 255, .025); }
  button { padding: 9px 14px; border: 1px solid transparent; border-radius: 9px; background: linear-gradient(135deg, #8e7eff, #5879e8); color: #fff; font-size: 12px; font-weight: 700; transition: filter .16s ease, transform .16s ease, border-color .16s ease; }
  button:hover { filter: brightness(1.12); transform: translateY(-1px); }
  button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 2px solid #aa9dff; outline-offset: 2px; }
  button:disabled { opacity: .6; cursor: not-allowed; }
  button.danger { background: #a83e55; }
  button.danger:hover { background: #bf4962; }
  button.small { padding: 6px 10px; font-size: 11px; }
  button.secondary { border-color: #303342; background: #1c1e29; color: #c4c7d2; }
  button.secondary:hover { border-color: #474b60; background: #252837; }
  input, select, textarea { width: 100%; margin-bottom: 10px; padding: 10px 12px; border: 1px solid #303342; border-radius: 9px; background: #0e1017; color: var(--text); font-size: 13px; }
  input::placeholder, textarea::placeholder { color: #747a8d; }
  .form-row { display: flex; align-items: flex-start; flex-wrap: wrap; gap: 10px; }
  .form-row input, .form-row select { min-width: 150px; flex: 1; }
  .loading { color: #8c91a2; font-style: italic; }
  a.user-link { border-bottom: 1px dashed var(--accent); color: var(--accent-bright); }
  a.user-link:hover { border-bottom-style: solid; color: #c4b8ff; }
  .filter-bar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
  .filter-bar select, .filter-bar input { max-width: 250px; }
  .tool-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:16px; }
  .tool-heading h2 { margin-bottom:5px; }
  .tool-subtitle { margin:0; color:#8c91a2; font-size:12px; line-height:1.6; }
  .tool-stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin:14px 0; }
  .tool-stat { padding:13px 15px; border:1px solid #292c3a; border-radius:11px; background:linear-gradient(145deg,#151722,#101117); }
  .tool-stat strong { display:block; color:#e7e8ef; font-size:20px; }
  .tool-stat span { display:block; margin-top:3px; color:#8c91a2; font-size:10px; text-transform:uppercase; letter-spacing:.08em; }
  .tool-controls { display:flex; align-items:center; flex-wrap:wrap; gap:9px; margin:14px 0; }
  .tool-controls input,.tool-controls select { flex:1 1 190px; width:auto; max-width:330px; margin:0; }
  .tool-empty { padding:24px; border:1px dashed #343746; border-radius:11px; color:#9297a8; text-align:center; }
  .tool-preview { padding:14px; border:1px solid #292c3a; border-radius:10px; background:#0e1017; color:#d5d7e0; white-space:pre-wrap; overflow-wrap:anywhere; }
  .tool-table-wrap { overflow-x:auto; }
  .mention-help { margin:7px 0 12px; padding:10px 12px; border-left:2px solid #8068ed; border-radius:0 8px 8px 0; background:#151621; color:#aeb2c1; font-size:12px; line-height:1.6; }
  .mention-help code { color:#d2c8ff; }
  .inline-check { display:flex; align-items:center; gap:9px; margin:2px 0 14px; color:#c4c7d2; font-size:12px; }
  .inline-check input { width:auto; margin:0; accent-color:#8068ed; }
  .field-meta { display:flex; justify-content:space-between; gap:10px; margin:-5px 0 10px; color:#858a9b; font-size:11px; }
  .ticket-actions { display:flex; flex-wrap:wrap; align-items:center; gap:6px; min-width:245px; }
  .ticket-actions select { width:auto; min-width:105px; margin:0; padding:6px 8px; }
  @media(max-width:600px) {
    .tool-heading { flex-direction:column; }
    .tool-controls input,.tool-controls select { flex-basis:100%; max-width:none; }
    .ticket-actions { min-width:220px; }
  }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .badge.kick, .badge.warn { background: #9c6a23; color: #fff1d2; }
  .badge.ban { background: #a83e55; color: #fff; }
  .badge.timeout { background: #624bcc; color: #fff; }
  .badge.default { background: #343747; color: #e2e4ec; }
  .charts-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
  .chart-box, .config-block { padding: 17px; border: 1px solid #292c3a; border-radius: 12px; background: #0e1017; }
  .config-block { margin-bottom: 16px; }
  .config-block h3 { margin-bottom: 12px; color: #d4d6e0; font-size: 14px; }
  .success { margin-top: 8px; color: #64d6a0; font-size: 13px; }
  .error { color: var(--danger); font-size: 13px; }
  code { padding: 2px 6px; border-radius: 5px; background: #0e1017; font-size: 12px; }
  .export-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
  .export-bar a { padding: 7px 11px; border: 1px solid #303342; border-radius: 8px; background: #1b1d28; color: #c4c7d2; font-size: 11px; }
  .export-bar a:hover { border-color: #514778; color: #ddd5ff; }
  .dashboard-hero { position: relative; display: flex; min-height: 355px; flex-direction: column; align-items: center; justify-content: center; overflow: hidden; padding: 24px 18px 30px; text-align: center; }
  .hero-mark { display: grid; width: 76px; height: 76px; margin-bottom: 20px; place-items: center; border: 1px solid rgba(164, 146, 255, .68); border-radius: 50%; background: radial-gradient(circle at 35% 25%, #392d70, #10121c 72%); color: #d6ceff; font-size: 34px; font-weight: 700; box-shadow: 0 0 42px rgba(105, 91, 239, .2), inset 0 0 20px rgba(115, 123, 255, .1); }
  .hero-eyebrow { color: #a2a3a8; font-size: 9px; font-weight: 700; letter-spacing: .22em; }
  .dashboard-hero h2 { margin-top: 12px; font-size: clamp(34px, 5vw, 57px); font-weight: 750; line-height: 1.03; letter-spacing: -.055em; }
  .dashboard-hero h2 span { color: #898b94; }
  .hero-description { max-width: 520px; margin-top: 15px; color: #a0a2aa; font-size: 13px; }
  .hero-actions { display: flex; flex-wrap: wrap; justify-content: center; gap: 9px; margin-top: 21px; }
  .hero-button { display: inline-flex; min-height: 38px; align-items: center; justify-content: center; gap: 9px; padding: 9px 14px; border: 1px solid #34353a; border-radius: 9px; color: #e7e7e9; font-size: 11px; font-weight: 650; transition: transform .18s ease, border-color .18s ease, background .18s ease; }
  .hero-button:hover { transform: translateY(-2px); border-color: #7770bd; color: #fff; }
  .hero-button-primary { border-color: #9383ff; background: linear-gradient(135deg, #8e7eff, #5879e8); color: #fff; }
  .hero-button-primary:hover { color: #fff; }
  .hero-button-secondary { background: #17181d; }
  .hero-button-quiet { border-color: transparent; color: #aaaab0; }
  .hero-status { display: inline-flex; align-items: center; gap: 8px; margin-top: 17px; padding: 6px 12px; border: 1px solid #292a30; border-radius: 999px; background: rgba(17, 18, 22, .78); color: #b7b8be; font-size: 10px; }
  .status-led { width: 7px; height: 7px; flex: 0 0 auto; border-radius: 50%; background: #85858b; }
  .status-led.online { background: #54d89a; box-shadow: 0 0 9px rgba(84, 216, 154, .7); }
  .status-led.offline { background: #f06478; box-shadow: 0 0 9px rgba(240, 100, 120, .5); }
  .status-led.checking { background: #91aaff; animation: pulse 1.1s ease-in-out infinite alternate; }
  @keyframes pulse { to { opacity: .35; } }
  .status-panel { padding: 19px 21px; }
  .status-panel-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; margin-bottom: 17px; }
  .status-panel-heading h2 { margin: 4px 0 0; }
  .status-updated { color: #777b87; font-size: 10px; }
  .status-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
  .status-item { display: flex; min-height: 72px; flex-direction: column; justify-content: space-between; gap: 8px; padding: 12px 13px; border: 1px solid #292b34; border-radius: 10px; background: rgba(9, 10, 15, .55); }
  .status-item-label { color: #8c909b; font-size: 10px; }
  .status-value { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 650; }
  .status-value::before { width: 6px; height: 6px; border-radius: 50%; background: currentColor; content: ""; }
  .status-value.online { color: #72d6a5; }
  .status-value.offline { color: #f17886; }
  .status-value.checking { color: #a4baff; }
  .dashboard-stats { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 16px; }
  .permissions-hero { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 22px; }
  .permissions-hero h2 { margin: 0 0 5px; font-size: 20px; }
  .permissions-help { max-width: 760px; color: #9da2b2; font-size: 12px; }
  .permissions-badge { flex: 0 0 auto; padding: 7px 10px; border: 1px solid rgba(151, 132, 255, .28); border-radius: 999px; background: rgba(117, 97, 239, .12); color: #c5baff; font-size: 10px; font-weight: 700; }
  .permissions-controls { display: grid; grid-template-columns: minmax(180px, 1fr) minmax(180px, 1fr); gap: 12px; padding: 16px; border: 1px solid #292c38; border-radius: 12px; background: rgba(9, 10, 15, .55); }
  .permissions-controls label { display: block; color: #9da2b2; font-size: 11px; }
  .permissions-controls select { margin: 5px 0 0; }
  .permissions-editor { margin-top: 21px; }
  .permissions-editor-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 15px; margin-bottom: 12px; }
  .permissions-editor-heading h3 { font-size: 14px; }
  .permissions-editor-heading p { margin-top: 3px; color: #818697; font-size: 11px; }
  .permission-count { color: #b6aaff !important; white-space: nowrap; }
  .permission-toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 11px; }
  .permission-toolbar button { padding: 7px 10px; }
  .permission-toolbar .permission-reload { margin-left: auto; }
  .permission-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
  .permission-option { display: flex; align-items: flex-start; gap: 11px; min-height: 76px; padding: 13px; border: 1px solid #2a2d37; border-radius: 10px; background: #101117; color: #d5d7df; cursor: pointer; transition: background .16s ease, border-color .16s ease, transform .16s ease; }
  .permission-option:hover { transform: translateY(-1px); border-color: #514b80; background: #151722; }
  .permission-option:has(input:checked) { border-color: rgba(150, 131, 255, .54); background: linear-gradient(120deg, rgba(117, 97, 239, .16), rgba(16, 18, 27, .95) 65%); }
  .permission-option input { width: 17px; height: 17px; flex: 0 0 auto; margin: 1px 0 0; accent-color: #8e7eff; }
  .permission-option strong { display: block; font-size: 12px; font-weight: 650; }
  .permission-option small { display: block; margin-top: 4px; color: #8d91a0; font-size: 10px; line-height: 1.45; }
  .permissions-savebar { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-top: 18px; padding-top: 15px; border-top: 1px solid #292c38; }
  .permission-message { min-height: 20px; font-size: 11px; }
  .permission-message.error { color: #f17886; }
  .permission-message.success { color: #72d6a5; }
  .permission-message.pending { color: #a4baff; }
  .permissions-save { min-width: 155px; }
  @media (max-width: 1050px) {
    .app-main { width: calc(100% - 232px); margin-left: 232px; padding-right: 22px; padding-left: 22px; }
    .app-sidebar { width: 232px; }
    .topbar { gap: 14px; }
    .topbar-actions { gap: 12px; }
    .user-name { display: none; }
  }
  @media (max-width: 760px) {
    .app-sidebar { width: min(290px, calc(100vw - 54px)); transform: translateX(-102%); transition: transform .24s ease; }
    body.sidebar-open .app-sidebar { transform: translateX(0); }
    .sidebar-overlay { position: fixed; z-index: 19; inset: 0; border: 0; border-radius: 0; background: rgba(3, 4, 8, .68); opacity: 0; pointer-events: none; transition: opacity .24s ease; }
    body.sidebar-open .sidebar-overlay { display: block; opacity: 1; pointer-events: auto; }
    .app-main { width: 100%; margin-left: 0; padding: 18px 16px 36px; }
    .topbar { align-items: flex-start; flex-wrap: wrap; margin-bottom: 21px; padding-bottom: 16px; }
    .menu-toggle { display: inline-grid; flex: 0 0 auto; place-items: center; }
    .topbar-left { flex: 1; }
    .topbar-actions { width: 100%; justify-content: space-between; }
    .search-box { width: auto; min-width: 0; flex: 1; }
    .user { gap: 8px; }
    .user-actions { gap: 5px; }
    .user-actions button { padding: 8px 9px; }
    .charts-grid { grid-template-columns: 1fr; }
    .status-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .permissions-controls { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 480px) {
    .app-main { padding-right: 12px; padding-left: 12px; }
    .topbar-actions { align-items: flex-start; gap: 10px; }
    .search-box form { gap: 5px; }
    .search-box input { min-width: 0; padding: 9px; }
    .search-box button { padding: 8px 10px; }
    .user img { width: 32px; height: 32px; }
    .user-actions { flex-direction: column; }
    .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
    .card { min-height: 100px; padding: 14px 12px; }
    .card .value { font-size: 23px; }
    .section { padding: 15px 12px; }
    .form-row { display: grid; grid-template-columns: 1fr; }
    .form-row input, .form-row select { min-width: 0; }
    .dashboard-hero { min-height: 315px; padding-right: 4px; padding-left: 4px; }
    .hero-mark { width: 62px; height: 62px; font-size: 28px; }
    .hero-actions { gap: 5px; }
    .hero-button { padding: 8px 10px; font-size: 10px; }
    .dashboard-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-panel-heading { align-items: flex-start; flex-direction: column; }
    .status-grid, .permission-list, .permissions-controls { grid-template-columns: 1fr; }
    .permissions-hero { flex-direction: column; }
    .permissions-badge { align-self: flex-start; }
    .permissions-savebar { align-items: stretch; flex-direction: column; }
    .permissions-save { width: 100%; }
    .permissions-editor-heading { align-items: flex-start; flex-direction: column; }
    .permission-toolbar .permission-reload { margin-left: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
  }
</style>
</head>
<body>
  <aside class="app-sidebar" id="app-sidebar">
    <a class="brand" href="${sidebarHome}" aria-label="Tommy Utilities, dashboard">
      <span class="brand-mark" aria-hidden="true">T</span>
      <span><strong>TOMMY UTILITIES</strong><small>BOT CONTROL CENTER</small></span>
    </a>
    <nav class="sidebar-nav" id="sidebar-nav" aria-label="Navigazione dashboard">
      ${sidebarNavigation}
    </nav>
    <div class="sidebar-footer">Tommy Utilities <span aria-hidden="true">·</span> Discord bot</div>
  </aside>
  <button class="sidebar-overlay" id="sidebar-overlay" type="button" aria-label="Chiudi navigazione"></button>
  <main class="app-main">
    <header class="topbar">
      <div class="topbar-left">
        <button class="menu-toggle" id="menu-toggle" type="button" aria-expanded="false" aria-controls="sidebar-nav" aria-label="Apri navigazione">☰</button>
        <div class="page-heading"><p class="eyebrow">CONTROL PANEL</p><h1>${escapeHtml(pageTitle)}</h1></div>
      </div>
      <div class="topbar-actions">
        ${searchControl}
        ${user ? `
          <div class="user">
            <img src="${avatar}" alt="">
            <span class="user-name">${name}</span>
            <div class="user-actions">
              <button class="secondary small" onclick="logoutAll()" title="Invalida tutte le sessioni">🔓 Logout Globale</button>
              <a href="/auth/logout"><button class="danger small">Logout</button></a>
            </div>
          </div>
        ` : `
          <div class="user">
            <span class="user-name">Accesso pubblico</span>
            <div class="user-actions"><a href="/auth/login"><button class="small">Accedi</button></a></div>
          </div>
        `}
      </div>
    </header>
    <div class="content-area">${body}</div>
  </main>
  <script>
    (function () {
      const toggle = document.getElementById('menu-toggle');
      const overlay = document.getElementById('sidebar-overlay');
      const nav = document.getElementById('sidebar-nav');
      function setSidebarOpen(open) {
        document.body.classList.toggle('sidebar-open', open);
        toggle.setAttribute('aria-expanded', String(open));
        toggle.setAttribute('aria-label', open ? 'Chiudi navigazione' : 'Apri navigazione');
      }
      toggle.addEventListener('click', () => setSidebarOpen(toggle.getAttribute('aria-expanded') !== 'true'));
      overlay.addEventListener('click', () => setSidebarOpen(false));
      nav.addEventListener('click', event => {
        if (event.target.closest('a')) setSidebarOpen(false);
      });
      document.addEventListener('keydown', event => {
        if (event.key === 'Escape') setSidebarOpen(false);
      });
      window.addEventListener('resize', () => {
        if (window.innerWidth > 760) setSidebarOpen(false);
      });
    })();
  </script>
</body>
</html>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function safeJson(v) {
  return JSON.stringify(v ?? null)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function makeEmbed(title, description, color) {
  return new EmbedBuilder()
    .setTitle(String(title).slice(0, 256))
    .setDescription(String(description).slice(0, 4096))
    .setColor(color)
    .setTimestamp();
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}g`;
}

// ---------- DASHBOARD ----------
function renderDashboardContent(security = {}) {
  const permissions = new Set(security.permissions || []);
  const canViewOverview = permissions.has('overview');
  const canModerate = permissions.has('moderation');
  const canManageTickets = permissions.has('tickets');
  const canManageCommunications = permissions.has('communications');
  const canManageGlobalBlacklist = security.canUseGlobalBlacklist === true;
  const quickLinks = [
    canModerate ? '<a class="hero-button hero-button-primary" href="/modlogs">Apri moderazione <span aria-hidden="true">→</span></a>' : '',
    permissions.has('tickets') ? '<a class="hero-button hero-button-secondary" href="/tickets">Gestisci ticket</a>' : '',
    permissions.has('settings') ? '<a class="hero-button hero-button-secondary" href="/config">Configurazione</a>' : '',
    security.canExportFullBackup ? '<a class="hero-button hero-button-secondary" href="/api/export/full-backup" onclick="return confirm(&quot;Il backup include tutti i dati salvati, compresi log e dati di accesso. Continuare?&quot;)">Esporta backup completo</a>' : '',
    canManageGlobalBlacklist ? '<a class="hero-button hero-button-primary" href="#blacklist-content">Gestisci blacklist</a>' : '',
    canViewOverview ? '<a class="hero-button hero-button-quiet" href="#service-status">Stato servizi <span aria-hidden="true">↓</span></a>' : ''
  ].filter(Boolean).join('');
  const blacklistStat = canManageGlobalBlacklist
    ? '<div class="card"><h2>Blacklist</h2><div class="value" id="stat-bl">...</div></div>'
    : '';
  const moderationPanels = canManageGlobalBlacklist ? `
    <div class="section">
      <h2>➕ Aggiungi alla Blacklist</h2>
      <p style="color:#888;font-size:13px;margin-bottom:12px;">Bannerà l'utente in tutti i server dove il bot è presente e gli invierà un DM.</p>
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
    </div>` : '';
  const statusPanel = canViewOverview ? `
    <section class="section status-panel" id="service-status">
      <div class="status-panel-heading">
        <div><p class="hero-eyebrow">MONITORAGGIO LIVE</p><h2>Stato dei servizi</h2></div>
        <span class="status-updated" id="status-updated">In attesa di aggiornamento</span>
      </div>
      <div class="status-grid">
        <div class="status-item"><span class="status-item-label">Dashboard API</span><strong class="status-value checking" id="status-api">Controllo...</strong></div>
        <div class="status-item"><span class="status-item-label">Gateway Discord</span><strong class="status-value checking" id="status-bot">Controllo...</strong></div>
        <div class="status-item"><span class="status-item-label">Database</span><strong class="status-value checking" id="status-database">Controllo...</strong></div>
        <div class="status-item"><span class="status-item-label">Ping gateway</span><strong class="status-value checking" id="status-ping">—</strong></div>
      </div>
    </section>` : '';
  const statsGrid = canViewOverview ? `
    <div class="grid dashboard-stats">
      ${canModerate ? '<div class="card"><h2>Log Totali</h2><div class="value" id="stat-logs">...</div></div>' : ''}
      ${blacklistStat}
      <div class="card"><h2>Server gestiti</h2><div class="value" id="stat-guilds">...</div></div>
      <div class="card"><h2>Ping</h2><div class="value" id="stat-ping">...</div></div>
      <div class="card"><h2>Uptime</h2><div class="value" id="stat-uptime">...</div></div>
      ${canManageTickets ? '<div class="card"><h2>Ticket Aperti</h2><div class="value" id="stat-tickets">...</div></div><div class="card"><h2>Transcripts</h2><div class="value" id="stat-transcripts">...</div></div>' : ''}
      ${canModerate ? '<div class="card"><h2>Note</h2><div class="value" id="stat-notes">...</div></div>' : ''}
      ${canManageCommunications ? '<div class="card"><h2>Reminder</h2><div class="value" id="stat-reminders">...</div></div>' : ''}
    </div>` : '';
  return `
  <section class="dashboard-hero">
    <div class="hero-mark" aria-hidden="true">T</div>
    <p class="hero-eyebrow">TOMMY UTILITIES · BOT CONTROL CENTER</p>
    <h2>Tutto il tuo server.<br><span>A portata di mano.</span></h2>
    <p class="hero-description">${canViewOverview ? 'Monitora l\'operatività e gestisci le attività del tuo server da un unico pannello.' : 'Gestisci la blacklist globale autorizzata per i tuoi ruoli.'}</p>
    <div class="hero-actions">${quickLinks}</div>
    ${canViewOverview ? '<div class="hero-status"><span class="status-led checking" id="status-led"></span><span id="status-summary" aria-live="polite">Verifica stato servizi...</span></div>' : ''}
  </section>

  ${statusPanel}
  ${statsGrid}

  ${moderationPanels}
  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  const canRefreshStats = ${canViewOverview};
  function refreshStatsAfterBlacklist() { if (canRefreshStats) loadStats(); }
  function setStat(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }
  async function loadStats() {
    const res = await apiFetch('/api/stats'); if (!res.ok) return;
    const s = await res.json();
    setStat('stat-logs', s.logs);
    const blacklist = document.getElementById('stat-bl');
    if (blacklist) blacklist.textContent = s.blacklist ?? '—';
    setStat('stat-guilds', s.guilds);
    setStat('stat-ping', s.ping == null ? 'N/D' : s.ping + 'ms');
    const h = Math.floor(s.uptime/3600), m = Math.floor((s.uptime%3600)/60);
    setStat('stat-uptime', h + 'h ' + m + 'm');
    setStat('stat-tickets', s.tickets);
    setStat('stat-notes', s.notes);
    setStat('stat-transcripts', s.transcripts);
    setStat('stat-reminders', s.reminders);
  }
  function setStatus(id, state, label) {
    const el = document.getElementById(id);
    el.textContent = label;
    el.className = 'status-value ' + state;
  }
  function markStatusUnavailable() {
    document.getElementById('status-led').className = 'status-led offline';
    document.getElementById('status-summary').textContent = 'Stato non disponibile';
    setStatus('status-api', 'offline', 'Non disponibile');
    setStatus('status-bot', 'offline', 'Non disponibile');
    setStatus('status-database', 'offline', 'Non disponibile');
    setStatus('status-ping', 'offline', 'N/D');
  }
  async function loadStatus() {
    try {
      const res = await apiFetch('/api/status');
      if (!res.ok) { markStatusUnavailable(); return; }
      const status = await res.json();
      const servicesOnline = status.status === 'operational';
      document.getElementById('status-led').className = 'status-led ' + (servicesOnline ? 'online' : 'offline');
      document.getElementById('status-summary').textContent = servicesOnline ? 'Tutti i servizi operativi' : 'Servizi con problemi';
      setStatus('status-api', 'online', 'Online');
      setStatus('status-bot', status.botOnline ? 'online' : 'offline', status.botOnline ? 'Connesso' : 'Disconnesso');
      setStatus('status-database', status.databaseReady ? 'online' : 'offline', status.databaseReady ? 'Operativo' : 'Non disponibile');
      setStatus('status-ping', status.ping == null ? 'offline' : 'online', status.ping == null ? 'N/D' : status.ping + ' ms');
      document.getElementById('status-updated').textContent = 'Aggiornato alle ' + new Date(status.checkedAt).toLocaleTimeString('it-IT');
    } catch (error) {
      console.error('[status] aggiornamento non riuscito', error);
      markStatusUnavailable();
    }
  }
  async function loadBlacklist() {
    const res = await apiFetch('/api/blacklist');
    const list = await res.json().catch(() => ({}));
    const el = document.getElementById('blacklist-content');
    if (!res.ok) { el.innerHTML = '<p class="error">' + esc(list.error || 'Blacklist non disponibile') + '</p>'; return; }
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
    if (!confirm('Rimuovere ' + ids.length + ' utenti dalla blacklist? Verranno sbannati in tutti i server.')) return;
    const res = await apiFetch('/api/blacklist/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { alert('✅ Rimossi ' + data.count + ' utenti'); loadBlacklist(); refreshStatsAfterBlacklist(); }
    else alert('❌ ' + (data.error || 'Errore'));
  }
  async function addBL() {
    const userId = document.getElementById('bl-userId').value.trim();
    const username = document.getElementById('bl-username').value.trim();
    const reason = document.getElementById('bl-reason').value.trim();
    const msg = document.getElementById('bl-msg');
    if (!userId || !username || !reason) { msg.innerHTML = '<span class="error">❌ Compila tutti i campi</span>'; return; }
    const res = await apiFetch('/api/blacklist', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId, username, reason }) });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      msg.innerHTML = '<span class="success">✅ Aggiunto (bannato in ' + esc(data.bannedIn || 0) + ' server)</span>';
      document.getElementById('bl-userId').value = '';
      document.getElementById('bl-username').value = '';
      document.getElementById('bl-reason').value = '';
      loadBlacklist(); refreshStatsAfterBlacklist();
    } else { msg.innerHTML = '<span class="error">❌ [' + res.status + '] ' + esc(data.error || 'Errore') + '</span>'; }
  }
  async function removeBL(userId) {
    if (!confirm('Rimuovere ' + userId + ' dalla blacklist? Verrà sbannato dove è bannato.')) return;
    const res = await apiFetch('/api/blacklist/' + encodeURIComponent(userId), { method: 'DELETE' });
    if (!res.ok) { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); return; }
    loadBlacklist(); refreshStatsAfterBlacklist();
  }
  if (${canViewOverview}) {
    loadStats(); loadStatus();
    setInterval(loadStats, 10000);
    setInterval(loadStatus, 15000);
  }
  if (${canManageGlobalBlacklist}) loadBlacklist();
  </script>`;
}

function renderResourcesContent(canManageResources = false) {
  return `
  <section class="dashboard-hero public-landing-hero">
    <div class="hero-mark" aria-hidden="true">T</div>
    <p class="hero-eyebrow">TOMMY UTILITIES · BOT CONTROL CENTER</p>
    <h2>Il tuo bot.<br><span>Sempre sotto controllo.</span></h2>
    <p class="hero-description">Esplora i server Discord e le risorse della community da un unico punto.</p>
    <div class="hero-actions">
      <a class="hero-button hero-button-primary" href="/auth/login">Accedi alla dashboard <span aria-hidden="true">→</span></a>
      <a class="hero-button hero-button-quiet" href="#public-resources">Scopri le risorse <span aria-hidden="true">↓</span></a>
    </div>
    <div class="hero-status"><span class="status-led checking" id="public-status-led"></span><span id="public-status-summary" aria-live="polite">Verifica stato servizi...</span></div>
  </section>
  <section class="section status-panel public-status-panel" aria-labelledby="public-status-title">
    <div class="status-panel-heading">
      <div><p class="hero-eyebrow">MONITORAGGIO LIVE</p><h2 id="public-status-title">Stato dei servizi</h2></div>
      <span class="status-updated" id="public-status-updated">In attesa di aggiornamento</span>
    </div>
    <div class="status-grid">
      <div class="status-item"><span class="status-item-label">Dashboard API</span><strong class="status-value checking" id="public-status-api">Controllo...</strong></div>
      <div class="status-item"><span class="status-item-label">Gateway Discord</span><strong class="status-value checking" id="public-status-gateway">Controllo...</strong></div>
      <div class="status-item"><span class="status-item-label">Server Discord</span><strong class="status-value checking" id="public-status-guilds">Controllo...</strong></div>
      <div class="status-item"><span class="status-item-label">Ping gateway</span><strong class="status-value checking" id="public-status-ping">Controllo...</strong></div>
    </div>
  </section>
  <section id="public-resources">
    <div class="resources-section-heading">
      <p class="hero-eyebrow">ESPLORA</p>
      <h2>Resources</h2>
      <p>Server Discord e risorse pubbliche della community.</p>
    </div>
    ${canManageResources ? `
    <form class="section resource-admin-form" id="resource-form">
      <h2 id="resource-form-title">Aggiungi una risorsa</h2>
      <input id="resource-id" name="id" type="hidden">
      <input id="resource-kind" name="kind" type="hidden" value="custom">
      <p id="resource-form-help">Le risorse personalizzate sono pubbliche. Puoi usare un link a una guida, a un documento o a un file.</p>
      <div class="resource-form-grid">
        <label>Titolo<input name="title" type="text" maxlength="100" required placeholder="Es. Guida alle lobby"></label>
        <label>Categoria<input name="category" type="text" maxlength="40" placeholder="Es. Guide"></label>
        <label class="resource-form-wide">Link<input id="resource-url" name="url" type="url" maxlength="2048" required placeholder="https://..."></label>
        <label id="resource-invite-field" class="resource-form-wide" hidden>Link invito Discord<input id="resource-invite-url" name="inviteUrl" type="url" maxlength="2048" placeholder="https://discord.gg/..."></label>
        <label class="resource-form-wide">Descrizione<textarea name="description" maxlength="500" rows="3" placeholder="Descrivi brevemente questa risorsa"></textarea></label>
      </div>
      <div class="resource-form-actions">
        <button type="submit">Pubblica risorsa</button>
        <button id="resource-form-cancel" class="secondary" type="button" hidden>Annulla modifica</button>
        <button id="resource-form-reset-guild" class="secondary" type="button" hidden>Ripristina dati Discord</button>
        <span id="resource-form-status" role="status" aria-live="polite"></span>
      </div>
    </form>
    ` : ''}
    <div class="grid resources-grid" id="resources-list" aria-live="polite">
      <div class="section resources-empty">Caricamento server...</div>
    </div>
  </section>
  <style>
    .resource-admin-form { margin-bottom: 20px; padding: 20px; }
    .resource-admin-form h2 { margin-bottom: 14px; font-size: 17px; }
    #resource-form-help { margin: -7px 0 14px; color: var(--muted); font-size: 11px; }
    .resource-form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 13px; }
    .resource-form-grid label { display: flex; flex-direction: column; gap: 6px; color: var(--muted); font-size: 11px; font-weight: 650; }
    .resource-form-grid #resource-invite-field[hidden] { display: none; }
    .resource-form-grid label small { color: #777d90; font-size: 10px; font-weight: 400; }
    .resource-form-grid input, .resource-form-grid textarea { width: 100%; padding: 9px 11px; border: 1px solid var(--border); border-radius: 9px; background: #0c0e16; color: var(--text); font: inherit; }
    .resource-form-grid textarea { resize: vertical; }
    .resource-form-grid input:focus, .resource-form-grid textarea:focus { outline: 2px solid rgba(144, 126, 255, .45); outline-offset: 1px; }
    .resource-form-wide { grid-column: 1 / -1; }
    .resource-form-actions { display: flex; align-items: center; gap: 12px; margin-top: 15px; }
    .resource-admin-actions { display: flex; align-items: center; gap: 7px; }
    #resource-form-status { color: var(--muted); font-size: 12px; }
    .resource-delete { padding: 6px 9px; border: 1px solid rgba(240, 100, 120, .35); border-radius: 8px; background: rgba(240, 100, 120, .1); color: #ff9aa8; font-size: 10px; }
    .resource-delete:hover { background: rgba(240, 100, 120, .2); }
    @media (max-width: 600px) { .resource-form-grid { grid-template-columns: 1fr; } }
  </style>
  <script>
  const canManageResources = ${canManageResources ? 'true' : 'false'};
  function resourceEsc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  const resourceLabels = {
    overview: 'Dashboard', moderation: 'Moderazione', global_blacklist: 'Blacklist',
    tickets: 'Ticket', settings: 'Configurazione', analytics: 'Analytics',
    communications: 'Comunicazioni', lobbies: 'Lobby', audit: 'Log accessi'
  };
  const resourceRoutes = [
    ['settings', '/config', 'Apri configurazione'],
    ['tickets', '/tickets', 'Gestisci ticket'],
    ['moderation', '/modlogs', 'Apri moderazione'],
    ['analytics', '/charts', 'Apri analytics'],
    ['communications', '/messages', 'Apri comunicazioni'],
    ['lobbies', '/lobbies', 'Apri lobby'],
    ['audit', '/access-logs', 'Apri log accessi'],
    ['overview', '/dashboard', 'Apri dashboard'],
    ['global_blacklist', '/dashboard', 'Apri blacklist']
  ];
  function setPublicStatus(id, state, label) {
    const element = document.getElementById(id);
    element.textContent = label;
    element.className = 'status-value ' + state;
  }
  async function loadPublicStatus() {
    try {
      const response = await fetch('/health', { cache: 'no-store' });
      if (!response.ok) throw new Error('Health check non disponibile');
      const health = await response.json();
      const apiOnline = health.status === 'ok';
      const gatewayOnline = Number.isFinite(health.ping);
      document.getElementById('public-status-led').className = 'status-led ' + (apiOnline ? 'online' : 'offline');
      document.getElementById('public-status-summary').textContent = apiOnline ? 'Dashboard operativa' : 'Servizi non disponibili';
      setPublicStatus('public-status-api', apiOnline ? 'online' : 'offline', apiOnline ? 'Online' : 'Non disponibile');
      setPublicStatus('public-status-gateway', gatewayOnline ? 'online' : 'offline', gatewayOnline ? 'Connesso' : 'Non disponibile');
      setPublicStatus('public-status-guilds', apiOnline ? 'online' : 'offline',
        Number.isFinite(health.guilds) ? health.guilds.toLocaleString('it-IT') : 'N/D');
      setPublicStatus('public-status-ping', gatewayOnline ? 'online' : 'offline',
        gatewayOnline ? health.ping + ' ms' : 'N/D');
      const checkedAt = new Date(health.timestamp);
      document.getElementById('public-status-updated').textContent = Number.isNaN(checkedAt.getTime())
        ? 'Aggiornamento live'
        : 'Aggiornato alle ' + checkedAt.toLocaleTimeString('it-IT');
    } catch (error) {
      console.error('[public status] aggiornamento non riuscito', error);
      document.getElementById('public-status-led').className = 'status-led offline';
      document.getElementById('public-status-summary').textContent = 'Stato non disponibile';
      setPublicStatus('public-status-api', 'offline', 'Non disponibile');
      setPublicStatus('public-status-gateway', 'offline', 'Non disponibile');
      setPublicStatus('public-status-guilds', 'offline', 'N/D');
      setPublicStatus('public-status-ping', 'offline', 'N/D');
      document.getElementById('public-status-updated').textContent = 'Stato non disponibile';
    }
  }
  async function loadResources() {
    const root = document.getElementById('resources-list');
    try {
      const response = await apiFetch('/api/resources');
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        root.innerHTML = '<div class="section resources-empty">' + resourceEsc(data.error || 'Impossibile caricare le risorse.') + '</div>';
        return;
      }
      if (!data.length) {
        root.innerHTML = '<div class="section resources-empty">Nessuna risorsa disponibile.</div>';
        return;
      }
      root.innerHTML = data.map(guild => {
        if (guild.kind === 'custom') {
          const editButton = canManageResources
            ? '<button class="secondary small resource-edit" type="button" data-resource-edit="' + encodeURIComponent(guild.id) +
              '" data-resource-title="' + resourceEsc(guild.title) +
              '" data-resource-category="' + resourceEsc(guild.category || 'Generale') +
              '" data-resource-url="' + resourceEsc(guild.url) +
              '" data-resource-description="' + resourceEsc(guild.description || '') +
              '">Modifica</button>'
            : '';
          const deleteButton = canManageResources
            ? '<button class="resource-delete" type="button" data-resource-delete="' + encodeURIComponent(guild.id) + '" aria-label="Rimuovi ' + resourceEsc(guild.title) + '">Rimuovi</button>'
            : '';
          return '<article class="card resource-card">' +
            '<div class="resource-card-header"><div class="resource-card-icon"><span aria-hidden="true">' + resourceEsc((guild.title || 'R').slice(0, 1).toUpperCase()) + '</span></div>' +
            '<div><div class="resource-card-type">' + resourceEsc(guild.category || 'Generale') + '</div><h3>' + resourceEsc(guild.title) + '</h3></div></div>' +
            (guild.description ? '<p class="resource-card-copy">' + resourceEsc(guild.description) + '</p>' : '') +
            '<div class="resource-card-actions"><a class="resource-link" href="' + resourceEsc(guild.url) + '" target="_blank" rel="noopener noreferrer">Apri risorsa ↗</a><div class="resource-admin-actions">' + editButton + deleteButton + '</div></div>' +
            '</article>';
        }
        const permissions = Array.isArray(guild.permissions) ? guild.permissions : [];
        const tags = permissions.map(permission => resourceLabels[permission]).filter(Boolean);
        const destination = resourceRoutes.find(([feature]) => permissions.includes(feature));
        const icon = guild.iconUrl
          ? '<img src="' + resourceEsc(guild.iconUrl) + '" alt="" loading="lazy">'
          : '<span aria-hidden="true">' + resourceEsc((guild.name || 'D').slice(0, 1).toUpperCase()) + '</span>';
        const members = Number.isFinite(guild.memberCount)
          ? '<span><strong>' + guild.memberCount.toLocaleString('it-IT') + '</strong> membri</span>'
          : '';
        const tagsMarkup = tags.length
          ? tags.map(label => '<span class="resource-tag">' + resourceEsc(label) + '</span>').join('')
          : '<span class="resource-tag">Resources</span>';
        const dashboardLink = destination
          ? '<a class="resource-link" href="' + destination[1] + '">' + destination[2] + ' →</a>'
          : '';
        const editButton = canManageResources
          ? '<button class="secondary small resource-edit" type="button" data-resource-guild-edit="' + encodeURIComponent(guild.id) +
            '" data-resource-title="' + resourceEsc(guild.name) +
            '" data-resource-category="' + resourceEsc(guild.category || 'Server Discord') +
            '" data-resource-url="' + resourceEsc(guild.resourceUrl || '') +
            '" data-resource-invite-url="' + resourceEsc(guild.inviteUrl || '') +
            '" data-resource-description="' + resourceEsc(guild.description || '') +
            '">Modifica scheda</button>'
          : '';
        const externalLink = guild.resourceUrl
          ? '<a class="resource-link" href="' + resourceEsc(guild.resourceUrl) + '" target="_blank" rel="noopener noreferrer">Link aggiuntivo ↗</a>'
          : '';
        const inviteLink = guild.inviteUrl
          ? '<a class="resource-server-link" href="' + resourceEsc(guild.inviteUrl) + '" target="_blank" rel="noopener noreferrer">Apri server</a>'
          : '<span class="resource-server-link" aria-disabled="true" title="Link invito non configurato">Invito non configurato</span>';
        return '<article class="card resource-card">' +
          '<div class="resource-card-header"><div class="resource-card-icon">' + icon + '</div>' +
          '<div><div class="resource-card-type">' + resourceEsc(guild.category || 'Server Discord') + '</div><h3>' + resourceEsc(guild.name) + '</h3></div></div>' +
          '<div class="resource-card-meta">' + members + '</div>' +
          (guild.description ? '<p class="resource-card-copy">' + resourceEsc(guild.description) + '</p>' : '') +
          '<div class="resource-tags">' + tagsMarkup + '</div>' +
          '<div class="resource-card-actions">' + inviteLink +
          '<div class="resource-admin-actions">' + externalLink + dashboardLink + editButton + '</div></div>' +
          '</article>';
      }).join('');
    } catch (error) {
      console.error('[resources] caricamento non riuscito', error);
      root.innerHTML = '<div class="section resources-empty">Errore durante il caricamento delle risorse.</div>';
    }
  }
  const resourceForm = document.getElementById('resource-form');
  if (resourceForm) {
    const submitButton = resourceForm.querySelector('button[type="submit"]');
    const cancelButton = document.getElementById('resource-form-cancel');
    const resetGuildButton = document.getElementById('resource-form-reset-guild');
    const resetResourceForm = () => {
      resourceForm.reset();
      document.getElementById('resource-id').value = '';
      document.getElementById('resource-kind').value = 'custom';
      document.getElementById('resource-form-title').textContent = 'Aggiungi una risorsa';
      document.getElementById('resource-form-help').textContent = 'Le risorse personalizzate sono pubbliche. Puoi usare un link a una guida, a un documento o a un file.';
      document.getElementById('resource-url').required = true;
      document.getElementById('resource-url').placeholder = 'https://...';
      document.getElementById('resource-invite-field').hidden = true;
      document.getElementById('resource-invite-url').value = '';
      submitButton.textContent = 'Pubblica risorsa';
      cancelButton.hidden = true;
      resetGuildButton.hidden = true;
      document.getElementById('resource-form-status').textContent = '';
    };

    cancelButton.addEventListener('click', resetResourceForm);
    resetGuildButton.addEventListener('click', async () => {
      const guildId = document.getElementById('resource-id').value;
      if (!guildId || !confirm('Ripristinare questa scheda ai dati originali di Discord?')) return;
      resetGuildButton.disabled = true;
      try {
        const response = await apiFetch('/api/resources/guild/' + encodeURIComponent(guildId), { method: 'DELETE' });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || 'Impossibile ripristinare la scheda.');
        resetResourceForm();
        await loadResources();
      } catch (error) {
        document.getElementById('resource-form-status').textContent = error.message || 'Errore durante il ripristino.';
      } finally {
        resetGuildButton.disabled = false;
      }
    });
    resourceForm.addEventListener('submit', async event => {
      event.preventDefault();
      const status = document.getElementById('resource-form-status');
      status.textContent = 'Salvataggio...';
      submitButton.disabled = true;
      try {
        const formData = new FormData(resourceForm);
        const resourceId = document.getElementById('resource-id').value;
        const resourceKind = document.getElementById('resource-kind').value;
        const endpoint = resourceKind === 'guild'
          ? '/api/resources/guild/' + encodeURIComponent(resourceId)
          : resourceId ? '/api/resources/' + encodeURIComponent(resourceId) : '/api/resources';
        const method = resourceId ? 'PUT' : 'POST';
        const response = await apiFetch(endpoint, {
          method,
          body: JSON.stringify({
            title: formData.get('title'),
            category: formData.get('category'),
            url: formData.get('url'),
            inviteUrl: formData.get('inviteUrl'),
            description: formData.get('description')
          })
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || 'Impossibile salvare la risorsa.');
        const wasEditing = !!resourceId;
        const wasGuild = resourceKind === 'guild';
        resetResourceForm();
        status.textContent = wasGuild ? 'Scheda server aggiornata.' : wasEditing ? 'Modifiche salvate.' : 'Risorsa pubblicata.';
        await loadResources();
      } catch (error) {
        status.textContent = error.message || 'Errore durante il salvataggio.';
      } finally {
        submitButton.disabled = false;
      }
    });
  }
  document.getElementById('resources-list').addEventListener('click', async event => {
    if (!canManageResources) return;
    const editButton = event.target.closest('[data-resource-edit], [data-resource-guild-edit]');
    if (editButton) {
      const isGuild = !!editButton.dataset.resourceGuildEdit;
      document.getElementById('resource-id').value = isGuild ? editButton.dataset.resourceGuildEdit : editButton.dataset.resourceEdit;
      document.getElementById('resource-kind').value = isGuild ? 'guild' : 'custom';
      document.querySelector('#resource-form [name="title"]').value = editButton.dataset.resourceTitle;
      document.querySelector('#resource-form [name="category"]').value = editButton.dataset.resourceCategory;
      document.querySelector('#resource-form [name="url"]').value = editButton.dataset.resourceUrl;
      document.getElementById('resource-invite-field').hidden = !isGuild;
      document.getElementById('resource-invite-url').value = isGuild ? editButton.dataset.resourceInviteUrl : '';
      document.querySelector('#resource-form [name="description"]').value = editButton.dataset.resourceDescription;
      document.getElementById('resource-url').required = !isGuild;
      document.getElementById('resource-url').placeholder = isGuild ? 'Link aggiuntivo facoltativo' : 'https://...';
      document.getElementById('resource-form-title').textContent = isGuild ? 'Modifica scheda server' : 'Modifica risorsa';
      document.getElementById('resource-form-help').textContent = isGuild
        ? 'Modifica la scheda pubblica e il link invito; le impostazioni del server Discord non cambiano.'
        : 'Le risorse personalizzate sono pubbliche. Puoi usare un link a una guida, a un documento o a un file.';
      document.querySelector('#resource-form button[type="submit"]').textContent = isGuild ? 'Salva scheda' : 'Salva modifiche';
      document.getElementById('resource-form-cancel').hidden = false;
      document.getElementById('resource-form-reset-guild').hidden = !isGuild;
      document.getElementById('resource-form-status').textContent = '';
      document.getElementById('resource-form').scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }

    const button = event.target.closest('[data-resource-delete]');
    if (!button) return;
    if (!confirm('Vuoi rimuovere questa risorsa pubblica?')) return;
    button.disabled = true;
    try {
      const response = await apiFetch('/api/resources/' + encodeURIComponent(button.dataset.resourceDelete), { method: 'DELETE' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'Impossibile rimuovere la risorsa.');
      await loadResources();
    } catch (error) {
      alert(error.message || 'Errore durante la rimozione.');
      button.disabled = false;
    }
  });
  loadPublicStatus();
  loadResources();
  </script>`;
}

// ---------- PERMESSI DASHBOARD ----------
function renderPermissionsContent() {
  const features = [
    ['overview', 'Dashboard e stato servizi', 'Panoramica, statistiche e stato live del bot.'],
    ['moderation', 'Moderazione, log e note', 'Ricerca utenti, azioni, note staff e registri di moderazione.'],
    ['global_blacklist', 'Blacklist globale', 'Visualizzazione e gestione della blacklist condivisa.'],
    ['tickets', 'Ticket e transcript', 'Gestione ticket, priorità, assegnazioni e transcript.'],
    ['settings', 'Configurazione e comandi', 'Impostazioni del server, welcome e comandi personalizzati.'],
    ['analytics', 'Grafici e classifiche', 'Statistiche aggregate, grafici e classifiche di attività.'],
    ['communications', 'Messaggi e reminder', 'Invio di messaggi e gestione dei promemoria.'],
    ['lobbies', 'Lobby', 'Configurazione e gestione delle lobby del server.'],
    ['audit', 'Log degli accessi', 'Cronologia degli accessi alla dashboard e relativi dettagli.']
  ];
  const options = features.map(([key, label, description]) =>
    `<label class="permission-option"><input class="dashboard-permission" type="checkbox" value="${key}" aria-describedby="permission-description-${key}" disabled><span><strong>${label}</strong><small id="permission-description-${key}">${description}</small></span></label>`
  ).join('');
  return `
  <section class="section">
    <div class="permissions-hero">
      <div>
        <h2>Permessi dashboard</h2>
        <p class="permissions-help">Scegli cosa può gestire ogni ruolo, separatamente per server. Le modifiche si applicano subito dopo il salvataggio. Senior Admin e gli admin in <code>DASHBOARD_ADMIN_IDS</code> mantengono accesso completo.</p>
      </div>
      <span class="permissions-badge">ACCESSO PER RUOLO</span>
    </div>
    <div class="permissions-controls">
      <label for="permission-guild">Server Discord<select id="permission-guild" disabled><option>Caricamento server...</option></select></label>
      <label for="permission-role">Ruolo da configurare<select id="permission-role" disabled><option>Seleziona un server</option></select></label>
    </div>
    <div class="permissions-editor">
      <div class="permissions-editor-heading">
        <div><h3>Aree accessibili</h3><p>Seleziona una o più aree da assegnare al ruolo.</p></div>
        <p class="permission-count" id="permission-count" aria-live="polite">0 di ${features.length} aree</p>
      </div>
      <div class="permission-toolbar">
        <button class="secondary small" id="permission-select-all" type="button" disabled>Seleziona tutte</button>
        <button class="secondary small" id="permission-clear-all" type="button" disabled>Rimuovi tutte</button>
        <button class="secondary small" id="permission-reset" type="button" disabled>Ripristina</button>
        <button class="secondary small permission-reload" id="permission-reload" type="button" disabled>Ricarica dati</button>
      </div>
      <div id="permission-list" class="permission-list">${options}</div>
    </div>
    <div class="permissions-savebar">
      <div id="permission-message" class="permission-message" role="status" aria-live="polite">Caricamento server autorizzati...</div>
      <button class="permissions-save" id="permission-save" type="button" disabled>Salva modifiche</button>
    </div>
  </section>
  <script>
  function permissionEsc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  let permissionGuilds = [];
  let permissionRoles = [];
  let savedPermissionValues = '[]';
  let activeGuildId = '';
  let activeRoleId = '';
  let permissionSaveInProgress = false;
  let permissionLoadInProgress = false;
  let permissionLoadSequence = 0;
  const permissionFeatureCount = ${features.length};
  const permissionInputs = () => Array.from(document.querySelectorAll('.dashboard-permission'));
  function selectedPermissionValues() {
    return permissionInputs().filter(input => input.checked).map(input => input.value).sort();
  }
  function permissionIsDirty() {
    return JSON.stringify(selectedPermissionValues()) !== savedPermissionValues;
  }
  function permissionMessage(text, type) {
    const el = document.getElementById('permission-message');
    el.textContent = text;
    el.className = 'permission-message ' + (type || '');
  }
  function updatePermissionEditor() {
    const count = permissionInputs().filter(input => input.checked).length;
    const canEdit = permissionRoles.length > 0 && !permissionLoadInProgress;
    const locked = permissionSaveInProgress || permissionLoadInProgress;
    const message = document.getElementById('permission-message');
    document.getElementById('permission-count').textContent = count + ' di ' + permissionFeatureCount + ' aree selezionate';
    document.getElementById('permission-guild').disabled = locked || !permissionGuilds.length;
    document.getElementById('permission-role').disabled = locked || !permissionRoles.length;
    permissionInputs().forEach(input => { input.disabled = !canEdit || permissionSaveInProgress; });
    document.getElementById('permission-select-all').disabled = !canEdit || count === permissionFeatureCount || permissionSaveInProgress;
    document.getElementById('permission-clear-all').disabled = !canEdit || count === 0 || permissionSaveInProgress;
    document.getElementById('permission-reset').disabled = !canEdit || !permissionIsDirty() || permissionSaveInProgress;
    document.getElementById('permission-reload').disabled = locked || (!permissionGuilds.length && !message.classList.contains('error'));
    document.getElementById('permission-save').disabled = !canEdit || !permissionIsDirty() || permissionSaveInProgress;
    if (!permissionSaveInProgress && permissionIsDirty() && !message.classList.contains('error')) {
      permissionMessage('Modifiche non salvate', 'pending');
    }
  }
  function canDiscardPermissionChanges() {
    if (permissionSaveInProgress) return false;
    if (!permissionIsDirty()) return true;
    return confirm('Ci sono modifiche non salvate. Vuoi scartarle?');
  }
  async function loadPermissionGuilds() {
    const select = document.getElementById('permission-guild');
    let guildListLoaded = false;
    permissionLoadInProgress = true;
    updatePermissionEditor();
    try {
      const res = await apiFetch('/api/dashboard/managed-guilds');
      const data = await res.json().catch(() => []);
      if (!res.ok) {
        permissionMessage(data.error || 'Impossibile caricare i server autorizzati.', 'error');
        return;
      }
      permissionGuilds = data;
      select.innerHTML = permissionGuilds.map(g => '<option value="' + permissionEsc(g.id) + '">' + permissionEsc(g.name) + '</option>').join('');
      if (!permissionGuilds.length) {
        select.innerHTML = '<option value="">Nessun server disponibile</option>';
        permissionMessage('Non hai accesso amministrativo a nessun server.', 'error');
        return;
      }
      guildListLoaded = true;
    } catch (error) {
      console.error('[permissions] caricamento server non riuscito', error);
      permissionMessage('Errore durante il caricamento dei server.', 'error');
    } finally {
      permissionLoadInProgress = false;
      updatePermissionEditor();
    }
    if (guildListLoaded) {
      const guildSelect = document.getElementById('permission-guild');
      guildSelect.value = permissionGuilds.some(guild => guild.id === activeGuildId) ? activeGuildId : permissionGuilds[0].id;
      await loadPermissionRoles(activeRoleId);
    }
  }
  async function loadPermissionRoles(preferredRoleId) {
    const guildId = document.getElementById('permission-guild').value;
    const roleSelect = document.getElementById('permission-role');
    const requestId = ++permissionLoadSequence;
    permissionLoadInProgress = true;
    permissionMessage('Caricamento ruoli...', 'pending');
    permissionRoles = [];
    activeGuildId = guildId;
    activeRoleId = '';
    permissionInputs().forEach(input => { input.checked = false; });
    savedPermissionValues = '[]';
    updatePermissionEditor();
    permissionMessage('Caricamento ruoli...', 'pending');
    try {
      const res = await apiFetch('/api/dashboard/role-permissions/' + encodeURIComponent(guildId));
      const data = await res.json().catch(() => []);
      if (requestId !== permissionLoadSequence) return;
      if (!res.ok) {
        roleSelect.innerHTML = '<option value="">Ruoli non disponibili</option>';
        permissionMessage(data.error || 'Impossibile caricare i ruoli.', 'error');
        return;
      }
      if (!Array.isArray(data)) throw new Error('Risposta ruoli non valida');
      permissionRoles = data;
      roleSelect.innerHTML = permissionRoles.map(role => '<option value="' + permissionEsc(role.id) + '">' + permissionEsc(role.name) + '</option>').join('');
      if (permissionRoles.length) {
        const selectedRole = permissionRoles.some(role => role.id === preferredRoleId) ? preferredRoleId : permissionRoles[0].id;
        roleSelect.value = selectedRole;
        activeRoleId = selectedRole;
        showRolePermissions();
      } else {
        roleSelect.innerHTML = '<option value="">Nessun ruolo configurabile</option>';
        permissionInputs().forEach(input => { input.checked = false; });
        savedPermissionValues = '[]';
        updatePermissionEditor();
        permissionMessage('Nessun ruolo configurabile in questo server.', '');
      }
    } catch (error) {
      if (requestId !== permissionLoadSequence) return;
      console.error('[permissions] caricamento ruoli non riuscito', error);
      roleSelect.innerHTML = '<option value="">Errore caricamento ruoli</option>';
      permissionMessage('Errore durante il caricamento dei ruoli.', 'error');
    } finally {
      if (requestId === permissionLoadSequence) {
        permissionLoadInProgress = false;
        updatePermissionEditor();
      }
    }
  }
  function showRolePermissions() {
    const roleSelect = document.getElementById('permission-role');
    const role = permissionRoles.find(item => item.id === roleSelect.value);
    activeRoleId = roleSelect.value;
    const selected = new Set(role ? role.permissions : []);
    permissionInputs().forEach(input => { input.checked = selected.has(input.value); });
    savedPermissionValues = JSON.stringify([...selected].sort());
    permissionMessage('Permessi aggiornati', 'success');
    updatePermissionEditor();
  }
  function handlePermissionRoleChange() {
    const roleSelect = document.getElementById('permission-role');
    if (!canDiscardPermissionChanges()) {
      roleSelect.value = activeRoleId;
      return;
    }
    showRolePermissions();
  }
  async function handlePermissionGuildChange() {
    const guildSelect = document.getElementById('permission-guild');
    if (!canDiscardPermissionChanges()) {
      guildSelect.value = activeGuildId;
      return;
    }
    await loadPermissionRoles();
  }
  function resetPermissionChanges() {
    const saved = new Set(JSON.parse(savedPermissionValues));
    permissionInputs().forEach(input => { input.checked = saved.has(input.value); });
    permissionMessage('Modifiche ripristinate.', 'success');
    updatePermissionEditor();
  }
  async function reloadPermissionData() {
    if (!canDiscardPermissionChanges()) return;
    await loadPermissionGuilds();
  }
  async function saveRolePermissions() {
    if (permissionSaveInProgress || permissionLoadInProgress || !permissionIsDirty() || !permissionRoles.length) return;
    const guildId = document.getElementById('permission-guild').value;
    const roleId = document.getElementById('permission-role').value;
    const permissions = selectedPermissionValues();
    if (!roleId) return;
    if (!permissions.length && !confirm('Rimuovere tutti i permessi di questo ruolo? Il ruolo perderà l’accesso alla dashboard.')) return;
    const button = document.getElementById('permission-save');
    permissionSaveInProgress = true;
    button.textContent = 'Salvataggio...';
    updatePermissionEditor();
    try {
      const res = await apiFetch('/api/dashboard/role-permissions/' + encodeURIComponent(guildId) + '/' + encodeURIComponent(roleId), {
        method: 'PUT',
        body: JSON.stringify({ permissions })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        permissionMessage(data.error || 'Salvataggio non riuscito.', 'error');
        return;
      }
      const role = permissionRoles.find(item => item.id === roleId);
      if (role) role.permissions = permissions;
      savedPermissionValues = JSON.stringify(permissions);
      permissionMessage(permissions.length ? 'Permessi salvati e applicati.' : 'Accesso dashboard rimosso per questo ruolo.', 'success');
    } catch (error) {
      console.error('[permissions] salvataggio non riuscito', error);
      permissionMessage('Errore durante il salvataggio. Riprova.', 'error');
    } finally {
      permissionSaveInProgress = false;
      button.textContent = 'Salva modifiche';
      updatePermissionEditor();
    }
  }
  document.getElementById('permission-guild').addEventListener('change', handlePermissionGuildChange);
  document.getElementById('permission-role').addEventListener('change', handlePermissionRoleChange);
  document.getElementById('permission-select-all').addEventListener('click', () => {
    permissionInputs().forEach(input => { input.checked = true; });
    updatePermissionEditor();
  });
  document.getElementById('permission-clear-all').addEventListener('click', () => {
    permissionInputs().forEach(input => { input.checked = false; });
    updatePermissionEditor();
  });
  document.getElementById('permission-reset').addEventListener('click', resetPermissionChanges);
  document.getElementById('permission-reload').addEventListener('click', reloadPermissionData);
  permissionInputs().forEach(input => input.addEventListener('change', () => {
    if (document.getElementById('permission-message').classList.contains('error')) {
      permissionMessage('Modifiche non salvate', 'pending');
    }
    updatePermissionEditor();
  }));
  document.getElementById('permission-save').addEventListener('click', saveRolePermissions);
  loadPermissionGuilds();
  </script>`;
}

// ---------- MOD LOGS ----------
function renderModlogsContent() {
  return `
  <div class="section">
    <div class="tool-heading">
      <div><h2>📋 Mod Logs</h2><p class="tool-subtitle">Registro delle azioni di moderazione, con filtri rapidi e ricerca nei dettagli.</p></div>
      <div class="export-bar"><button class="secondary small" onclick="loadLogs(true)">↻ Aggiorna</button><a href="/api/export/logs.csv">📥 Esporta CSV</a></div>
    </div>
    <div class="tool-stats">
      <div class="tool-stat"><strong id="logs-total">—</strong><span>Log disponibili</span></div>
      <div class="tool-stat"><strong id="logs-visible">—</strong><span>Risultati filtrati</span></div>
    </div>
    <div class="tool-controls">
      <select id="filter-type" onchange="renderLogs()">
        <option value="">Tutti i tipi</option>
        <option value="Kick">Kick</option>
        <option value="Ban">Ban</option>
        <option value="Warn">Warn</option>
        <option value="Timeout">Timeout</option>
        <option value="Clear">Clear</option>
        <option value="Purge">Purge</option>
        <option value="Lock">Lock</option>
        <option value="Unlock">Unlock</option>
        <option value="Ticket Claim">Ticket Claim</option>
        <option value="Ticket Priorità">Ticket Priorità</option>
      </select>
      <input type="search" id="filter-user" placeholder="ID utente target" oninput="renderLogs()" maxlength="20">
      <input type="search" id="filter-log-text" placeholder="Cerca target, moderatore o motivo" oninput="renderLogs()" maxlength="100">
    </div>
    <div id="logs-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let allLogs = [];
  let logsLoaded = false;
  async function loadLogs(force) {
    const el = document.getElementById('logs-content');
    if (!logsLoaded || force) {
      el.innerHTML = '<p class="loading">Caricamento log...</p>';
      try {
        const res = await apiFetch('/api/logs/all');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (!Array.isArray(data)) throw new Error('Risposta non valida dal server');
        allLogs = data;
        logsLoaded = true;
      } catch (error) {
        el.innerHTML = '<div class="tool-empty">Impossibile caricare i log. <button class="secondary small" onclick="loadLogs(true)">Riprova</button></div>';
        console.error('[modlogs] caricamento non riuscito', error);
        return;
      }
    }
    renderLogs();
  }
  function renderLogs() {
    const type = document.getElementById('filter-type').value;
    const userId = document.getElementById('filter-user').value.trim();
    const query = document.getElementById('filter-log-text').value.trim().toLowerCase();
    let logs = allLogs;
    if (type) logs = logs.filter(l => l.type === type);
    if (userId) logs = logs.filter(l => (l.target_id || '').includes(userId));
    if (query) logs = logs.filter(l => [l.target, l.target_id, l.moderator, l.reason, l.type]
      .some(value => String(value || '').toLowerCase().includes(query)));
    const el = document.getElementById('logs-content');
    document.getElementById('logs-total').textContent = allLogs.length.toLocaleString('it-IT');
    document.getElementById('logs-visible').textContent = logs.length.toLocaleString('it-IT');
    if (!logs.length) { el.innerHTML = '<div class="tool-empty">' + (allLogs.length ? 'Nessun log corrisponde ai filtri.' : 'Non ci sono ancora log di moderazione.') + '</div>'; return; }
    el.innerHTML = '<div class="tool-table-wrap"><table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th><th>Durata</th></tr></thead><tbody>' +
      logs.map(l => '<tr>' +
        '<td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td>' +
        '<td><span class="badge ' + esc((l.type || 'default').toLowerCase()) + '">' + esc(l.type || '-') + '</span></td>' +
        '<td>' + (l.target_id ? '<a class="user-link" href="/user/' + esc(l.target_id) + '">' + esc(l.target || l.target_id) + '</a>' : esc(l.target || '-')) + '</td>' +
        '<td>' + esc(l.moderator || '-') + '</td>' +
        '<td>' + esc(l.reason || '-') + '</td>' +
        '<td>' + esc(l.duration || '-') + '</td>' +
      '</tr>').join('') + '</tbody></table></div>';
  }
  loadLogs(false);
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
    const res = await apiFetch('/api/notes/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { alert('✅ Eliminate ' + data.count + ' note'); loadNotes(); }
    else alert('❌ [' + res.status + '] ' + (data.error || 'Errore'));
  }
  async function deleteNote(id) {
    if (!confirm('Eliminare la nota #' + id + '?')) return;
    const res = await apiFetch('/api/notes/' + encodeURIComponent(id), { method: 'DELETE' });
    if (res.ok) loadNotes();
    else { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); }
  }
  loadNotes();
  </script>`;
}

// ---------- TICKET ----------
function renderTicketsContent() {
  return `
  <div class="section">
    <div class="tool-heading">
      <div><h2>🎫 Ticket Aperti</h2><p class="tool-subtitle">Gestisci assegnazione, priorità e chiusura dei ticket attivi.</p></div>
      <button class="secondary small" onclick="loadTickets(true)">↻ Aggiorna</button>
    </div>
    <div class="tool-stats">
      <div class="tool-stat"><strong id="tickets-total">—</strong><span>Ticket aperti</span></div>
      <div class="tool-stat"><strong id="tickets-urgent">—</strong><span>Priorità alta/urgente</span></div>
    </div>
    <div class="form-row" style="margin-bottom:14px;">
      <select id="tp-channel" aria-label="Canale in cui inviare il pannello ticket"></select>
      <button onclick="createTicketPanel()">📋 Crea Pannello Ticket</button>
    </div>
    <div class="tool-controls">
      <input type="search" id="ticket-filter" placeholder="Cerca server, canale o utente" oninput="renderTickets()" maxlength="100">
      <select id="ticket-priority-filter" onchange="renderTickets()" aria-label="Filtra per priorità">
        <option value="">Tutte le priorità</option><option value="low">Bassa</option><option value="med">Media</option><option value="high">Alta</option><option value="urgent">Urgente</option>
      </select>
    </div>
    <div id="tickets-content" class="loading">Caricamento...</div>
  </div>

  <div class="section">
    <div class="tool-heading">
      <div><h2>📜 Archivio Transcripts</h2><p class="tool-subtitle">Ultimi 100 ticket chiusi, con transcript consultabili.</p></div>
      <button class="secondary small" onclick="loadTranscripts(true)">↻ Aggiorna</button>
    </div>
    <div class="tool-controls"><input type="search" id="transcript-filter" placeholder="Cerca canale, utente o staff" oninput="renderTranscripts()" maxlength="100"></div>
    <div id="transcripts-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let openTickets = [];
  let savedTranscripts = [];

  async function loadChannelsForPanel() {
    const sel = document.getElementById('tp-channel');
    try {
      const res = await apiFetch('/api/messages/channels');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const chs = await res.json();
      sel.innerHTML = chs.map(c => '<option value="' + esc(c.channelId) + '">' + esc(c.guildName) + ' → #' + esc(c.channelName) + '</option>').join('') || '<option value="">Nessun canale disponibile</option>';
    } catch (error) {
      sel.innerHTML = '<option value="">Canali non disponibili</option>';
      console.error('[tickets] caricamento canali non riuscito', error);
    }
  }

  async function createTicketPanel() {
    const channelId = document.getElementById('tp-channel').value;
    if (!channelId) { alert('Seleziona un canale'); return; }
    if (!confirm('Inviare il pannello ticket in questo canale?')) return;
    try {
      const res = await apiFetch('/api/ticketpanel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId }) });
      if (res.ok) alert('✅ Pannello inviato');
      else { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); }
    } catch (error) { alert('❌ Invio non riuscito. Controlla la connessione e riprova.'); console.error('[tickets] invio pannello non riuscito', error); }
  }

  async function loadTickets(force) {
    const el = document.getElementById('tickets-content');
    if (!force || !openTickets.length) el.innerHTML = '<p class="loading">Caricamento ticket...</p>';
    try {
      const res = await apiFetch('/api/tickets');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error('Risposta non valida dal server');
      openTickets = data;
      renderTickets();
    } catch (error) {
      el.innerHTML = '<div class="tool-empty">Impossibile caricare i ticket. <button class="secondary small" onclick="loadTickets(true)">Riprova</button></div>';
      console.error('[tickets] caricamento non riuscito', error);
    }
  }

  function renderTickets() {
    const query = document.getElementById('ticket-filter').value.trim().toLowerCase();
    const priority = document.getElementById('ticket-priority-filter').value;
    const tickets = openTickets.filter(t => {
      const matchesQuery = !query || [t.guild, t.channel, t.userId, t.claimedBy].some(value => String(value || '').toLowerCase().includes(query));
      return matchesQuery && (!priority || t.priority === priority);
    });
    document.getElementById('tickets-total').textContent = openTickets.length.toLocaleString('it-IT');
    document.getElementById('tickets-urgent').textContent = openTickets.filter(t => t.priority === 'high' || t.priority === 'urgent').length.toLocaleString('it-IT');
    const el = document.getElementById('tickets-content');
    if (!tickets.length) { el.innerHTML = '<div class="tool-empty">' + (openTickets.length ? 'Nessun ticket corrisponde ai filtri.' : 'Non ci sono ticket aperti.') + '</div>'; return; }
    el.innerHTML = '<div class="tool-table-wrap"><table><thead><tr><th>Server</th><th>Canale</th><th>Utente</th><th>Claim</th><th>Priorità</th><th>Azioni</th></tr></thead><tbody>' +
      tickets.map(t => '<tr>' +
        '<td>' + esc(t.guild) + '</td>' +
        '<td>#' + esc(t.channel) + '</td>' +
        '<td><a class="user-link" href="/user/' + esc(t.userId) + '">' + esc(t.userId) + '</a></td>' +
        '<td>' + esc(t.claimedBy || '-') + '</td>' +
        '<td><span class="badge ' + esc(t.priority === 'urgent' || t.priority === 'high' ? 'ban' : 'default') + '">' + esc(t.priority || '—') + '</span></td>' +
        '<td><div class="ticket-actions">' +
          '<button class="secondary small" onclick="claimTicket(\\'' + esc(t.channelId) + '\\')">Prendi</button> ' +
          '<select aria-label="Modifica priorità" onchange="setPriority(\\'' + esc(t.channelId) + '\\', this.value)">' +
            '<option value="">Priorità</option>' +
            '<option value="low"' + (t.priority === 'low' ? ' selected' : '') + '>🟢 Bassa</option>' +
            '<option value="med"' + (t.priority === 'med' ? ' selected' : '') + '>🟡 Media</option>' +
            '<option value="high"' + (t.priority === 'high' ? ' selected' : '') + '>🟠 Alta</option>' +
            '<option value="urgent"' + (t.priority === 'urgent' ? ' selected' : '') + '>🔴 Urgente</option>' +
          '</select>' +
          '<button class="danger small" onclick="closeTicket(\\'' + esc(t.channelId) + '\\')">Chiudi</button>' +
        '</div></td>' +
      '</tr>').join('') + '</tbody></table></div>';
  }

  async function claimTicket(channelId) {
    const r = await postJson('/api/tickets/' + encodeURIComponent(channelId) + '/claim', {});
    if (r.ok) loadTickets();
    else alert('❌ ' + ((r.data && r.data.error) || 'Errore'));
  }

  async function setPriority(channelId, priority) {
    if (!priority) return;
    const r = await postJson('/api/tickets/' + encodeURIComponent(channelId) + '/priority', { priority: priority });
    if (r.ok) loadTickets();
    else alert('❌ ' + ((r.data && r.data.error) || 'Errore'));
  }

  async function loadTranscripts(force) {
    const el = document.getElementById('transcripts-content');
    el.innerHTML = '<p class="loading">Caricamento archivio...</p>';
    try {
      const res = await apiFetch('/api/tickets/transcripts');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error('Risposta non valida dal server');
      savedTranscripts = data;
      renderTranscripts();
    } catch (error) {
      el.innerHTML = '<div class="tool-empty">Impossibile caricare i transcript. <button class="secondary small" onclick="loadTranscripts(true)">Riprova</button></div>';
      console.error('[tickets] caricamento transcript non riuscito', error);
    }
  }

  function renderTranscripts() {
    const query = document.getElementById('transcript-filter').value.trim().toLowerCase();
    const transcripts = savedTranscripts.filter(t => !query || [t.channel_name, t.user_id, t.claimed_by, t.priority]
      .some(value => String(value || '').toLowerCase().includes(query)));
    const el = document.getElementById('transcripts-content');
    if (!transcripts.length) { el.innerHTML = '<div class="tool-empty">' + (savedTranscripts.length ? 'Nessun transcript corrisponde alla ricerca.' : 'Non ci sono transcript salvati.') + '</div>'; return; }
    el.innerHTML = '<div class="tool-table-wrap"><table><thead><tr><th>Data</th><th>Canale</th><th>Utente</th><th>Claim</th><th>Priorità</th><th>Link</th></tr></thead><tbody>' +
      transcripts.map(t => '<tr>' +
        '<td>' + esc(new Date(t.created_at).toLocaleString('it-IT')) + '</td>' +
        '<td>#' + esc(t.channel_name) + '</td>' +
        '<td>' + esc(t.user_id) + '</td>' +
        '<td>' + esc(t.claimed_by || '-') + '</td>' +
        '<td><span class="badge default">' + esc(t.priority || '—') + '</span></td>' +
        '<td><a class="user-link" href="/api/tickets/transcripts/' + encodeURIComponent(t.id) + '" target="_blank" rel="noopener">Visualizza ↗</a></td>' +
        '</tr>').join('') + '</tbody></table></div>';
  }

  async function closeTicket(channelId) {
    if (!confirm('Chiudere ed eliminare questo ticket? Verrà salvato un transcript.')) return;
    const res = await apiFetch('/api/tickets/' + encodeURIComponent(channelId), { method: 'DELETE' });
    if (res.ok) { alert('✅ Ticket chiuso e transcript salvato'); loadTickets(true); loadTranscripts(true); }
    else { const data = await res.json().catch(() => ({})); alert('Errore: ' + (data.error || 'sconosciuto')); }
  }

  loadChannelsForPanel();
  loadTickets();
  loadTranscripts();
  setInterval(() => loadTickets(true), 15000);
  </script>`;
}

// ---------- COMANDI CUSTOM ----------
function renderCommandsContent() {
  return `
  <div class="section">
    <div class="tool-heading"><div><h2>➕ Crea un comando</h2><p class="tool-subtitle">Aggiungi una risposta personalizzata richiamabile con il prefisso del bot.</p></div></div>
    <input type="text" id="cmd-name" placeholder="Nome comando (es. regole)" maxlength="50" oninput="updateCommandPreview()" aria-label="Nome comando">
    <textarea id="cmd-response" rows="3" placeholder="Scrivi la risposta del bot..." maxlength="4096" oninput="updateCommandPreview()" aria-label="Risposta comando"></textarea>
    <div class="field-meta"><span>Solo lettere, numeri, trattini e underscore</span><span id="cmd-response-count">0 / 4096</span></div>
    <div class="tool-preview"><div id="cmd-preview-name" style="margin-bottom:8px;color:#b9a9ff;font-weight:700;">-nome-comando</div><div id="cmd-preview">La risposta apparirà qui in anteprima.</div></div>
    <div class="export-bar" style="margin-top:12px;"><button onclick="addCmd()">➕ Aggiungi comando</button></div>
    <div id="cmd-msg"></div>
  </div>

  <div class="section">
    <div class="tool-heading">
      <div><h2>🔧 I tuoi comandi</h2><p class="tool-subtitle">Gestisci i comandi registrati e rimuovi quelli non più necessari.</p></div>
      <button class="secondary small" onclick="loadCmds(true)">↻ Aggiorna</button>
    </div>
    <div class="tool-stats"><div class="tool-stat"><strong id="cmd-total">—</strong><span>Comandi registrati</span></div><div class="tool-stat"><strong id="cmd-selected-count">0</strong><span>Selezionati</span></div></div>
    <div class="tool-controls">
      <input type="search" id="cmd-filter" placeholder="Cerca per comando o risposta" oninput="renderCmds()" maxlength="100">
      <button class="danger small" onclick="bulkDeleteCmds()">🗑️ Elimina selezionati</button>
    </div>
    <div id="commands-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let customCommands = [];
  let selectedCommands = new Set();
  async function loadCmds(force) {
    const el = document.getElementById('commands-content');
    el.innerHTML = '<p class="loading">Caricamento comandi...</p>';
    try {
      const res = await apiFetch('/api/commands');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error('Risposta non valida dal server');
      customCommands = data;
      selectedCommands = new Set(Array.from(selectedCommands).filter(name => customCommands.some(command => command.name === name)));
      renderCmds();
    } catch (error) {
      el.innerHTML = '<div class="tool-empty">Impossibile caricare i comandi. <button class="secondary small" onclick="loadCmds(true)">Riprova</button></div>';
      console.error('[commands] caricamento non riuscito', error);
    }
  }
  function renderCmds() {
    const query = document.getElementById('cmd-filter').value.trim().toLowerCase();
    const cmds = customCommands.filter(c => !query || (c.name + ' ' + c.response).toLowerCase().includes(query));
    const el = document.getElementById('commands-content');
    document.getElementById('cmd-total').textContent = customCommands.length.toLocaleString('it-IT');
    updateCommandSelection();
    if (!cmds.length) {
      el.innerHTML = '<div class="tool-empty">' + (customCommands.length ? 'Nessun comando corrisponde alla ricerca.' : 'Non hai ancora creato comandi personalizzati.') + '</div>';
      return;
    }
    el.innerHTML = '<div class="tool-table-wrap"><table><thead><tr><th style="width:30px;"><input type="checkbox" id="cmd-select-all" onclick="toggleAllCmds()" aria-label="Seleziona i comandi visibili"></th><th>Comando</th><th>Risposta</th><th></th></tr></thead><tbody>' +
      cmds.map(c => '<tr><td><input type="checkbox" class="cmd-check" value="' + esc(c.name) + '"' + (selectedCommands.has(c.name) ? ' checked' : '') + ' onchange="setCommandSelected(this)"></td><td><code>-' + esc(c.name) + '</code></td><td style="white-space:pre-wrap;overflow-wrap:anywhere;">' + esc(c.response) + '</td><td><button class="danger small" onclick="removeCmd(\\'' + esc(c.name) + '\\')">Elimina</button></td></tr>').join('') + '</tbody></table></div>';
    updateCommandSelection();
  }
  function toggleAllCmds() {
    const checked = document.getElementById('cmd-select-all').checked;
    document.querySelectorAll('.cmd-check').forEach(c => {
      c.checked = checked;
      if (checked) selectedCommands.add(c.value);
      else selectedCommands.delete(c.value);
    });
    updateCommandSelection();
  }
  function setCommandSelected(checkbox) {
    if (checkbox.checked) selectedCommands.add(checkbox.value);
    else selectedCommands.delete(checkbox.value);
    updateCommandSelection();
  }
  function updateCommandSelection() {
    const checks = Array.from(document.querySelectorAll('.cmd-check'));
    const selectedVisible = checks.filter(c => selectedCommands.has(c.value)).length;
    const count = document.getElementById('cmd-selected-count');
    if (count) count.textContent = selectedCommands.size.toLocaleString('it-IT');
    const selectAll = document.getElementById('cmd-select-all');
    if (selectAll) {
      selectAll.checked = checks.length > 0 && selectedVisible === checks.length;
      selectAll.indeterminate = selectedVisible > 0 && selectedVisible < checks.length;
    }
  }
  function updateCommandPreview() {
    const name = document.getElementById('cmd-name').value.trim();
    const response = document.getElementById('cmd-response').value;
    document.getElementById('cmd-response-count').textContent = response.length.toLocaleString('it-IT') + ' / 4096';
    document.getElementById('cmd-preview').textContent = response || 'La risposta apparirà qui in anteprima.';
    document.getElementById('cmd-preview-name').textContent = name && /^[a-z0-9_-]{1,50}$/i.test(name) ? '-' + name.toLowerCase() : '-nome-comando';
  }
  async function bulkDeleteCmds() {
    const names = Array.from(selectedCommands);
    if (!names.length) { alert('Nessun comando selezionato'); return; }
    if (!confirm('Eliminare ' + names.length + ' comandi?')) return;
    try {
      const res = await apiFetch('/api/commands/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ names }) });
      const data = await res.json().catch(() => ({}));
      if (res.ok) { names.forEach(name => selectedCommands.delete(name)); alert('✅ Eliminati ' + data.count + ' comandi'); loadCmds(true); }
      else alert('❌ [' + res.status + '] ' + (data.error || 'Errore'));
    } catch (error) { alert('❌ Eliminazione non riuscita. Riprova.'); console.error('[commands] eliminazione multipla non riuscita', error); }
  }
  async function addCmd() {
    const name = document.getElementById('cmd-name').value.trim();
    const response = document.getElementById('cmd-response').value.trim();
    const msg = document.getElementById('cmd-msg');
    if (!name || !response) { msg.innerHTML = '<span class="error">❌ Compila tutti i campi</span>'; return; }
    if (!/^[a-z0-9_-]{1,50}$/i.test(name)) { msg.innerHTML = '<span class="error">❌ Usa solo lettere, numeri, trattini e underscore nel nome</span>'; return; }
    if (/@(everyone|here)\\b/i.test(response)) { msg.innerHTML = '<span class="error">❌ Le menzioni @everyone e @here non sono consentite nelle risposte custom</span>'; return; }
    try {
      const res = await apiFetch('/api/commands', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, response }) });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        msg.innerHTML = '<span class="success">✅ Comando -' + esc(name.toLowerCase()) + ' aggiunto</span>';
        document.getElementById('cmd-name').value = '';
        document.getElementById('cmd-response').value = '';
        updateCommandPreview();
        loadCmds(true);
      } else { msg.innerHTML = '<span class="error">❌ [' + res.status + '] ' + esc(data.error || 'Errore') + '</span>'; }
    } catch (error) { msg.innerHTML = '<span class="error">❌ Connessione non riuscita. Riprova.</span>'; console.error('[commands] creazione non riuscita', error); }
  }
  async function removeCmd(name) {
    if (!confirm('Eliminare il comando -' + name + '?')) return;
    try {
      const res = await apiFetch('/api/commands/' + encodeURIComponent(name), { method: 'DELETE' });
      if (!res.ok) { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); return; }
      selectedCommands.delete(name);
      loadCmds(true);
    } catch (error) { alert('❌ Eliminazione non riuscita. Riprova.'); console.error('[commands] eliminazione non riuscita', error); }
  }
  loadCmds();
  updateCommandPreview();
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
          <button onclick="saveAutorole('\${esc(guildId)}')">Salva</button>
          <div id="autorole-msg"></div>
        </div>

        <div class="config-block">
          <h3>📋 Canale Log Moderazione</h3>
          <select id="cfg-logchannel">
            <option value="">— Nessuno —</option>
            \${guild.channels.map(c => '<option value="' + esc(c.id) + '" ' + (config.log_channel_id === c.id ? 'selected' : '') + '>#' + esc(c.name) + '</option>').join('')}
          </select>
          <button onclick="saveLogChannel('\${esc(guildId)}')">Salva</button>
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
          <br><button onclick="saveWelcome('\${esc(guildId)}')">Salva</button>
          <button class="secondary" onclick="testWelcome('\${esc(guildId)}')">🧪 Test Welcome</button>
          <div id="welcome-msg"></div>
        </div>
      </div>
    \`;
  }

  async function saveAutorole(guildId) {
    const autoroleId = document.getElementById('cfg-autorole').value || null;
    const res = await apiFetch('/api/config/' + encodeURIComponent(guildId), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ autoroleId }) });
    document.getElementById('autorole-msg').innerHTML = res.ok ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  async function saveLogChannel(guildId) {
    const logChannelId = document.getElementById('cfg-logchannel').value || null;
    const res = await apiFetch('/api/config/' + encodeURIComponent(guildId), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ logChannelId }) });
    document.getElementById('logchannel-msg').innerHTML = res.ok ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  async function saveWelcome(guildId) {
    const channelId = document.getElementById('cfg-welcomechannel').value || null;
    const message = document.getElementById('cfg-welcomemessage').value;
    const embedEnabled = document.getElementById('cfg-welcomeembed').checked;
    const res = await apiFetch('/api/welcome/' + encodeURIComponent(guildId), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId, message, embedEnabled }) });
    document.getElementById('welcome-msg').innerHTML = res.ok ? '<span class="success">✅ Salvato</span>' : '<span class="error">❌ Errore</span>';
  }
  async function testWelcome(guildId) {
    if (!confirm('Inviare un messaggio di test nel canale welcome?')) return;
    const res = await apiFetch('/api/welcome/' + encodeURIComponent(guildId) + '/test', { method: 'POST' });
    if (res.ok) alert('✅ Test inviato');
    else { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); }
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
  const USER_ID = ${safeJson(userId)};
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
    else ticketsEl.innerHTML = '<table><thead><tr><th>Server</th><th>Canale</th><th>Claim</th><th>Priorità</th><th></th></tr></thead><tbody>' +
      data.tickets.map(t => '<tr><td>' + esc(t.guild) + '</td><td>#' + esc(t.channel) + '</td><td>' + esc(t.claimedBy || '-') + '</td><td>' + esc(t.priority || '-') + '</td><td><button class="danger small" onclick="closeTicket(\\'' + esc(t.channelId) + '\\')">Chiudi</button></td></tr>').join('') + '</tbody></table>';
  }

  async function removeBL() {
    if (!confirm('Rimuovere ' + USER_ID + ' dalla blacklist? Verrà sbannato dove è bannato.')) return;
    const res = await apiFetch('/api/blacklist/' + encodeURIComponent(USER_ID), { method: 'DELETE' });
    if (!res.ok) { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); return; }
    loadUser();
  }
  async function deleteNote(id) {
    if (!confirm('Eliminare la nota #' + id + '?')) return;
    const res = await apiFetch('/api/notes/' + encodeURIComponent(id), { method: 'DELETE' });
    if (!res.ok) { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); return; }
    loadUser();
  }
  async function closeTicket(channelId) {
    if (!confirm('Chiudere questo ticket? Il canale verrà cancellato.')) return;
    const res = await apiFetch('/api/tickets/' + encodeURIComponent(channelId), { method: 'DELETE' });
    if (!res.ok) { const d = await res.json().catch(() => ({})); alert('❌ ' + (d.error || 'Errore')); return; }
    loadUser();
  }
  loadUser();
  </script>`;
}

// ---------- RICERCA ----------
function renderSearchContent(q) {
  return `
  <div class="section">
    <div class="tool-heading">
      <div><h2>🔍 Ricerca globale</h2><p class="tool-subtitle">Trova utenti e contenuti in blacklist, note staff, log e ticket autorizzati.</p></div>
    </div>
    <form class="tool-controls" action="/search" method="get" role="search">
      <input type="search" name="q" id="search-query" placeholder="Utente, ID, motivo o parola chiave..." value="${escapeHtml(q)}" maxlength="100" aria-label="Termine di ricerca">
      <button type="submit">Cerca</button>
    </form>
    <div class="tool-stats">
      <div class="tool-stat"><strong id="search-total">—</strong><span>Risultati totali</span></div>
      <div class="tool-stat"><strong id="search-categories">—</strong><span>Sezioni con risultati</span></div>
    </div>
    <div class="tool-controls" id="search-filters" aria-label="Filtra categoria risultati"></div>
    <div id="search-content" class="loading">Ricerca in corso...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  const QUERY = ${safeJson(q)};
  let searchResults = null;
  let searchCategory = 'all';

  async function doSearch() {
    const el = document.getElementById('search-content');
    if (!QUERY.trim()) { el.innerHTML = '<p class="loading">Inserisci un termine di ricerca.</p>'; return; }
    el.innerHTML = '<p class="loading">Ricerca in corso...</p>';
    try {
      const res = await apiFetch('/api/search?q=' + encodeURIComponent(QUERY));
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!data || !Array.isArray(data.blacklist) || !Array.isArray(data.notes) || !Array.isArray(data.logs) || !Array.isArray(data.tickets)) {
        throw new Error('Risposta non valida dal server');
      }
      searchResults = data;
      renderSearchResults();
    } catch (error) {
      el.innerHTML = '<div class="tool-empty">Ricerca non disponibile. <button class="secondary small" onclick="doSearch()">Riprova</button></div>';
      console.error('[search] ricerca non riuscita', error);
    }
  }

  function setSearchCategory(category) {
    searchCategory = category;
    renderSearchResults();
  }

  function renderSearchResults() {
    if (!searchResults) return;
    const groups = [
      { key: 'blacklist', label: 'Blacklist', icon: '🚫', rows: searchResults.blacklist },
      { key: 'notes', label: 'Note staff', icon: '📝', rows: searchResults.notes },
      { key: 'logs', label: 'Mod Logs', icon: '📋', rows: searchResults.logs },
      { key: 'tickets', label: 'Ticket', icon: '🎫', rows: searchResults.tickets }
    ];
    const total = groups.reduce((sum, group) => sum + group.rows.length, 0);
    const activeGroups = groups.filter(group => group.rows.length);
    document.getElementById('search-total').textContent = total.toLocaleString('it-IT');
    document.getElementById('search-categories').textContent = activeGroups.length.toLocaleString('it-IT');
    document.getElementById('search-filters').innerHTML = '<button class="' + (searchCategory === 'all' ? '' : 'secondary') + ' small" onclick="setSearchCategory(\\'all\\')">Tutto · ' + total + '</button>' +
      activeGroups.map(group => '<button class="' + (searchCategory === group.key ? '' : 'secondary') + ' small" onclick="setSearchCategory(\\'' + group.key + '\\')">' + group.icon + ' ' + esc(group.label) + ' · ' + group.rows.length + '</button>').join('');
    const visibleGroups = searchCategory === 'all' ? activeGroups : activeGroups.filter(group => group.key === searchCategory);
    if (!visibleGroups.length) {
      document.getElementById('search-content').innerHTML = '<div class="tool-empty">' + (total ? 'Nessun risultato in questa categoria.' : 'Nessun risultato per “' + esc(QUERY) + '”. Prova con un altro ID o termine.') + '</div>';
      return;
    }
    let html = '';
    visibleGroups.forEach(group => {
      html += '<h3 style="margin:22px 0 10px;">' + group.icon + ' ' + esc(group.label) + ' <span style="color:#858a9b;font-size:12px;font-weight:400;">' + group.rows.length + '</span></h3>';
      if (group.key === 'blacklist') {
        html += '<div class="tool-table-wrap"><table><thead><tr><th>Utente</th><th>Motivo</th><th>Aggiunto da</th></tr></thead><tbody>' +
          group.rows.map(e => '<tr><td><a class="user-link" href="/user/' + encodeURIComponent(e.user_id) + '">' + esc(e.username) + '</a><div><code>' + esc(e.user_id) + '</code></div></td><td>' + esc(e.reason) + '</td><td>' + esc(e.moderator_tag) + '</td></tr>').join('') + '</tbody></table></div>';
      } else if (group.key === 'notes') {
        html += '<div class="tool-table-wrap"><table><thead><tr><th>#</th><th>Utente</th><th>Contenuto</th></tr></thead><tbody>' +
          group.rows.map(n => '<tr><td>' + esc(n.id) + '</td><td><a class="user-link" href="/user/' + encodeURIComponent(n.user_id) + '">' + esc(n.user_id) + '</a></td><td>' + esc(n.content) + '</td></tr>').join('') + '</tbody></table></div>';
      } else if (group.key === 'logs') {
        html += '<div class="tool-table-wrap"><table><thead><tr><th>Data</th><th>Tipo</th><th>Target</th><th>Moderatore</th><th>Motivo</th></tr></thead><tbody>' +
          group.rows.slice(0, 50).map(l => '<tr><td>' + esc(new Date(l.timestamp).toLocaleString('it-IT')) + '</td><td><span class="badge ' + esc((l.type || 'default').toLowerCase()) + '">' + esc(l.type || '-') + '</span></td><td>' + (l.target_id ? '<a class="user-link" href="/user/' + encodeURIComponent(l.target_id) + '">' + esc(l.target || l.target_id) + '</a>' : esc(l.target || '-')) + '</td><td>' + esc(l.moderator || '-') + '</td><td>' + esc(l.reason || '-') + '</td></tr>').join('') + '</tbody></table></div>';
        if (group.rows.length > 50) html += '<p class="tool-subtitle" style="margin-top:8px;">Mostrati 50 di ' + group.rows.length + ' log.</p>';
      } else {
        html += '<div class="tool-table-wrap"><table><thead><tr><th>Server</th><th>Canale</th></tr></thead><tbody>' +
          group.rows.map(t => '<tr><td>' + esc(t.guild) + '</td><td>#' + esc(t.channel) + '</td></tr>').join('') + '</tbody></table></div>';
      }
    });
    document.getElementById('search-content').innerHTML = html;
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
    <div class="filter-bar">
      <input type="text" id="al-filter" placeholder="Filtra per utente o azione..." oninput="renderAccess()" maxlength="100">
    </div>
    <div class="export-bar"><a href="/api/export/access-logs.csv">📥 Esporta CSV</a></div>
    <div id="access-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let allAccess = [];
  async function loadAccess() {
    const res = await apiFetch('/api/access-logs');
    if (!res.ok) {
      document.getElementById('access-content').innerHTML = '<p class="loading">Gli IP sono visibili solo agli admin indicati in DASHBOARD_ADMIN_IDS.</p>';
      return;
    }
    allAccess = await res.json();
    renderAccess();
  }
  function renderAccess() {
    const filter = (document.getElementById('al-filter').value || '').toLowerCase();
    const logs = filter
      ? allAccess.filter(l => (l.username || '').toLowerCase().includes(filter) || (l.user_id || '').includes(filter) || (l.user_agent || '').toLowerCase().includes(filter))
      : allAccess;
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

// ---------- MESSAGGI + MODERAZIONE CANALE ----------
function renderMessagesContent() {
  return `
  <div class="section">
    <div class="tool-heading">
      <div><h2>✉️ Invia un messaggio</h2><p class="tool-subtitle">Componi un messaggio o un embed e controlla l’anteprima prima dell’invio.</p></div>
    </div>
    <div class="charts-grid">
      <div>
        <label for="msg-channel" style="font-size:12px;color:#aeb2c1;">Server e canale</label>
        <select id="msg-channel" onchange="updateMessagePreview()" aria-label="Seleziona server e canale"></select>

        <label for="msg-content" style="font-size:12px;color:#aeb2c1;">Messaggio</label>
        <textarea id="msg-content" rows="5" placeholder="Scrivi il messaggio da inviare..." maxlength="2000" oninput="updateMessagePreview()"></textarea>
        <div class="field-meta"><span>Massimo 2000 caratteri</span><span id="msg-content-count">0 / 2000</span></div>
        <div class="mention-help">
          Per menzionare davvero qualcuno usa la sintassi Discord con il suo ID:
          utente <code>&lt;@ID&gt;</code> (oppure <code>&lt;@!ID&gt;</code>), ruolo <code>&lt;@&amp;ID&gt;</code>.
          Un testo come <code>@nome</code> non identifica da solo un account. I ping <code>@everyone</code>/<code>@here</code> richiedono l’opzione dedicata e una conferma.
        </div>
        <label class="inline-check"><input id="msg-allow-mentions" type="checkbox" checked onchange="updateMessagePreview()"> Attiva le menzioni esplicite di utenti e ruoli</label>
        <label class="inline-check"><input id="msg-allow-mass-mentions" type="checkbox" onchange="updateMessagePreview()"> Consenti ping di massa con @everyone e @here</label>

        <details style="margin:14px 0;">
          <summary style="cursor:pointer;color:#b9a9ff;">➕ Aggiungi embed opzionale</summary>
          <div style="margin-top:12px;">
            <input id="emb-title" placeholder="Titolo" maxlength="256" oninput="updateMessagePreview()">
            <textarea id="emb-desc" rows="3" placeholder="Descrizione" maxlength="4096" oninput="updateMessagePreview()"></textarea>
            <input id="emb-color" placeholder="Colore (es. #5865F2)" maxlength="20" oninput="updateMessagePreview()">
            <input id="emb-image" placeholder="URL immagine" maxlength="500" oninput="updateMessagePreview()">
            <input id="emb-thumb" placeholder="URL thumbnail" maxlength="500" oninput="updateMessagePreview()">
            <input id="emb-footer" placeholder="Footer" maxlength="2048" oninput="updateMessagePreview()">
          </div>
        </details>

        <button id="msg-send" onclick="sendMessage()">📤 Invia messaggio</button>
        <div id="msg-result" role="status" aria-live="polite"></div>
      </div>
      <div>
        <h3 style="margin:0 0 10px;color:#d4d6e0;font-size:14px;">Anteprima</h3>
        <div class="tool-preview" style="min-height:130px;">
          <div id="msg-preview-channel" style="margin-bottom:10px;color:#858a9b;font-size:11px;">Seleziona un canale</div>
          <div id="msg-preview-content" style="white-space:pre-wrap;overflow-wrap:anywhere;"></div>
          <div id="msg-preview-embed" style="display:none;margin-top:12px;padding:12px;border-left:3px solid #8068ed;border-radius:4px;background:#171923;">
            <strong id="msg-preview-title"></strong>
            <div id="msg-preview-description" style="margin-top:6px;white-space:pre-wrap;overflow-wrap:anywhere;"></div>
            <div id="msg-preview-footer" style="margin-top:10px;color:#858a9b;font-size:11px;"></div>
          </div>
          <div id="msg-preview-hints" style="margin-top:12px;color:#858a9b;font-size:11px;"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="tool-heading"><div><h2>🧹 Moderazione canale</h2><p class="tool-subtitle">Le azioni si applicano al canale selezionato sopra.</p></div></div>
    <div class="form-row">
      <input id="mc-amount" type="number" min="1" max="100" value="10" style="max-width:120px;">
      <button class="danger small" onclick="modClear()">🧹 Pulisci</button>
      <button class="secondary small" onclick="modLock()">🔒 Blocca</button>
      <button class="secondary small" onclick="modUnlock()">🔓 Sblocca</button>
    </div>
    <input id="mc-reason" placeholder="Motivo (opzionale, per il blocco)" maxlength="512">
    <div id="mc-result"></div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let channelsCache = [];
  async function loadChannels() {
    const sel = document.getElementById('msg-channel');
    try {
      const res = await apiFetch('/api/messages/channels');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error('Risposta non valida dal server');
      channelsCache = data;
      const grouped = {};
      channelsCache.forEach(channel => {
        const key = channel.guildId;
        if (!grouped[key]) grouped[key] = { name: channel.guildName, channels: [] };
        grouped[key].channels.push(channel);
      });
      sel.innerHTML = Object.keys(grouped).map(guildId => '<optgroup label="' + esc(grouped[guildId].name) + '">' +
        grouped[guildId].channels.map(c => '<option value="' + esc(c.channelId) + '">#' + esc(c.channelName) + '</option>').join('') + '</optgroup>').join('') ||
        '<option value="">Nessun canale accessibile</option>';
      updateMessagePreview();
    } catch (error) {
      sel.innerHTML = '<option value="">Canali non disponibili</option>';
      document.getElementById('msg-result').innerHTML = '<span class="error">❌ Impossibile caricare i canali. Riprova ricaricando la pagina.</span>';
      console.error('[messages] caricamento canali non riuscito', error);
    }
  }

  function updateMessagePreview() {
    const channel = channelsCache.find(c => c.channelId === document.getElementById('msg-channel').value);
    const content = document.getElementById('msg-content').value;
    const title = document.getElementById('emb-title').value.trim();
    const description = document.getElementById('emb-desc').value.trim();
    const footer = document.getElementById('emb-footer').value.trim();
    const mentionEnabled = document.getElementById('msg-allow-mentions').checked;
    const massMentionsEnabled = document.getElementById('msg-allow-mass-mentions').checked;
    const hasMassMention = /@(everyone|here)\\b/i.test(content);
    document.getElementById('msg-preview-channel').textContent = channel ? channel.guildName + ' · #' + channel.channelName : 'Seleziona un canale';
    document.getElementById('msg-preview-content').textContent = content || 'Il testo del messaggio apparirà qui.';
    document.getElementById('msg-content-count').textContent = content.length.toLocaleString('it-IT') + ' / 2000';
    document.getElementById('msg-preview-title').textContent = title;
    document.getElementById('msg-preview-description').textContent = description;
    document.getElementById('msg-preview-footer').textContent = footer;
    const embedPreview = document.getElementById('msg-preview-embed');
    embedPreview.style.display = title || description || footer ? 'block' : 'none';
    const mentionMatches = content.match(/<@!?\\d{17,20}>|<@&\\d{17,20}>/g) || [];
    const mentionHint = mentionMatches.length
      ? (mentionEnabled ? mentionMatches.length + ' menzion' + (mentionMatches.length === 1 ? 'e' : 'i') + ' esplicite attive' : 'Menzioni di utenti e ruoli disattivate')
      : (mentionEnabled ? 'I tag Discord di utenti e ruoli verranno menzionati' : 'Menzioni di utenti e ruoli disattivate');
    const massMentionHint = hasMassMention
      ? (massMentionsEnabled ? ' · Ping di massa attivo: verrà chiesta conferma prima dell’invio' : ' · @everyone/@here presenti ma senza notifiche')
      : (massMentionsEnabled ? ' · Ping di massa consentito se inserisci @everyone o @here' : ' · Ping di massa disattivati');
    document.getElementById('msg-preview-hints').textContent = mentionHint + massMentionHint;
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
    const btn = document.getElementById('msg-send');
    btn.disabled = true; btn.textContent = '⏳ Invio...';
    try {
      const allowMentions = document.getElementById('msg-allow-mentions').checked;
      const allowMassMentions = document.getElementById('msg-allow-mass-mentions').checked;
      if (allowMassMentions && /@(everyone|here)\\b/i.test(content) &&
          !confirm('Il messaggio notificherà @everyone o @here. Vuoi procedere?')) return;
      const res = await apiFetch('/api/messages/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channelId, content, embed, allowMentions, allowMassMentions }) });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        result.innerHTML = '<span class="success">✅ Inviato in #' + esc(currentChannel().channelName) + ' · ID: ' + esc(data.messageId) + '</span>';
        document.getElementById('msg-content').value = '';
        updateMessagePreview();
      } else {
        result.innerHTML = '<span class="error">❌ [' + res.status + '] ' + esc(data.error || 'Errore') + '</span>';
      }
    } catch (error) {
      result.innerHTML = '<span class="error">❌ Invio non riuscito. Controlla la connessione e riprova.</span>';
      console.error('[messages] invio non riuscito', error);
    } finally {
      btn.disabled = false; btn.textContent = '📤 Invia messaggio';
    }
  }

  function currentChannel() {
    const id = document.getElementById('msg-channel').value;
    return channelsCache.find(c => c.channelId === id) || null;
  }
  function mcShow(html) { document.getElementById('mc-result').innerHTML = html; }
  function mcReport(r, okText) {
    if (r.ok) mcShow('<span class="success">✅ ' + esc(okText) + '</span>');
    else mcShow('<span class="error">❌ [' + r.status + '] ' + esc((r.data && r.data.error) || 'Errore') + '</span>');
  }
  async function modClear() {
    const ch = currentChannel();
    if (!ch) return mcShow('<span class="error">❌ Seleziona un canale</span>');
    const amount = parseInt(document.getElementById('mc-amount').value, 10);
    if (!(amount >= 1 && amount <= 100)) return mcShow('<span class="error">❌ Inserisci un numero tra 1 e 100</span>');
    if (!confirm('Cancellare fino a ' + amount + ' messaggi in #' + ch.channelName + '?')) return;
    const r = await postJson('/api/mod/clear', { guildId: ch.guildId, channelId: ch.channelId, amount: amount });
    mcReport(r, r.ok ? 'Cancellati ' + r.data.count + ' messaggi' : '');
  }
  async function modLock() {
    const ch = currentChannel();
    if (!ch) return mcShow('<span class="error">❌ Seleziona un canale</span>');
    if (!confirm('Bloccare #' + ch.channelName + ' per tutti?')) return;
    const reason = document.getElementById('mc-reason').value.trim();
    const r = await postJson('/api/mod/lock', { guildId: ch.guildId, channelId: ch.channelId, reason: reason });
    mcReport(r, 'Canale bloccato');
  }
  async function modUnlock() {
    const ch = currentChannel();
    if (!ch) return mcShow('<span class="error">❌ Seleziona un canale</span>');
    const r = await postJson('/api/mod/unlock', { guildId: ch.guildId, channelId: ch.channelId });
    mcReport(r, 'Canale sbloccato');
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
    <select id="ua-guild" onchange="fillGuildOptions()"></select>
    <label style="font-size:13px;color:#888;">Motivo (opzionale)</label>
    <input id="ua-reason" placeholder="Motivo dell'azione" maxlength="512">
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
      <button class="secondary" onclick="doAction('kick')">👢 Kick</button>
      <button class="danger" onclick="doAction('ban')">🔨 Ban</button>
      <button class="secondary" onclick="doAction('unban')">🔓 Unban</button>
      <button class="secondary" onclick="doWarn()">⚠️ Warn</button>
    </div>
    <div id="ua-result"></div>

    <h3 style="margin-top:22px;font-size:15px;color:#bbb;">Altre azioni</h3>
    <div class="form-row">
      <input id="ua-timeout" type="number" min="1" max="40320" placeholder="Timeout (minuti, max 40320)">
      <button class="secondary" onclick="doTimeout()">⏱️ Timeout</button>
    </div>
    <div class="form-row">
      <select id="ua-role"></select>
      <button class="secondary" onclick="doRole('add')">➕ Assegna ruolo</button>
      <button class="secondary" onclick="doRole('remove')">➖ Rimuovi ruolo</button>
    </div>
    <div class="form-row">
      <select id="ua-invite-channel"></select>
      <button class="secondary" onclick="doInvite()">📨 Invita</button>
    </div>
    <textarea id="ua-note" rows="2" maxlength="1000" placeholder="Nota staff (2-1000 caratteri)"></textarea>
    <button class="secondary" onclick="doNote()">📝 Aggiungi nota</button>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let currentUser = null;
  let uaGuilds = [];

  async function loadGuildsForUA() {
    const res = await apiFetch('/api/guilds');
    uaGuilds = await res.json().catch(() => []);
    fillGuildOptions();
  }

  function fillGuildOptions() {
    const guildId = document.getElementById('ua-guild').value;
    const g = uaGuilds.find(x => x.id === guildId);
    document.getElementById('ua-role').innerHTML = (g && g.roles.length)
      ? g.roles.map(r => '<option value="' + esc(r.id) + '">' + esc(r.name) + '</option>').join('')
      : '<option value="">Nessun ruolo</option>';
    document.getElementById('ua-invite-channel').innerHTML = (g && g.channels.length)
      ? g.channels.map(c => '<option value="' + esc(c.id) + '">#' + esc(c.name) + '</option>').join('')
      : '<option value="">Nessun canale</option>';
  }

  async function lookupUser() {
    const userId = document.getElementById('ua-userid').value.trim();
    const info = document.getElementById('ua-userinfo');
    const actions = document.getElementById('ua-actions');
    if (!/^\\d{17,20}$/.test(userId)) { info.innerHTML = '<span class="error">❌ ID non valido</span>'; return; }
    info.innerHTML = '<p class="loading">Ricerca...</p>';
    const res = await apiFetch('/api/user-lookup/' + encodeURIComponent(userId));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { info.innerHTML = '<span class="error">❌ ' + esc(data.error || 'Errore') + '</span>'; actions.style.display = 'none'; return; }
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
    fillGuildOptions();

    actions.style.display = 'block';
  }

  function uaContext() {
    if (!currentUser) return null;
    const guildId = document.getElementById('ua-guild').value;
    if (!guildId) return null;
    return { guildId: guildId, userId: currentUser.id, tag: currentUser.tag };
  }
  function uaShow(html) { document.getElementById('ua-result').innerHTML = html; }
  function uaReport(r, okText) {
    if (r.ok) uaShow('<span class="success">✅ ' + esc(okText) + '</span>');
    else uaShow('<span class="error">❌ [' + r.status + '] ' + esc((r.data && r.data.error) || 'Errore') + '</span>');
  }
  function needCtx() {
    const c = uaContext();
    if (!c) uaShow('<span class="error">❌ Seleziona un server</span>');
    return c;
  }

  async function doAction(action) {
    const c = needCtx(); if (!c) return;
    if (!confirm('Confermi ' + action.toUpperCase() + ' di ' + c.tag + '?')) return;
    const reason = document.getElementById('ua-reason').value.trim();
    const r = await postJson('/api/user-action', { action: action, userId: c.userId, guildId: c.guildId, reason: reason });
    uaReport(r, action.toUpperCase() + ' eseguito');
  }

  async function doWarn() {
    const c = needCtx(); if (!c) return;
    if (!confirm('Registrare un warn per ' + c.tag + '?')) return;
    const reason = document.getElementById('ua-reason').value.trim();
    const r = await postJson('/api/mod/warn', { guildId: c.guildId, userId: c.userId, reason: reason });
    uaReport(r, 'Warn registrato');
  }

  async function doTimeout() {
    const c = needCtx(); if (!c) return;
    const minutes = parseInt(document.getElementById('ua-timeout').value, 10);
    if (!(minutes >= 1 && minutes <= 40320)) return uaShow('<span class="error">❌ Inserisci minuti tra 1 e 40320</span>');
    if (!confirm('Timeout di ' + minutes + ' minuti per ' + c.tag + '?')) return;
    const reason = document.getElementById('ua-reason').value.trim();
    const r = await postJson('/api/mod/timeout', { guildId: c.guildId, userId: c.userId, seconds: minutes * 60, reason: reason });
    uaReport(r, 'Timeout applicato');
  }

  async function doRole(action) {
    const c = needCtx(); if (!c) return;
    const roleId = document.getElementById('ua-role').value;
    if (!roleId) return uaShow('<span class="error">❌ Nessun ruolo selezionato</span>');
    const r = await postJson('/api/mod/role', { guildId: c.guildId, userId: c.userId, roleId: roleId, action: action });
    uaReport(r, action === 'add' ? 'Ruolo assegnato' : 'Ruolo rimosso');
  }

  async function doInvite() {
    const c = needCtx(); if (!c) return;
    const channelId = document.getElementById('ua-invite-channel').value;
    if (!channelId) return uaShow('<span class="error">❌ Nessun canale selezionato</span>');
    const r = await postJson('/api/mod/invite', { guildId: c.guildId, channelId: channelId, userId: c.userId });
    if (!r.ok) return uaReport(r, '');
    uaShow('<span class="success">✅ ' + esc(r.data.via === 'dm' ? 'Invito inviato in DM' : 'DM chiusi: invito postato nel canale') + '</span>');
  }

  async function doNote() {
    const c = needCtx(); if (!c) return;
    const content = document.getElementById('ua-note').value.trim();
    if (content.length < 2) return uaShow('<span class="error">❌ La nota è troppo corta</span>');
    const r = await postJson('/api/notes', { guildId: c.guildId, userId: c.userId, content: content });
    uaReport(r, 'Nota aggiunta');
    if (r.ok) document.getElementById('ua-note').value = '';
  }

  loadGuildsForUA();
  ${userId ? 'lookupUser();' : ''}
  </script>`;
}

// ---------- REMINDER ----------
function renderRemindersContent() {
  return `
  <div class="section">
    <h2>⏰ Nuovo Reminder</h2>
    <div class="form-row">
      <select id="rm-guild" onchange="loadChannels()"></select>
      <select id="rm-channel"></select>
    </div>
    <input id="rm-content" placeholder="Cosa ricordare (max 500)" maxlength="500">
    <div class="form-row">
      <input id="rm-hours" type="number" min="0" max="720" value="0" placeholder="Ore" style="max-width:120px;">
      <input id="rm-minutes" type="number" min="0" max="59" value="30" placeholder="Minuti" style="max-width:120px;">
      <button onclick="createReminder()">➕ Crea</button>
    </div>
    <div id="rm-result"></div>
  </div>

  <div class="section">
    <h2>📋 Reminder Recenti</h2>
    <div id="reminders-content" class="loading">Caricamento...</div>
  </div>

  <script>
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  let guildsData = [];
  let channelsCache = [];

  async function loadGuilds() {
    const res = await apiFetch('/api/guilds');
    guildsData = await res.json();
    const sel = document.getElementById('rm-guild');
    sel.innerHTML = guildsData.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('');
    if (!channelsCache.length) {
      const cRes = await apiFetch('/api/messages/channels');
      channelsCache = await cRes.json();
    }
    if (guildsData.length) loadChannels();
  }
  function loadChannels() {
    const guildId = document.getElementById('rm-guild').value;
    const filtered = channelsCache.filter(c => c.guildId === guildId);
    document.getElementById('rm-channel').innerHTML = filtered.map(c => '<option value="' + esc(c.channelId) + '">#' + esc(c.channelName) + '</option>').join('') || '<option value="">Nessun canale</option>';
  }
  async function createReminder() {
    const guildId = document.getElementById('rm-guild').value;
    const channelId = document.getElementById('rm-channel').value;
    const content = document.getElementById('rm-content').value.trim();
    const hours = parseInt(document.getElementById('rm-hours').value, 10);
    const minutes = parseInt(document.getElementById('rm-minutes').value, 10);
    const result = document.getElementById('rm-result');
    if (!guildId || !channelId || !content || Number.isNaN(hours) || Number.isNaN(minutes)) { result.innerHTML = '<span class="error">❌ Compila tutti i campi</span>'; return; }
    const res = await apiFetch('/api/reminders', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ guildId, channelId, content, hours, minutes }) });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      result.innerHTML = '<span class="success">✅ Reminder #' + esc(data.id) + ' creato</span>';
      document.getElementById('rm-content').value = '';
      document.getElementById('rm-hours').value = '0';
      document.getElementById('rm-minutes').value = '30';
      loadReminders();
    } else { result.innerHTML = '<span class="error">❌ [' + res.status + '] ' + esc(data.error || 'Errore') + '</span>'; }
  }
  async function loadReminders() {
    const res = await apiFetch('/api/reminders');
    const rows = await res.json();
    const el = document.getElementById('reminders-content');
    if (!rows.length) { el.innerHTML = '<p class="loading">Nessun reminder.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>#</th><th>Utente</th><th>Server</th><th>Canale</th><th>Contenuto</th><th>Quando</th></tr></thead><tbody>' +
      rows.map(r => '<tr>' +
        '<td>' + esc(r.id) + '</td>' +
        '<td><a class="user-link" href="/user/' + esc(r.user_id) + '">' + esc(r.user_id) + '</a></td>' +
        '<td>' + esc(r.guild_id) + '</td>' +
        '<td>' + esc(r.channel_id) + '</td>' +
        '<td>' + esc(r.content) + '</td>' +
        '<td>' + esc(new Date(r.remind_at).toLocaleString('it-IT')) + '</td>' +
      '</tr>').join('') + '</tbody></table>';
  }
  loadGuilds();
  loadReminders();
  </script>`;
}

module.exports = { createWebServer };
