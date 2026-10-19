require('dotenv').config();
const {
  Client,
  GatewayIntentBits,
  Partials,
  Events,
  PermissionsBitField,
  ChannelType,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  SlashCommandBuilder,
  REST,
  Routes,
  AuditLogEvent
} = require('discord.js');

const StorageService = require('./storage');
const { createWebServer } = require('./web');

// ==================== VALIDAZIONE ENV ====================
const TOKEN = (process.env.DISCORD_TOKEN || process.env.TOKEN || '').trim();
const CLIENT_ID = (process.env.CLIENT_ID || '').trim();
const MOD_LOG_CHANNEL_ID = (process.env.MOD_LOG_CHANNEL_ID || '').trim();
const BLACKLIST_ADMIN_SERVERS = (process.env.BLACKLIST_ADMIN_SERVERS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const GUILD_ID = (process.env.GUILD_ID || '').trim();

if (!TOKEN) throw new Error('TOKEN mancante nel file .env');
if (!CLIENT_ID) throw new Error('CLIENT_ID mancante nel file .env');
if (!MOD_LOG_CHANNEL_ID) throw new Error('MOD_LOG_CHANNEL_ID mancante nel file .env');

// ==================== LOGGER ====================
const log = {
  info: (msg) => console.log(`\x1b[36m[INFO]\x1b[0m ${msg}`),
  ok: (msg) => console.log(`\x1b[32m[OK]\x1b[0m ${msg}`),
  warn: (msg) => console.log(`\x1b[33m[WARN]\x1b[0m ${msg}`),
  err: (msg, err) => console.error(`\x1b[31m[ERR]\x1b[0m ${msg}`, err ?? '')
};

// ==================== UTILITY ====================
function formatDate(iso) {
  if (!iso) return 'N/A';
  return new Date(iso).toLocaleString('it-IT');
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}g`;
}

// Converte "10m", "1h", "2d", "30s" in millisecondi
function parseDuration(input) {
  if (!input) return null;
  const m = String(input).trim().match(/^(\d+)\s*(s|m|h|d)$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (isNaN(n) || n <= 0) return null;
  const unit = m[2].toLowerCase();
  const multipliers = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return n * multipliers[unit];
}

function getRoles(member, guild) {
  if (!member) return 'N/A';
  return member.roles.cache
    .filter(r => r.id !== guild.id)
    .map(r => r.toString())
    .join(', ') || 'Nessuno';
}

const STAFF_ROLES = ['Staff', 'Admin', 'Senior Admin'];
const ADMIN_ROLES = ['Admin', 'Senior Admin'];

function hasStaffOrAdmin(member) {
  if (!member) return false;
  if (member.permissions?.has(PermissionsBitField.Flags.Administrator)) return true;
  return member.roles?.cache?.some(r => STAFF_ROLES.includes(r.name)) ?? false;
}

function isAdmin(member) {
  if (!member) return false;
  if (member.permissions?.has(PermissionsBitField.Flags.Administrator)) return true;
  return member.roles?.cache?.some(r => ADMIN_ROLES.includes(r.name)) ?? false;
}

function actorName(executor) {
  if (!executor) return 'N/A';
  return executor.user ? executor.user.tag : (executor.username ?? 'N/A');
}

function outranks(executor, targetMember, guild) {
  if (!executor || !targetMember) return true;
  if (guild.ownerId === executor.id) return true;
  if (targetMember.id === guild.ownerId) return false;
  return executor.roles.highest.position > targetMember.roles.highest.position;
}

function extractUserId(input) {
  if (!input) return null;
  const str = String(input).trim();
  const m = str.match(/^<@!?(\d{17,20})>$/);
  if (m) return m[1];
  if (/^\d{17,20}$/.test(str)) return str;
  return null;
}

function extractRoleId(input) {
  if (!input) return null;
  const str = String(input).trim();
  const m = str.match(/^<@&(\d{17,20})>$/);
  if (m) return m[1];
  if (/^\d{17,20}$/.test(str)) return str;
  return null;
}

function isTicketChannel(channel) {
  return typeof channel.name === 'string' && channel.name.startsWith('ticket-');
}

function calculatePages(total, perPage) {
  return Math.max(1, Math.ceil(total / perPage));
}

function getPaginatedSlice(arr, page, perPage) {
  const start = page * perPage;
  return arr.slice(start, start + perPage);
}

function isInteractionSource(source) {
  return typeof source.isRepliable === 'function' && source.isRepliable();
}

const cooldowns = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cooldowns) if (now >= v) cooldowns.delete(k);
}, 60000).unref?.();

function checkCooldown(userId, commandName, cooldownTime = 3000) {
  const key = `${userId}-${commandName}`;
  const now = Date.now();
  const exp = cooldowns.get(key);
  if (exp && now < exp) {
    return { onCooldown: true, remaining: Math.ceil((exp - now) / 1000) };
  }
  cooldowns.set(key, now + cooldownTime);
  return { onCooldown: false };
}

async function safeReply(interaction, data) {
  try {
    if (interaction.replied || interaction.deferred) return await interaction.followUp(data);
    return await interaction.reply(data);
  } catch (err) {
    log.err('safeReply fallito', err);
    return null;
  }
}

async function safeReplySource(source, data, isSlash) {
  if (isSlash) {
    return safeReply(source, data);
  }
  const payload = { ...data };
  delete payload.ephemeral;
  try {
    return await source.channel.send(payload);
  } catch (err) {
    log.err('Invio messaggio fallito', err);
    return null;
  }
}

function buildResultEmbed(result, defaultTitle = 'Risultato') {
  const msg = (result && result.message) ? String(result.message) : '';
  const isSuccess = msg.includes('✅') || result?.success === true;
  const isError = msg.includes('❌') || result?.success === false;

  const cleanText = msg.replace(/^(✅|❌|⚠️|🧹|🔒|🔓|🏓|⏱️)\s*/u, '').trim();
  const customTitle = result && result.title ? result.title : defaultTitle;
  const title = isSuccess ? `✅ ${customTitle}` : isError ? `❌ ${customTitle}` : `ℹ️ ${customTitle}`;
  const color = isSuccess ? 0x00FF00 : isError ? 0xFF0000 : 0x0099FF;

  return EmbedManager.createEmbed({
    title,
    description: cleanText || 'Operazione completata.',
    color,
    timestamp: true
  });
}

// ==================== EMBED MANAGER ====================
class EmbedManager {
  static createEmbed(options = {}) {
    const embed = new EmbedBuilder();
    if (options.title) embed.setTitle(String(options.title).slice(0, 256));
    if (options.description) embed.setDescription(String(options.description).slice(0, 4096));
    if (options.color !== undefined) embed.setColor(options.color);
    if (Array.isArray(options.fields)) {
      const safe = options.fields
        .filter(f => f && f.name && f.value !== undefined && f.value !== null)
        .map(f => ({
          name: String(f.name).slice(0, 256),
          value: String(f.value).slice(0, 1024),
          inline: !!f.inline
        }));
      if (safe.length) embed.addFields(safe);
    }
    if (options.thumbnail) embed.setThumbnail(options.thumbnail);
    if (options.image) embed.setImage(options.image);
    if (options.author) embed.setAuthor(options.author);
    if (options.footer) embed.setFooter(options.footer);
    if (options.timestamp) embed.setTimestamp();
    return embed;
  }
  static success(title, desc) { return this.createEmbed({ title, description: desc, color: 0x00FF00, timestamp: true }); }
  static error(title, desc) { return this.createEmbed({ title, description: desc, color: 0xFF0000, timestamp: true }); }
  static info(title, desc) { return this.createEmbed({ title, description: desc, color: 0x0099FF, timestamp: true }); }
  static warning(title, desc) { return this.createEmbed({ title, description: desc, color: 0xFFA500, timestamp: true }); }
}

let clientRef = null;
const storage = new StorageService(process.env.DB_PATH || './data/bot.db');
const botStartTime = Date.now();

// ==================== ANTI-NUKE ====================
const antinukeTracker = new Map();

function trackAction(guildId, userId, actionType, windowMs) {
  const key = `${guildId}-${userId}-${actionType}`;
  const now = Date.now();
  const timestamps = antinukeTracker.get(key) || [];
  const recent = timestamps.filter(t => now - t < windowMs);
  recent.push(now);
  antinukeTracker.set(key, recent);
  return recent.length;
}

async function quarantineUser(guild, member, reason) {
  let quarantineRole = guild.roles.cache.find(r => r.name === 'Quarantena' || r.name === 'Quarantine');
  
  if (!quarantineRole) {
    try {
      quarantineRole = await guild.roles.create({
        name: 'Quarantena',
        color: 0x808080,
        permissions: [],
        reason: 'Ruolo creato automaticamente per l\'Anti-Nuke'
      });
      log.info(`Creato ruolo "Quarantena" in ${guild.name}`);
    } catch (err) {
      log.err('Impossibile creare il ruolo Quarantena', err);
      return false;
    }
  }

  const botMember = guild.members.me;
  if (quarantineRole.position >= botMember.roles.highest.position) {
    log.warn(`Il ruolo "Quarantena" è troppo in alto per essere assegnato in ${guild.name}`);
    return false;
  }

  try {
    const rolesToRemove = member.roles.cache.filter(r => r.id !== guild.id && r.id !== quarantineRole.id);
    await member.roles.remove(rolesToRemove, reason);
    await member.roles.add(quarantineRole, reason);
    log.ok(`Utente ${member.user.tag} messo in quarantena in ${guild.name}`);
    return true;
  } catch (err) {
    log.err(`Errore quarantena per ${member.user.tag}`, err);
    return false;
  }
}

async function checkAntiNuke(guild, auditAction, actionType, threshold) {
  let executorId = null;
  try {
    const logs = await guild.fetchAuditLogs({ limit: 1, type: auditAction });
    const entry = logs.entries.first();
    if (!entry) return;
    if (entry.executor.id === clientRef.user.id) return;
    if (Date.now() - entry.createdTimestamp > 15000) return;
    executorId = entry.executor.id;
  } catch (e) {
    return;
  }

  if (!executorId) return;

  const config = storage.getAntiNukeConfig(guild.id);
  const whitelist = config.whitelist_ids.split(',').map(s => s.trim()).filter(Boolean);
  if (whitelist.includes(executorId)) return;
  if (executorId === guild.ownerId) return; // Il proprietario del server è sempre immune

  const windowMs = config.window_ms || 10000;
  const count = trackAction(guild.id, executorId, actionType, windowMs);

  if (count >= (threshold || 3)) {
    const member = await guild.members.fetch(executorId).catch(() => null);
    if (!member) return;

    const botMember = guild.members.me;
    if (member.roles.highest.position >= botMember.roles.highest.position) {
      log.warn(`Anti-Nuke: impossibile punire ${executorId} (ruolo troppo alto)`);
      return;
    }

    const punishReason = `[ANTI-NUKE] Superata soglia ${actionType} (${count} in ${windowMs}ms)`;
    
    if (config.punishment === 'quarantine') {
      const success = await quarantineUser(guild, member, punishReason);
      if (!success) {
        await member.ban({ reason: punishReason }).catch(() => {});
      }
    } else if (config.punishment === 'ban') {
      await member.ban({ reason: punishReason }).catch(() => {});
    } else if (config.punishment === 'kick') {
      await member.kick(punishReason).catch(() => {});
    }

    antinukeTracker.delete(`${guild.id}-${executorId}-${actionType}`);

    await ModLogModule.logUserAction(guild, {
      type: 'Anti-Nuke',
      title: '🛡️ Anti-Nuke Attivato',
      targetId: executorId,
      target: `${member.user.tag} (${executorId})`,
      moderator: 'Sistema Anti-Nuke',
      reason: `Ha eseguito ${count} azioni di tipo "${actionType}" in ${windowMs}ms (soglia: ${threshold}). Punizione: ${config.punishment}`
    }).catch(() => {});
  }
}

// ==================== MOD LOG ====================
const ModLogModule = {
  async logUserAction(guild, logData = {}) {
    storage.saveLog(logData);
    try {
      if (!guild) return;
      const config = storage.getGuildConfig(guild.id);
      const channelId = config.log_channel_id || MOD_LOG_CHANNEL_ID;
      const ch = guild.channels.cache.get(channelId);
      if (!ch) return;

      const fields = [
        { name: 'Type', value: logData.type || 'N/A', inline: true },
        logData.target && { name: 'Target', value: logData.target, inline: true },
        logData.moderator && { name: 'Moderator', value: logData.moderator, inline: true },
        logData.user && { name: 'User', value: logData.user, inline: true },
        logData.channel && { name: 'Channel', value: logData.channel, inline: true },
        logData.duration && { name: 'Duration', value: logData.duration, inline: true },
        logData.reason && { name: 'Reason', value: logData.reason, inline: false },
        { name: 'Date', value: new Date().toLocaleString('it-IT'), inline: false }
      ].filter(Boolean);

      const embed = EmbedManager.createEmbed({
        title: logData.title || 'Azione Mod',
        color: 0x5865F2,
        fields,
        timestamp: true
      });

      await ch.send({ embeds: [embed] }).catch(err => log.warn(`Log send fallito: ${err.message}`));
    } catch (err) {
      log.err('logUserAction', err);
    }
  }
};

const TICKET_COOLDOWN_MS = 5 * 60 * 1000;
const CLOSE_DELAY_MS = 3000;
const closingTickets = new Set();
const ticketCooldowns = new Map();

async function createTicket(source, user) {
  const guild = source.guild;
  const isSlash = isInteractionSource(source);

  const botMember = guild.members.me;
  if (!botMember.permissions.has(PermissionsBitField.Flags.ManageChannels)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Permessi Insufficienti', 'Il bot non ha il permesso di gestire canali.')],
      ephemeral: true
    }, isSlash);
  }

  const last = ticketCooldowns.get(user.id);
  if (last && Date.now() - last < TICKET_COOLDOWN_MS) {
    const rem = Math.ceil((TICKET_COOLDOWN_MS - (Date.now() - last)) / 60000);
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Cooldown', `Devi attendere ${rem} minuti prima di aprire un altro ticket.`)],
      ephemeral: true
    }, isSlash);
  }

  try {
    const existing = guild.channels.cache.find(c => c.name === `ticket-${user.id}`);
    if (existing) {
      return safeReplySource(source, {
        embeds: [EmbedManager.error('Ticket Esistente', `Hai già un ticket aperto: ${existing}`)],
        ephemeral: true
      }, isSlash);
    }

    const staffRoles = guild.roles.cache.filter(r =>
      ['Staff', 'Admin', 'Senior Admin'].includes(r.name)
    );

    const overwrites = [
      { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
      {
        id: user.id,
        allow: [
          PermissionsBitField.Flags.ViewChannel,
          PermissionsBitField.Flags.SendMessages,
          PermissionsBitField.Flags.ReadMessageHistory,
          PermissionsBitField.Flags.AttachFiles,
          PermissionsBitField.Flags.EmbedLinks
        ]
      }
    ];

    for (const role of staffRoles.values()) {
      overwrites.push({
        id: role.id,
        allow: [
          PermissionsBitField.Flags.ViewChannel,
          PermissionsBitField.Flags.SendMessages,
          PermissionsBitField.Flags.ReadMessageHistory,
          PermissionsBitField.Flags.ManageMessages,
          PermissionsBitField.Flags.AttachFiles,
          PermissionsBitField.Flags.EmbedLinks
        ]
      });
    }

    const channel = await guild.channels.create({
      name: `ticket-${user.id}`,
      type: ChannelType.GuildText,
      permissionOverwrites: overwrites
    });

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('close_ticket').setLabel('Chiudi Ticket').setStyle(ButtonStyle.Danger),
      new ButtonBuilder().setCustomId('claim_ticket').setLabel('Prendi in carico').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId('priority_ticket').setLabel('Imposta Priorità').setStyle(ButtonStyle.Secondary)
    );

    const ticketEmbed = EmbedManager.createEmbed({
      title: 'Ticket Aperto',
      description: `Benvenuto ${user}, questo è il tuo ticket.\n\nDescrivi il tuo problema e un membro dello staff ti assisterà.`,
      color: 0x0099FF,
      fields: [
        { name: 'Utente', value: `${user.username} (${user.id})`, inline: true },
        { name: 'Canale', value: `${channel}`, inline: true }
      ],
      timestamp: true
    });

    await channel.send({ embeds: [ticketEmbed], components: [row] });

    await safeReplySource(source, {
      embeds: [EmbedManager.success('Ticket Creato', `Ticket creato: ${channel}`)],
      ephemeral: true
    }, isSlash);

    await ModLogModule.logUserAction(guild, {
      type: 'Ticket Aperto',
      title: 'Ticket Aperto',
      targetId: user.id,
      target: `${user.username} (${user.id})`,
      user: `${user.username} (${user.id})`,
      channel: channel.name
    });

    ticketCooldowns.set(user.id, Date.now());
  } catch (err) {
    log.err('createTicket', err);
    await safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Errore nella creazione del ticket.')],
      ephemeral: true
    }, isSlash);
  }
}

async function closeTicket(source, user) {
  const channel = source.channel;
  const isSlash = isInteractionSource(source);

  if (!isTicketChannel(channel)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Questo comando può essere usato solo nei ticket.')],
      ephemeral: true
    }, isSlash);
  }

  const ticketUserId = channel.name.replace('ticket-', '');
  const isOwner = user.id === ticketUserId;
  const isStaffOrAdmin = source.member ? hasStaffOrAdmin(source.member) : false;

  if (!isOwner && !isStaffOrAdmin) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', "Solo l'autore del ticket o uno staff possono chiuderlo.")],
      ephemeral: true
    }, isSlash);
  }

  if (closingTickets.has(channel.id)) return;
  closingTickets.add(channel.id);

  try {
    await safeReplySource(source, {
      embeds: [EmbedManager.createEmbed({
        title: 'Ticket in Chiusura',
        description: `Il ticket verrà chiuso tra ${CLOSE_DELAY_MS / 1000} secondi...`,
        color: 0xFF0000,
        timestamp: true
      })],
      ephemeral: true
    }, isSlash);

    await ModLogModule.logUserAction(channel.guild, {
      type: 'Ticket Chiuso',
      title: 'Ticket Chiuso',
      targetId: ticketUserId,
      target: `${user.username} (${user.id})`,
      user: `${user.username} (${user.id})`,
      channel: channel.name
    });

    setTimeout(async () => {
      try {
        const still = channel.guild.channels.cache.get(channel.id);
        if (still && channel.deletable) await channel.delete();
      } catch (err) {
        log.err('delete ticket', err);
      } finally {
        closingTickets.delete(channel.id);
      }
    }, CLOSE_DELAY_MS);
  } catch (err) {
    log.err('closeTicket', err);
    closingTickets.delete(channel.id);
  }
}

// ==================== LOBBY ====================
async function createLobby(interaction) {
  const user = interaction.user;
  const guild = interaction.guild;

  const botMember = guild.members.me;
  if (!botMember.permissions.has(PermissionsBitField.Flags.ManageChannels)) {
    return safeReply(interaction, {
      embeds: [EmbedManager.error('Permessi Insufficienti', 'Il bot non ha il permesso di gestire canali.')],
      ephemeral: true
    });
  }

  const existing = guild.channels.cache.find(
    c => c.name === `lobby-${user.username}` && c.type === ChannelType.GuildCategory
  );
  if (existing) {
    return safeReply(interaction, {
      embeds: [EmbedManager.error('Lobby Esistente', 'Hai già una lobby attiva!')],
      ephemeral: true
    });
  }

  try {
    const category = await guild.channels.create({
      name: `lobby-${user.username}`,
      type: ChannelType.GuildCategory,
      permissionOverwrites: [
        { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
        {
          id: user.id,
          allow: [
            PermissionsBitField.Flags.ViewChannel,
            PermissionsBitField.Flags.SendMessages,
            PermissionsBitField.Flags.ReadMessageHistory,
            PermissionsBitField.Flags.Connect,
            PermissionsBitField.Flags.Speak
          ]
        }
      ]
    });

    const text = await guild.channels.create({
      name: `chat-${user.username}`,
      type: ChannelType.GuildText,
      parent: category.id,
      permissionOverwrites: category.permissionOverwrites.cache
    });

    const voice = await guild.channels.create({
      name: `lobby-${user.username}`,
      type: ChannelType.GuildVoice,
      parent: category.id,
      permissionOverwrites: category.permissionOverwrites.cache
    });

    const embed = EmbedManager.success('Lobby Creata!', `La tua lobby privata è pronta, ${user}!`)
      .addFields(
        { name: 'Categoria', value: category.name, inline: true },
        { name: 'Testuale', value: `${text}`, inline: true },
        { name: 'Vocale', value: `${voice}`, inline: true }
      );

    return safeReply(interaction, { embeds: [embed], ephemeral: true });
  } catch (err) {
    log.err('createLobby', err);
    return safeReply(interaction, {
      embeds: [EmbedManager.error('Errore', 'Errore nella creazione della lobby.')],
      ephemeral: true
    });
  }
}
// ==================== MODLOGS ====================
async function handleModlogs(source, target, isSlash) {
  if (!target) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Utente non valido.')],
      ephemeral: isSlash
    }, isSlash);
  }

  const logs = storage.getLogsForUser(target.id);

  if (!logs.length) {
    return safeReplySource(source, {
      embeds: [EmbedManager.createEmbed({
        title: 'Nessun Log',
        description: `Nessun log trovato per **${target.username}**.`,
        color: 0x808080,
        timestamp: true
      })],
      ephemeral: isSlash
    }, isSlash);
  }

  const PER_PAGE = 5;
  const totalPages = calculatePages(logs.length, PER_PAGE);
  let page = 0;

  const buildEmbed = (p) => {
    const slice = getPaginatedSlice(logs, p, PER_PAGE);
    const fields = slice.map((l, i) => {
      const caseNum = logs.length - (p * PER_PAGE + i);
      return {
        name: `Case ${caseNum} - ${l.type}`,
        value: [
          l.moderator ? `**Moderatore:** ${l.moderator}` : null,
          l.reason ? `**Motivo:** ${l.reason}` : null,
          l.duration ? `**Durata:** ${l.duration}` : null,
          `**Data:** ${formatDate(l.timestamp)}`
        ].filter(Boolean).join('\n'),
        inline: false
      };
    });
    return EmbedManager.createEmbed({
      title: `Modlogs - ${target.username}`,
      color: 0x5865F2,
      fields,
      footer: { text: `Pagina ${p + 1}/${totalPages} | Log totali: ${logs.length}` },
      timestamp: true
    });
  };

  const buildRow = (p) => new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('modlogs_prev').setLabel('◀').setStyle(ButtonStyle.Secondary).setDisabled(p === 0),
    new ButtonBuilder().setCustomId('modlogs_next').setLabel('▶').setStyle(ButtonStyle.Secondary).setDisabled(p === totalPages - 1)
  );

  let msg;
  const data = { embeds: [buildEmbed(0)], components: totalPages > 1 ? [buildRow(0)] : [] };
  if (isSlash) {
    await source.reply({ ...data, ephemeral: false });
    msg = await source.fetchReply();
  } else {
    msg = await source.channel.send(data);
  }

  if (totalPages <= 1) return;

  const authorId = isSlash ? source.user.id : source.author.id;
  const collector = msg.createMessageComponentCollector({ time: 60000 });

  collector.on('collect', async btn => {
    if (btn.user.id !== authorId) {
      return btn.reply({
        embeds: [EmbedManager.error('Non Autorizzato', 'Non puoi usare questi bottoni.')],
        ephemeral: true
      });
    }
    if (btn.customId === 'modlogs_prev') page = Math.max(0, page - 1);
    if (btn.customId === 'modlogs_next') page = Math.min(totalPages - 1, page + 1);
    await btn.update({ embeds: [buildEmbed(page)], components: [buildRow(page)] }).catch(() => {});
  });

  collector.on('end', async () => { try { await msg.edit({ components: [] }); } catch {} });
}

// ==================== BLACKLIST ====================
function isServerAuthorized(guildId) {
  if (BLACKLIST_ADMIN_SERVERS.length === 0) return true;
  return BLACKLIST_ADMIN_SERVERS.includes(guildId);
}

async function handleGuildMemberAdd(member) {
  if (storage.isBlacklisted(member.user.id)) {
    const entry = storage.getBlacklistEntry(member.user.id);
    try {
      await member.send({
        embeds: [EmbedManager.error('Accesso Negato', `Sei nella blacklist globale.\n**Motivo:** ${entry.reason}`)]
      }).catch(() => {});
      await member.kick(`[BLACKLIST GLOBALE] ${entry.reason}`);
      await ModLogModule.logUserAction(member.guild, {
        type: 'Blacklist Kick',
        title: 'Blacklist Kick Automatico',
        targetId: member.user.id,
        target: `${member.user.username} (${member.user.id})`,
        reason: entry.reason,
        moderator: 'Sistema Automatico'
      });
      return;
    } catch (err) {
      log.err('handleGuildMemberAdd blacklist', err);
    }
  }

  try {
    const config = storage.getGuildConfig(member.guild.id);
    if (config.autorole_id) {
      const role = member.guild.roles.cache.get(config.autorole_id);
      if (role) {
        const botMember = member.guild.members.me;
        if (botMember.permissions.has(PermissionsBitField.Flags.ManageRoles) &&
            role.position < botMember.roles.highest.position) {
          await member.roles.add(role, 'Auto-role all\'ingresso');
        }
      }
    }
  } catch (err) {
    log.err('handleGuildMemberAdd autorole', err);
  }
}

async function addBlacklist(source, targetUser, reason, moderator, isSlash) {
  reason = reason || 'Nessun motivo specificato';

  const guildId = source.guild?.id;
  if (guildId && !isServerAuthorized(guildId)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Non Autorizzato', 'Questo server non è autorizzato a gestire la blacklist globale.')],
      ephemeral: isSlash
    }, isSlash);
  }

  if (storage.isBlacklisted(targetUser.id)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Già in Blacklist', `${targetUser.username} è già nella blacklist globale.`)],
      ephemeral: isSlash
    }, isSlash);
  }
  if (targetUser.id === clientRef.user.id) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Non puoi mettere in blacklist il bot.')],
      ephemeral: isSlash
    }, isSlash);
  }
  if (targetUser.id === moderator.id) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Non puoi mettere te stesso in blacklist.')],
      ephemeral: isSlash
    }, isSlash);
  }

  if (isSlash && !source.deferred && !source.replied) {
    await source.deferReply().catch(err => log.err('addBlacklist deferReply', err));
  }

  storage.addToBlacklist(
    targetUser.id, targetUser.username, reason,
    moderator.id, moderator.tag ?? moderator.username
  );

  try {
    await targetUser.send({
      embeds: [EmbedManager.error('Aggiunto alla Blacklist Globale', `Sei stato aggiunto alla blacklist globale.\n**Motivo:** ${reason}`)]
    });
  } catch {}

  const results = await Promise.allSettled(
    clientRef.guilds.cache.map(async (guild) => {
      try {
        const member = await guild.members.fetch(targetUser.id).catch(() => null);
        if (!member) return false;
        await guild.members.ban(targetUser.id, { reason: `[BLACKLIST GLOBALE] ${reason}` });
        await ModLogModule.logUserAction(guild, {
          type: 'Blacklist Ban',
          title: 'Ban Globale (Blacklist)',
          targetId: targetUser.id,
          target: `${targetUser.username} (${targetUser.id})`,
          moderator: `${moderator.username} (${moderator.id})`,
          reason
        });
        return true;
      } catch (err) {
        log.err(`ban ${guild.name}`, err);
        return false;
      }
    })
  );
  const bannedCount = results.filter(r => r.status === 'fulfilled' && r.value === true).length;

  return safeReplySource(source, {
    embeds: [EmbedManager.createEmbed({
      title: 'Blacklist Globale Aggiunta',
      color: 0x8B0000,
      fields: [
        { name: 'Utente', value: `${targetUser.username} (${targetUser.id})`, inline: true },
        { name: 'Moderatore', value: `${moderator.username}`, inline: true },
        { name: 'Server Bannati', value: `${bannedCount}`, inline: true },
        { name: 'Motivo', value: reason, inline: false }
      ],
      timestamp: true
    })],
    ephemeral: false
  }, isSlash);
}

async function removeBlacklist(source, targetUser, moderator, isSlash) {
  if (!storage.isBlacklisted(targetUser.id)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Non in Blacklist', `${targetUser.username} non è nella blacklist globale.`)],
      ephemeral: isSlash
    }, isSlash);
  }

  if (isSlash && !source.deferred && !source.replied) {
    await source.deferReply().catch(err => log.err('removeBlacklist deferReply', err));
  }

  storage.removeFromBlacklist(targetUser.id);

  const results = await Promise.allSettled(
    clientRef.guilds.cache.map(async (guild) => {
      try {
        let ban = null;
        try {
          ban = await guild.bans.fetch(targetUser.id);
        } catch (e) {
          if (e.code !== 10026) throw e;
        }
        if (ban) {
          await guild.members.unban(targetUser.id, `[BLACKLIST RIMOSSA] ${moderator.username}`);
          await ModLogModule.logUserAction(guild, {
            type: 'Blacklist Unban',
            title: 'Unban Globale (Blacklist Rimossa)',
            targetId: targetUser.id,
            target: `${targetUser.username} (${targetUser.id})`,
            moderator: `${moderator.username} (${moderator.id})`,
            reason: 'Blacklist globale rimossa'
          });
          return true;
        }
      } catch (err) {
        log.err(`unban ${guild.name}`, err);
      }
      return false;
    })
  );
  const unbannedCount = results.filter(r => r.status === 'fulfilled' && r.value === true).length;

  try {
    await targetUser.send({
      embeds: [EmbedManager.success('Rimosso dalla Blacklist Globale', 'Sei stato rimosso dalla blacklist globale.')]
    });
  } catch {}

  return safeReplySource(source, {
    embeds: [EmbedManager.createEmbed({
      title: 'Blacklist Globale Rimossa',
      color: 0x00FF00,
      fields: [
        { name: 'Utente', value: `${targetUser.username} (${targetUser.id})`, inline: true },
        { name: 'Moderatore', value: `${moderator.username}`, inline: true },
        { name: 'Server Sbannati', value: `${unbannedCount}`, inline: true }
      ],
      timestamp: true
    })],
    ephemeral: false
  }, isSlash);
}

async function listBlacklist(source, isSlash) {
  const list = storage.getAllBlacklist();
  if (!list.length) {
    return safeReplySource(source, {
      embeds: [EmbedManager.info('Blacklist Globale', 'La blacklist globale è vuota.')],
      ephemeral: isSlash
    }, isSlash);
  }

  const PER_PAGE = 5;
  const totalPages = calculatePages(list.length, PER_PAGE);
  let page = 0;

  const buildEmbed = (p) => {
    const slice = getPaginatedSlice(list, p, PER_PAGE);
    const fields = slice.map((e, i) => ({
      name: `#${p * PER_PAGE + i + 1} — ${e.username}`,
      value: [
        `**ID:** ${e.user_id}`,
        `**Motivo:** ${e.reason}`,
        `**Aggiunto da:** ${e.moderator_tag}`,
        `**Data:** ${formatDate(e.added_at)}`
      ].join('\n'),
      inline: false
    }));
    return EmbedManager.createEmbed({
      title: 'Blacklist Globale',
      color: 0x8B0000,
      fields,
      footer: { text: `Pagina ${p + 1}/${totalPages} | Totale: ${list.length}` },
      timestamp: true
    });
  };

  const buildRow = (p) => new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('bl_prev').setLabel('◀').setStyle(ButtonStyle.Secondary).setDisabled(p === 0),
    new ButtonBuilder().setCustomId('bl_next').setLabel('▶').setStyle(ButtonStyle.Secondary).setDisabled(p === totalPages - 1)
  );

  let msg;
  const data = { embeds: [buildEmbed(0)], components: totalPages > 1 ? [buildRow(0)] : [] };
  if (isSlash) {
    await source.reply({ ...data, ephemeral: false });
    msg = await source.fetchReply();
  } else {
    msg = await source.channel.send(data);
  }

  if (totalPages <= 1) return;

  const authorId = isSlash ? source.user.id : source.author.id;
  const collector = msg.createMessageComponentCollector({ time: 60000 });
  collector.on('collect', async btn => {
    if (btn.user.id !== authorId) {
      return btn.reply({ embeds: [EmbedManager.error('Non Autorizzato', 'Non puoi usare questi bottoni.')], ephemeral: true });
    }
    if (btn.customId === 'bl_prev') page = Math.max(0, page - 1);
    if (btn.customId === 'bl_next') page = Math.min(totalPages - 1, page + 1);
    await btn.update({ embeds: [buildEmbed(page)], components: [buildRow(page)] }).catch(() => {});
  });
  collector.on('end', async () => { try { await msg.edit({ components: [] }); } catch {} });
}

async function checkBlacklist(source, targetUser, isSlash) {
  if (!targetUser) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Utente non valido.')],
      ephemeral: isSlash
    }, isSlash);
  }
  const entry = storage.getBlacklistEntry(targetUser.id);
  if (!entry) {
    return safeReplySource(source, {
      embeds: [EmbedManager.success('Non in Blacklist', `${targetUser.username} NON è nella blacklist globale.`)],
      ephemeral: isSlash
    }, isSlash);
  }
  return safeReplySource(source, {
    embeds: [EmbedManager.createEmbed({
      title: 'Utente in Blacklist',
      color: 0x8B0000,
      fields: [
        { name: 'Utente', value: `${entry.username} (${entry.user_id})`, inline: true },
        { name: 'Motivo', value: entry.reason, inline: false },
        { name: 'Aggiunto da', value: entry.moderator_tag, inline: true },
        { name: 'Data', value: formatDate(entry.added_at), inline: true }
      ],
      timestamp: true
    })],
    ephemeral: isSlash
  }, isSlash);
}

// ==================== STATS ====================
async function showStats(source, isSlash) {
  const s = storage.getStats();
  const typeLines = s.byType.length
    ? s.byType.map(t => `• **${t.type}**: ${t.c}`).join('\n')
    : 'Nessuna azione registrata';

  const embed = EmbedManager.createEmbed({
    title: '📊 Statistiche Bot',
    color: 0x5865F2,
    fields: [
      { name: 'Log Totali', value: `${s.total}`, inline: true },
      { name: 'Blacklist', value: `${s.blacklist}`, inline: true },
      { name: 'Server', value: `${clientRef.guilds.cache.size}`, inline: true },
      { name: 'Azioni per Tipo', value: typeLines, inline: false }
    ],
    timestamp: true
  });
  return safeReplySource(source, { embeds: [embed] }, isSlash);
}

// ==================== PURGE ====================
async function purgeUser(source, targetUser, amount, executor, isSlash) {
  if (!executor.permissions.has(PermissionsBitField.Flags.ManageMessages)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', 'Non hai il permesso "Gestisci Messaggi".')],
      ephemeral: isSlash
    }, isSlash);
  }

  const channel = source.channel;
  const botMember = channel.guild.members.me;
  if (!channel.permissionsFor(botMember).has(PermissionsBitField.Flags.ManageMessages)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Permessi', 'Il bot non può gestire i messaggi qui.')],
      ephemeral: isSlash
    }, isSlash);
  }

  amount = Math.min(Math.max(amount || 100, 1), 100);

  try {
    const messages = await channel.messages.fetch({ limit: 100 });
    const toDelete = messages
      .filter(m => m.author.id === targetUser.id)
      .first(amount);

    if (!toDelete.length) {
      return safeReplySource(source, {
        embeds: [EmbedManager.info('Nessun messaggio', `Nessun messaggio recente di ${targetUser.username} trovato in questo canale.`)],
        ephemeral: isSlash
      }, isSlash);
    }

    const deleted = await channel.bulkDelete(toDelete, true);

    await ModLogModule.logUserAction(channel.guild, {
      type: 'Purge',
      title: 'Purge Messaggi',
      targetId: targetUser.id,
      target: `${targetUser.username} (${targetUser.id})`,
      moderator: `${executor.user ? executor.user.tag : executor.username} (${executor.id})`,
      channel: channel.name,
      reason: `Cancellati ${deleted.size} messaggi`
    });

    return safeReplySource(source, {
      embeds: [EmbedManager.success('Purge Completato', `🧹 Cancellati **${deleted.size}** messaggi di ${targetUser.username} in ${channel}.`)],
      ephemeral: isSlash
    }, isSlash);
  } catch (err) {
    if (err.code === 50034) {
      return safeReplySource(source, {
        embeds: [EmbedManager.error('Errore', 'Non posso cancellare messaggi più vecchi di 14 giorni.')],
        ephemeral: isSlash
      }, isSlash);
    }
    log.err('purgeUser', err);
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Errore durante la cancellazione.')],
      ephemeral: isSlash
    }, isSlash);
  }
}

// ==================== NOTE ====================
async function addNote(source, targetUser, content, author, isSlash) {
  if (!hasStaffOrAdmin(author)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')],
      ephemeral: isSlash
    }, isSlash);
  }
  if (!content || content.trim().length < 2) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Il contenuto della nota è troppo corto.')],
      ephemeral: isSlash
    }, isSlash);
  }
  if (content.length > 1000) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Troppo lunga', 'Max 1000 caratteri.')],
      ephemeral: isSlash
    }, isSlash);
  }

  const guildId = source.guild.id;
  const noteId = storage.addNote(
    guildId, targetUser.id,
    author.id, author.user ? author.user.tag : author.username,
    content.trim()
  );

  await ModLogModule.logUserAction(source.guild, {
    type: 'Nota Aggiunta',
    title: 'Nota Staff',
    targetId: targetUser.id,
    target: `${targetUser.username} (${targetUser.id})`,
    moderator: `${author.user ? author.user.tag : author.username} (${author.id})`,
    reason: content.slice(0, 500)
  });

  return safeReplySource(source, {
    embeds: [EmbedManager.success('Nota Aggiunta', `Nota **#${noteId}** aggiunta per ${targetUser.username}.`)],
    ephemeral: isSlash
  }, isSlash);
}
async function listNotes(source, targetUser, isSlash) {
  const guildId = source.guild.id;
  const notes = storage.getNotesForUser(guildId, targetUser.id);

  if (!notes.length) {
    return safeReplySource(source, {
      embeds: [EmbedManager.info('Nessuna Nota', `Nessuna nota per ${targetUser.username}.`)],
      ephemeral: isSlash
    }, isSlash);
  }

  const PER_PAGE = 5;
  const totalPages = calculatePages(notes.length, PER_PAGE);
  let page = 0;

  const buildEmbed = (p) => {
    const slice = getPaginatedSlice(notes, p, PER_PAGE);
    const fields = slice.map(n => ({
      name: `#${n.id} — ${n.author_tag}`,
      value: `${n.content}\n*${formatDate(n.created_at)}*`,
      inline: false
    }));
    return EmbedManager.createEmbed({
      title: `📝 Note - ${targetUser.username}`,
      color: 0x9B59B6,
      fields,
      footer: { text: `Pagina ${p + 1}/${totalPages} | Totale: ${notes.length}` },
      timestamp: true
    });
  };

  const buildRow = (p) => new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('notes_prev').setLabel('◀').setStyle(ButtonStyle.Secondary).setDisabled(p === 0),
    new ButtonBuilder().setCustomId('notes_next').setLabel('▶').setStyle(ButtonStyle.Secondary).setDisabled(p === totalPages - 1)
  );

  let msg;
  const data = { embeds: [buildEmbed(0)], components: totalPages > 1 ? [buildRow(0)] : [] };
  if (isSlash) {
    await source.reply({ ...data, ephemeral: false });
    msg = await source.fetchReply();
  } else {
    msg = await source.channel.send(data);
  }

  if (totalPages <= 1) return;

  const authorId = isSlash ? source.user.id : source.author.id;
  const collector = msg.createMessageComponentCollector({ time: 60000 });
  collector.on('collect', async btn => {
    if (btn.user.id !== authorId) {
      return btn.reply({ embeds: [EmbedManager.error('Non Autorizzato', 'Non puoi usare questi bottoni.')], ephemeral: true });
    }
    if (btn.customId === 'notes_prev') page = Math.max(0, page - 1);
    if (btn.customId === 'notes_next') page = Math.min(totalPages - 1, page + 1);
    await btn.update({ embeds: [buildEmbed(page)], components: [buildRow(page)] }).catch(() => {});
  });
  collector.on('end', async () => { try { await msg.edit({ components: [] }); } catch {} });
}

async function removeNote(source, noteId, executor, isSlash) {
  if (!isAdmin(executor)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')],
      ephemeral: isSlash
    }, isSlash);
  }
  const guildId = source.guild.id;
  const note = storage.getNote(guildId, noteId);
  if (!note) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Non Trovata', `Nessuna nota con ID #${noteId}.`)],
      ephemeral: isSlash
    }, isSlash);
  }
  storage.deleteNote(guildId, noteId);
  return safeReplySource(source, {
    embeds: [EmbedManager.success('Nota Eliminata', `Nota **#${noteId}** eliminata.`)],
    ephemeral: isSlash
  }, isSlash);
}

// ==================== AUTOROLE ====================
async function setAutorole(source, role, executor, isSlash) {
  if (!isAdmin(executor)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')],
      ephemeral: isSlash
    }, isSlash);
  }

  const botMember = source.guild.members.me;
  if (!botMember.permissions.has(PermissionsBitField.Flags.ManageRoles)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Permessi', 'Il bot non ha il permesso "Gestisci Ruoli".')],
      ephemeral: isSlash
    }, isSlash);
  }
  if (role.position >= botMember.roles.highest.position) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Errore', 'Il ruolo è più alto o uguale al ruolo più alto del bot.')],
      ephemeral: isSlash
    }, isSlash);
  }

  storage.setAutorole(source.guild.id, role.id);
  return safeReplySource(source, {
    embeds: [EmbedManager.success('Autorole Impostato', `I nuovi membri riceveranno automaticamente il ruolo ${role}.`)],
    ephemeral: isSlash
  }, isSlash);
}

async function clearAutorole(source, executor, isSlash) {
  if (!isAdmin(executor)) {
    return safeReplySource(source, {
      embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')],
      ephemeral: isSlash
    }, isSlash);
  }
  storage.clearAutorole(source.guild.id);
  return safeReplySource(source, {
    embeds: [EmbedManager.success('Autorole Rimosso', 'Nessun ruolo verrà più assegnato automaticamente.')],
    ephemeral: isSlash
  }, isSlash);
}

// ==================== HELP ====================
function buildHelpEmbed() {
  return new EmbedBuilder()
    .setTitle('📋 Comandi Disponibili')
    .setDescription('**Slash commands** (consigliati) e **prefissi** `-` o `&`')
    .setColor('#0099ff')
    .addFields(
      { name: '🎫 Ticket', value: '`/ticketpanel` `/ticket` `/close`', inline: true },
      { name: '🛡️ Moderazione', value: '`/warn` `/timeout` `/modlogs` `/kick` `/ban` `/unban` `/clear`', inline: true },
      { name: '🧹 Purge', value: '`/purge`', inline: true },
      { name: '🚫 Blacklist', value: '`/blacklist add|remove|list|check`', inline: true },
      { name: '📝 Note', value: '`/note add|list|remove`', inline: true },
      { name: '⚙️ Config', value: '`/autorole set|clear`\n`/welcome channel|message|toggle|test|disable`', inline: true },
      { name: '👤 Utente', value: '`/userinfo` `/roles` `/stats` `/ping` `/uptime`', inline: true },
      { name: '📨 Inviti & Ruoli', value: '`/invite` `/giverole` `/removerole`', inline: true },
      { name: '🔒 Canali', value: '`/lock` `/unlock`', inline: true },
      { name: '🎮 Lobby', value: '`/dashboard`', inline: true },
      { name: '⏰ Reminder', value: '`/remind`', inline: true },
      { name: '🔧 Custom', value: '`/addcmd` `/delcmd` `/listcmd`', inline: true }
    )
    .setFooter({ text: 'Usa /help per rivedere questo messaggio' });
}

// ==================== COMMAND LOGIC ====================
const CommandLogic = {
  async getUserFromId(guild, userId) {
    try { return await guild.members.fetch(userId); }
    catch { return null; }
  },

  async kick(guild, executor, userId, reason = 'Nessun motivo') {
    if (!executor.permissions.has(PermissionsBitField.Flags.KickMembers))
      return { success: false, message: '❌ Non hai il permesso "Espelli Membri"!' };
    const targetId = extractUserId(userId);
    if (!targetId) return { success: false, message: '❌ ID utente non valido!' };

    const member = await this.getUserFromId(guild, targetId);
    if (!member) return { success: false, message: '❌ Utente non trovato nel server!' };

    const botMember = guild.members.me;
    if (!botMember.permissions.has(PermissionsBitField.Flags.KickMembers))
      return { success: false, message: '❌ Non ho il permesso "Espelli Membri"!' };
    if (member.id === botMember.id)
      return { success: false, message: '❌ Non posso espellere me stesso!' };
    if (member.roles.highest.position >= botMember.roles.highest.position)
      return { success: false, message: '❌ Non posso espellere un utente con ruolo più alto!' };
    if (!outranks(executor, member, guild))
      return { success: false, message: '❌ Non puoi espellere un utente con ruolo uguale o superiore al tuo!' };

    await member.kick(reason);
    await ModLogModule.logUserAction(guild, {
      type: 'Kick', title: 'Kick', targetId,
      target: `${member.user.tag} (${targetId})`,
      moderator: `${actorName(executor)} (${executor.id})`,
      reason
    });
    return { success: true, message: `✅ Utente ${member.user.tag} (${targetId}) è stato espulso. Motivo: ${reason}` };
  },

  async ban(guild, executor, userId, reason = 'Nessun motivo') {
    if (!executor.permissions.has(PermissionsBitField.Flags.BanMembers))
      return { success: false, message: '❌ Non hai il permesso "Banna Membri"!' };
    const targetId = extractUserId(userId);
    if (!targetId) return { success: false, message: '❌ ID utente non valido!' };

    const botMember = guild.members.me;
    if (!botMember.permissions.has(PermissionsBitField.Flags.BanMembers))
      return { success: false, message: '❌ Non ho il permesso "Banna Membri"!' };
    if (targetId === botMember.id)
      return { success: false, message: '❌ Non posso bannare me stesso!' };

    const member = await this.getUserFromId(guild, targetId);
    if (member && !member.bannable)
      return { success: false, message: '❌ Non posso bannare questo utente!' };
    if (member && !outranks(executor, member, guild))
      return { success: false, message: '❌ Non puoi bannare un utente con ruolo uguale o superiore al tuo!' };

    await guild.members.ban(targetId, { reason });
    await ModLogModule.logUserAction(guild, {
      type: 'Ban', title: 'Ban', targetId,
      target: member ? `${member.user.tag} (${targetId})` : targetId,
      moderator: `${actorName(executor)} (${executor.id})`,
      reason
    });
    return { success: true, message: `✅ Utente con ID ${targetId} è stato bannato. Motivo: ${reason}` };
  },

  async unban(guild, executor, userId) {
    if (!executor.permissions.has(PermissionsBitField.Flags.BanMembers))
      return { success: false, message: '❌ Non hai il permesso "Banna Membri"!' };
    const targetId = extractUserId(userId);
    if (!targetId) return { success: false, message: '❌ ID utente non valido!' };

    const botMember = guild.members.me;
    if (!botMember.permissions.has(PermissionsBitField.Flags.BanMembers))
      return { success: false, message: '❌ Non ho il permesso "Banna Membri"!' };

    try {
      const ban = await guild.bans.fetch(targetId);
      if (!ban) return { success: false, message: '❌ Utente non bannato!' };
      await guild.bans.remove(targetId);
      await ModLogModule.logUserAction(guild, {
        type: 'Unban', title: 'Unban', targetId,
        target: `${ban.user.tag} (${targetId})`,
        moderator: `${actorName(executor)} (${executor.id})`
      });
      return { success: true, message: `✅ Utente ${ban.user.tag} (${targetId}) è stato sbannato.` };
    } catch (error) {
      if (error.code === 10026) return { success: false, message: '❌ Utente non trovato o non bannato.' };
      throw error;
    }
  },

  async clear(channel, executor, amount) {
    if (!executor.permissions.has(PermissionsBitField.Flags.ManageMessages))
      return { success: false, message: '❌ Non hai il permesso "Gestisci Messaggi"!' };
    if (amount < 1 || amount > 100)
      return { success: false, message: '❌ Puoi cancellare tra 1 e 100 messaggi' };

    const botMember = channel.guild.members.me;
    if (!channel.permissionsFor(botMember).has(PermissionsBitField.Flags.ManageMessages))
      return { success: false, message: '❌ Non ho il permesso di gestire i messaggi!' };

    try {
      const deleted = await channel.bulkDelete(amount, true);
      await ModLogModule.logUserAction(channel.guild, {
        type: 'Clear', title: 'Clear Messaggi',
        moderator: `${actorName(executor)} (${executor.id})`,
        channel: channel.name,
        reason: `Cancellati ${deleted.size} messaggi`
      });
      return { success: true, message: `🧹 Cancellati ${deleted.size} messaggi` };
    } catch (error) {
      if (error.code === 50034)
        return { success: false, message: '❌ Non posso cancellare messaggi più vecchi di 14 giorni.' };
      throw error;
    }
  },

  async invite(interactionOrMessage, guild, executor, targetUserId, replyMethod) {
    if (!executor.permissions.has(PermissionsBitField.Flags.CreateInstantInvite))
      return replyMethod({ success: false, message: '❌ Non hai il permesso "Crea Invito"!' });

    const userId = extractUserId(targetUserId);
    if (!userId) return replyMethod({ success: false, message: '❌ ID utente non valido!' });

    let targetUser = null;
    try {
      const member = await guild.members.fetch(userId);
      if (member) targetUser = member.user;
    } catch {}

    if (!targetUser && clientRef) {
      try { targetUser = await clientRef.users.fetch(userId); }
      catch (err) { log.err('fetch user invite', err); }
    }
    if (!targetUser) return replyMethod({ success: false, message: '❌ Utente non trovato!' });

    const channel = interactionOrMessage.channel;
    if (!channel || !channel.isTextBased())
      return replyMethod({ success: false, message: '❌ Questo canale non supporta inviti.' });

    const botMember = guild.members.me;
    if (!channel.permissionsFor(botMember).has(PermissionsBitField.Flags.CreateInstantInvite))
      return replyMethod({ success: false, message: `❌ Non ho il permesso di creare inviti in ${channel}.` });

    try {
      const invite = await channel.createInvite({
        maxUses: 1,
        maxAge: 3600,
        unique: true,
        reason: `Invite da ${executor.user ? executor.user.tag : executor.username} per ${targetUser.username}`
      });
      const executorName = executor.user ? executor.user.tag : executor.username;
      const dmMessage = `${executorName} ti ha inviato un invito per il server **${guild.name}**\n${invite.url}\nValido per 1 utilizzo, scade tra 60 minuti.`;
      try {
        await targetUser.send(dmMessage);
        return replyMethod({ success: true, message: `✅ Invito inviato a ${targetUser.username}!` });
      } catch {
        await channel.send(`${targetUser}\n${executorName} ti ha inviato un invito per il server ${guild.name}\n${invite.url}\nValido per 1 utilizzo, scade tra 60 minuti.`);
        return replyMethod({ success: true, message: `⚠️ DM chiusi, invito postato in ${channel}` });
      }
    } catch (error) {
      log.err('createInvite', error);
      return replyMethod({ success: false, message: "❌ Errore durante la creazione dell'invito." });
    }
  },

  async addRole(guild, executor, targetUserId, roleId) {
    if (!executor.permissions.has(PermissionsBitField.Flags.ManageRoles))
      return { success: false, message: '❌ Non hai il permesso "Gestisci Ruoli"!' };

    const targetId = extractUserId(targetUserId);
    const roleIdMatch = extractRoleId(roleId);
    if (!targetId) return { success: false, message: '❌ ID utente non valido!' };
    if (!roleIdMatch) return { success: false, message: '❌ ID ruolo non valido!' };

    const member = await this.getUserFromId(guild, targetId);
    if (!member) return { success: false, message: '❌ Utente non trovato nel server!' };
    const role = guild.roles.cache.get(roleIdMatch);
    if (!role) return { success: false, message: '❌ Ruolo non trovato!' };

    const botMember = guild.members.me;
    if (!botMember.permissions.has(PermissionsBitField.Flags.ManageRoles))
      return { success: false, message: '❌ Non ho il permesso "Gestisci Ruoli"!' };
    if (role.position >= botMember.roles.highest.position)
      return { success: false, message: '❌ Non posso assegnare un ruolo più alto o uguale al mio!' };
    if (guild.ownerId !== executor.id && role.position >= executor.roles.highest.position)
      return { success: false, message: '❌ Non puoi assegnare un ruolo più alto o uguale al tuo!' };
    if (member.roles.cache.has(roleIdMatch))
      return { success: false, message: `❌ L'utente ha già il ruolo ${role.name}!` };

    await member.roles.add(role);
    return { success: true, message: `✅ Ruolo **${role.name}** assegnato a ${member.user.tag}!` };
  },

  async removeRole(guild, executor, targetUserId, roleId) {
    if (!executor.permissions.has(PermissionsBitField.Flags.ManageRoles))
      return { success: false, message: '❌ Non hai il permesso "Gestisci Ruoli"!' };

    const targetId = extractUserId(targetUserId);
    const roleIdMatch = extractRoleId(roleId);
    if (!targetId) return { success: false, message: '❌ ID utente non valido!' };
    if (!roleIdMatch) return { success: false, message: '❌ ID ruolo non valido!' };

    const member = await this.getUserFromId(guild, targetId);
    if (!member) return { success: false, message: '❌ Utente non trovato nel server!' };
    const role = guild.roles.cache.get(roleIdMatch);
    if (!role) return { success: false, message: '❌ Ruolo non trovato!' };

    const botMember = guild.members.me;
    if (!botMember.permissions.has(PermissionsBitField.Flags.ManageRoles))
      return { success: false, message: '❌ Non ho il permesso "Gestisci Ruoli"!' };
    if (role.position >= botMember.roles.highest.position)
      return { success: false, message: '❌ Non posso rimuovere un ruolo più alto o uguale al mio!' };
    if (guild.ownerId !== executor.id && role.position >= executor.roles.highest.position)
      return { success: false, message: '❌ Non puoi rimuovere un ruolo più alto o uguale al tuo!' };
    if (!member.roles.cache.has(roleIdMatch))
      return { success: false, message: `❌ L'utente non ha il ruolo ${role.name}!` };

    await member.roles.remove(role);
    return { success: true, message: `✅ Ruolo **${role.name}** rimosso da ${member.user.tag}!` };
  },

  async listRoles(guild) {
    const roles = guild.roles.cache
      .filter(r => r.name !== '@everyone')
      .sort((a, b) => b.position - a.position)
      .map(r => `**${r.name}** (ID: \`${r.id}\`) - ${r.members.size} membri`);
    if (!roles.length) return { success: false, message: '❌ Nessun ruolo trovato!' };

    let text = `**📋 Lista Ruoli (${roles.length})**\n\n${roles.join('\n')}`;
    if (text.length > 2000) {
      text = `**📋 Lista Ruoli (${roles.length})**\n\n${roles.slice(0, 20).join('\n')}\n\n*...e altri ${roles.length - 20} ruoli*`;
    }
    return { success: true, message: text };
  },

  async lockChannel(channel, executor, reason = 'Nessun motivo') {
    if (!executor.permissions.has(PermissionsBitField.Flags.ManageChannels))
      return { success: false, message: '❌ Non hai il permesso "Gestisci Canali"!' };

    const botMember = channel.guild.members.me;
    if (!channel.permissionsFor(botMember).has(PermissionsBitField.Flags.ManageChannels))
      return { success: false, message: '❌ Non ho il permesso di gestire questo canale!' };

    const everyone = channel.guild.roles.everyone;
    const current = channel.permissionOverwrites.cache.get(everyone.id);
    if (current && current.deny.has(PermissionsBitField.Flags.SendMessages))
      return { success: false, message: '❌ Questo canale è già bloccato!' };

    await channel.permissionOverwrites.edit(everyone, { SendMessages: false });
    const name = executor.user ? executor.user.tag : executor.username;
    await ModLogModule.logUserAction(channel.guild, {
      type: 'Lock', title: 'Canale Bloccato',
      moderator: `${name} (${executor.id})`,
      channel: channel.name,
      reason
    });
    return { success: true, message: `🔒 Canale bloccato! Motivo: ${reason} - Da: ${name}` };
  },

  async unlockChannel(channel, executor) {
    if (!executor.permissions.has(PermissionsBitField.Flags.ManageChannels))
      return { success: false, message: '❌ Non hai il permesso "Gestisci Canali"!' };

    const botMember = channel.guild.members.me;
    if (!channel.permissionsFor(botMember).has(PermissionsBitField.Flags.ManageChannels))
      return { success: false, message: '❌ Non ho il permesso di gestire questo canale!' };

    const everyone = channel.guild.roles.everyone;
    const current = channel.permissionOverwrites.cache.get(everyone.id);
    if (!current || !current.deny.has(PermissionsBitField.Flags.SendMessages))
      return { success: false, message: '❌ Questo canale non è bloccato!' };

    await channel.permissionOverwrites.delete(everyone);
    const name = executor.user ? executor.user.tag : executor.username;
    await ModLogModule.logUserAction(channel.guild, {
      type: 'Unlock', title: 'Canale Sbloccato',
      moderator: `${name} (${executor.id})`,
      channel: channel.name
    });
    return { success: true, message: `🔓 Canale sbloccato! Da: ${name}` };
  }
};

// ==================== SLASH COMMANDS ====================
const slashCommands = [
  new SlashCommandBuilder().setName('help').setDescription('Mostra la lista dei comandi'),
  new SlashCommandBuilder().setName('stats').setDescription('Mostra le statistiche del bot'),
  new SlashCommandBuilder().setName('ping').setDescription('Mostra la latenza del bot'),
  new SlashCommandBuilder().setName('uptime').setDescription('Mostra da quanto tempo il bot è online'),

  new SlashCommandBuilder().setName('ticketpanel').setDescription('Crea il pannello ticket'),
  new SlashCommandBuilder().setName('ticket').setDescription('Apre un ticket'),
  new SlashCommandBuilder().setName('close').setDescription('Chiude il ticket corrente'),

  new SlashCommandBuilder().setName('userinfo').setDescription('Mostra info utente')
    .addUserOption(o => o.setName('utente').setDescription('Utente')),
  new SlashCommandBuilder().setName('roles').setDescription('Lista ruoli del server'),

  new SlashCommandBuilder().setName('warn').setDescription('Warna un utente')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addStringOption(o => o.setName('motivo').setDescription('Motivo')),
  new SlashCommandBuilder().setName('timeout').setDescription('Timeout utente')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addIntegerOption(o => o.setName('secondi').setDescription('Durata in secondi (1-2419200)').setRequired(true))
    .addStringOption(o => o.setName('motivo').setDescription('Motivo')),
  new SlashCommandBuilder().setName('kick').setDescription('Espelle un utente')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addStringOption(o => o.setName('motivo').setDescription('Motivo')),
  new SlashCommandBuilder().setName('ban').setDescription('Banna un utente')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addStringOption(o => o.setName('motivo').setDescription('Motivo')),
  new SlashCommandBuilder().setName('unban').setDescription('Sbanna un utente tramite ID')
    .addStringOption(o => o.setName('id').setDescription('ID utente').setRequired(true)),
  new SlashCommandBuilder().setName('clear').setDescription('Cancella messaggi (1-100)')
    .addIntegerOption(o => o.setName('quantita').setDescription('Numero messaggi').setRequired(true)),
  new SlashCommandBuilder().setName('purge').setDescription('Cancella i messaggi di un utente nel canale')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addIntegerOption(o => o.setName('quantita').setDescription('Numero max messaggi (1-100, default 100)')),
  new SlashCommandBuilder().setName('modlogs').setDescription('Mostra log moderazione')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true)),

  new SlashCommandBuilder().setName('blacklist').setDescription('Gestione blacklist globale')
    .addSubcommand(s => s.setName('add').setDescription('Aggiungi alla blacklist')
      .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
      .addStringOption(o => o.setName('motivo').setDescription('Motivo')))
    .addSubcommand(s => s.setName('remove').setDescription('Rimuovi dalla blacklist')
      .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true)))
    .addSubcommand(s => s.setName('list').setDescription('Mostra la lista'))
    .addSubcommand(s => s.setName('check').setDescription('Controlla un utente')
      .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))),

  new SlashCommandBuilder().setName('note').setDescription('Gestione note staff')
    .addSubcommand(s => s.setName('add').setDescription('Aggiungi una nota')
      .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
      .addStringOption(o => o.setName('testo').setDescription('Contenuto nota').setRequired(true)))
    .addSubcommand(s => s.setName('list').setDescription('Lista note di un utente')
      .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true)))
    .addSubcommand(s => s.setName('remove').setDescription('Rimuovi una nota')
      .addIntegerOption(o => o.setName('id').setDescription('ID nota').setRequired(true))),

  new SlashCommandBuilder().setName('autorole').setDescription('Configura il ruolo automatico')
    .addSubcommand(s => s.setName('set').setDescription('Imposta il ruolo automatico')
      .addRoleOption(o => o.setName('ruolo').setDescription('Ruolo').setRequired(true)))
    .addSubcommand(s => s.setName('clear').setDescription('Rimuovi il ruolo automatico')),

  new SlashCommandBuilder().setName('addcmd').setDescription('Aggiunge comando custom')
    .addStringOption(o => o.setName('nome').setDescription('Nome').setRequired(true))
    .addStringOption(o => o.setName('risposta').setDescription('Risposta').setRequired(true)),
  new SlashCommandBuilder().setName('delcmd').setDescription('Elimina comando custom')
    .addStringOption(o => o.setName('nome').setDescription('Nome').setRequired(true)),
  new SlashCommandBuilder().setName('listcmd').setDescription('Mostra la lista dei comandi custom'),

  new SlashCommandBuilder().setName('remind').setDescription('Imposta un reminder')
    .addStringOption(o => o.setName('tempo').setDescription('Es: 10m, 1h, 2d, 30s').setRequired(true))
    .addStringOption(o => o.setName('testo').setDescription('Cosa ricordare').setRequired(true)),

  new SlashCommandBuilder().setName('dashboard').setDescription('Mostra dashboard (crea lobby)'),

  new SlashCommandBuilder().setName('invite').setDescription('Invia un invito (1 uso, 60 min)')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true)),
  new SlashCommandBuilder().setName('giverole').setDescription('Assegna un ruolo')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addRoleOption(o => o.setName('ruolo').setDescription('Ruolo').setRequired(true)),
  new SlashCommandBuilder().setName('removerole').setDescription('Rimuove un ruolo')
    .addUserOption(o => o.setName('utente').setDescription('Utente').setRequired(true))
    .addRoleOption(o => o.setName('ruolo').setDescription('Ruolo').setRequired(true)),

  new SlashCommandBuilder().setName('lock').setDescription('Blocca il canale')
    .addStringOption(o => o.setName('motivo').setDescription('Motivo')),
  new SlashCommandBuilder().setName('unlock').setDescription('Sblocca il canale')
];

// ==================== REGISTRAZIONE COMANDI ====================
async function registerSlashCommands(clientId, token) {
  const rest = new REST({ version: '10', timeout: 30000 }).setToken(token);
  rest.on('rateLimited', (info) =>
    log.warn(`Rate limit Discord: ${info.method} ${info.route}, riprovo tra ${Math.ceil(info.timeToReset / 1000)}s`));

  log.info(`Preparazione registrazione ${slashCommands.length} comandi...`);

  const validCommands = [];
  for (const cmd of slashCommands) {
    try {
      const json = cmd.toJSON();
      validCommands.push(json);
    } catch (err) {
      log.err(`❌ Comando "/${cmd.name}" non valido: ${err.message}`);
    }
  }

  try {
    if (GUILD_ID) {
      await rest.put(Routes.applicationCommands(clientId), { body: [] }).catch(err =>
        log.warn(`Cancellazione globali fallita: ${err.message}`));

      log.info(`Registrazione ISTANTANEA sul server ${GUILD_ID}...`);
      await rest.put(Routes.applicationGuildCommands(clientId, GUILD_ID), { body: validCommands });
      log.ok(`✅ ${validCommands.length} comandi registrati ISTANTANEAMENTE su guild ${GUILD_ID}`);
    } else {
      log.info('Registrazione globale (può richiedere fino a 1 ora)...');
      await rest.put(Routes.applicationCommands(clientId), { body: validCommands });
      log.ok(`✅ ${validCommands.length} comandi registrati globalmente`);
    }
  } catch (err) {
    log.err('Registrazione fallita', err);
    if (err.rawError) {
      console.error('\n=== DETTAGLI ERRORE DISCORD ===');
      console.error(JSON.stringify(err.rawError, null, 2));
      console.error('=== FINE DETTAGLI ===\n');
    }
  }
}
// ==================== CLIENT ====================
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildVoiceStates
  ],
  partials: [Partials.Channel, Partials.Message, Partials.User, Partials.GuildMember]
});
clientRef = client;

// ==================== ANTI-NUKE EVENTI ====================
client.on(Events.ChannelDelete, async (channel) => {
  if (!channel.guild) return;
  const config = storage.getAntiNukeConfig(channel.guild.id);
  await checkAntiNuke(channel.guild, AuditLogEvent.ChannelDelete, 'channel', config.threshold_channel);
});

client.on(Events.GuildRoleDelete, async (role) => {
  if (!role.guild) return;
  const config = storage.getAntiNukeConfig(role.guild.id);
  await checkAntiNuke(role.guild, AuditLogEvent.RoleDelete, 'role', config.threshold_role);
});

client.on(Events.GuildBanAdd, async (ban) => {
  const config = storage.getAntiNukeConfig(ban.guild.id);
  await checkAntiNuke(ban.guild, AuditLogEvent.MemberBanAdd, 'ban', config.threshold_ban);
});

// ==================== REMINDER SCHEDULER ====================
setInterval(async () => {
  try {
    const due = storage.getDueReminders(new Date());
    for (const r of due) {
      try {
        const guild = client.guilds.cache.get(r.guild_id);
        if (!guild) {
          storage.deleteReminder(r.id);
          continue;
        }
        const channel = guild.channels.cache.get(r.channel_id);
        if (!channel) {
          storage.deleteReminder(r.id);
          continue;
        }
        await channel.send({
          content: `<@${r.user_id}> ⏰ **Reminder:** ${r.content}`,
          allowedMentions: { users: [r.user_id], roles: [] }
        }).catch(err => log.warn(`Reminder send fallito: ${err.message}`));
        storage.deleteReminder(r.id);
      } catch (err) {
        log.err('reminder loop', err);
        storage.deleteReminder(r.id);
      }
    }
  } catch (err) {
    log.err('reminder scheduler', err);
  }
}, 30 * 1000).unref?.();

// ==================== PREFIX COMMANDS ====================
async function handlePrefixCommand(message) {
  if (message.author.bot) return;
  if (!message.guild) return;

  const prefixes = ['-', '&'];
  const used = prefixes.find(p => message.content.startsWith(p));
  if (!used) return;

  const args = message.content.slice(used.length).trim().split(/ +/);
  const commandName = args.shift()?.toLowerCase();
  if (!commandName) return;

  const { guild, channel, member } = message;

  const custom = storage.getCommand(commandName);
  if (custom) {
    if (channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.ManageMessages)) {
      await message.delete().catch(err => {
        log.warn(`Impossibile cancellare messaggio custom command: ${err.message}`);
      });
    }

    return channel.send({
      content: custom,
      allowedMentions: {
        parse: ['users', 'everyone'],
        repliedUser: false
      }
    }).catch(err => log.err('custom command send', err));
  }

  const cd = checkCooldown(member.id, commandName);
  if (cd.onCooldown) {
    return message.reply({ content: `⏳ Aspetta ${cd.remaining}s prima di riusare questo comando.`, allowedMentions: { repliedUser: false } });
  }

  const replyMethod = async (r) => {
    if (!r || !r.message) return;
    const embed = buildResultEmbed(r, r.title || 'Risultato');
    return message.reply({ embeds: [embed], allowedMentions: { repliedUser: false } });
  };

  try {
    switch (commandName) {
      case 'help':
        return channel.send({ embeds: [buildHelpEmbed()] });

      case 'stats': {
        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        return showStats(message, false);
      }

      case 'ping': {
        const latency = Date.now() - message.createdTimestamp;
        const apiLatency = Math.round(client.ws.ping);
        return channel.send({
          embeds: [EmbedManager.info('🏓 Pong!',
            `**Latenza Bot:** ${latency}ms\n**Latenza API:** ${apiLatency}ms`
          )]
        });
      }

      case 'uptime': {
        const uptimeMs = Date.now() - botStartTime;
        const seconds = Math.floor(uptimeMs / 1000);
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        const parts = [];
        if (days > 0) parts.push(`${days}g`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        parts.push(`${secs}s`);

        return channel.send({
          embeds: [EmbedManager.info('⏱️ Uptime',
            `Il bot è online da: **${parts.join(' ')}**`
          )]
        });
      }

      case 'kick': {
        if (!args[0]) return message.reply('❌ Uso: `-kick <id o @utente> [motivo]`');
        const r = await CommandLogic.kick(guild, member, args[0], args.slice(1).join(' ') || 'Nessun motivo');
        return replyMethod({ ...r, title: 'Kick' });
      }
      case 'ban': {
        if (!args[0]) return message.reply('❌ Uso: `-ban <id o @utente> [motivo]`');
        const r = await CommandLogic.ban(guild, member, args[0], args.slice(1).join(' ') || 'Nessun motivo');
        return replyMethod({ ...r, title: 'Ban' });
      }
      case 'unban': {
        if (!args[0]) return message.reply('❌ Uso: `-unban <id o @utente>`');
        const r = await CommandLogic.unban(guild, member, args[0]);
        return replyMethod({ ...r, title: 'Unban' });
      }
      case 'clear': {
        const amount = parseInt(args[0]);
        if (isNaN(amount)) return message.reply('❌ Uso: `-clear <1-100>`');
        const r = await CommandLogic.clear(channel, member, amount);
        return replyMethod({ ...r, title: 'Clear' });
      }
      case 'purge': {
        if (!args[0]) return message.reply('❌ Uso: `-purge <@utente o ID> [quantità]`');
        const id = extractUserId(args[0]);
        if (!id) return message.reply('❌ ID utente non valido!');
        let target;
        try { target = await client.users.fetch(id); } catch { return message.reply('❌ Utente non trovato.'); }
        const amount = parseInt(args[1]) || 100;
        return purgeUser(message, target, amount, member, false);
      }
      case 'invite': {
        if (!args[0]) return message.reply('❌ Uso: `-invite <id o @utente>`');
        return CommandLogic.invite(message, guild, member, args[0], async (r) => {
          return message.reply({ embeds: [buildResultEmbed(r, 'Invito')], allowedMentions: { repliedUser: false } });
        });
      }
      case 'giverole': {
        if (!args[0] || !args[1]) return message.reply('❌ Uso: `-giverole <user> <role>`');
        const r = await CommandLogic.addRole(guild, member, args[0], args[1]);
        return replyMethod({ ...r, title: 'Give Role' });
      }
      case 'removerole': {
        if (!args[0] || !args[1]) return message.reply('❌ Uso: `-removerole <user> <role>`');
        const r = await CommandLogic.removeRole(guild, member, args[0], args[1]);
        return replyMethod({ ...r, title: 'Remove Role' });
      }
      case 'roles': {
        const r = await CommandLogic.listRoles(guild);
        return channel.send({ embeds: [buildResultEmbed({ ...r, title: 'Lista Ruoli' })] });
      }
      case 'lock': {
        const r = await CommandLogic.lockChannel(channel, member, args.join(' ') || 'Nessun motivo');
        return replyMethod({ ...r, title: 'Canale Bloccato' });
      }
      case 'unlock': {
        const r = await CommandLogic.unlockChannel(channel, member);
        return replyMethod({ ...r, title: 'Canale Sbloccato' });
      }

      case 'addcmd': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
        const name = args.shift()?.toLowerCase();
        const resp = args.join(' ');
        if (!name || !resp) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-addcmd <nome> <risposta>`')] });
        if (resp.length > 4096) return message.reply({ embeds: [EmbedManager.error('Troppo lungo', 'Max 4096 caratteri.')] });
        storage.saveCommand(name, resp);
        return message.reply({ embeds: [EmbedManager.success('Comando Aggiunto', `"${name}" salvato.`)] });
      }
      case 'delcmd': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
        const name = args.shift()?.toLowerCase();
        if (!storage.deleteCommand(name))
          return message.reply({ embeds: [EmbedManager.error('Non Trovato', `"${name}" non esiste.`)] });
        return message.reply({ embeds: [EmbedManager.success('Comando Eliminato', `"${name}" rimosso.`)] });
      }
      case 'listcmd':
      case 'cmds': {
        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });

        const cmds = storage.loadCommands();
        const names = Object.keys(cmds);

        if (!names.length) {
          return message.reply({ embeds: [EmbedManager.info('Comandi Custom', 'Nessun comando custom salvato.')] });
        }

        const list = names.sort().slice(0, 50).map(n => `\`-${n}\``).join(', ');
        const extra = names.length > 50 ? `\n\n*...e altri ${names.length - 50} comandi*` : '';

        return message.reply({
          embeds: [EmbedManager.info(
            `Comandi Custom (${names.length})`,
            `${list}${extra}`
          )]
        });
      }

      case 'remind':
      case 'reminder': {
        const timeArg = args[0];
        const content = args.slice(1).join(' ');

        if (!timeArg || !content) {
          return message.reply('❌ Uso: `-remind <tempo> <testo>`\nEsempi: `10m`, `1h`, `2d`, `30s`');
        }

        const ms = parseDuration(timeArg);
        if (!ms) {
          return message.reply('❌ Formato tempo non valido. Usa `10m`, `1h`, `2d`, `30s`.');
        }
        if (ms < 5000) {
          return message.reply('❌ Il tempo minimo è 5 secondi.');
        }
        if (ms > 30 * 24 * 60 * 60 * 1000) {
          return message.reply('❌ Il tempo massimo è 30 giorni.');
        }
        if (content.length > 500) {
          return message.reply('❌ Il testo è troppo lungo (max 500 caratteri).');
        }

        const remindAt = new Date(Date.now() + ms);
        const id = storage.addReminder(member.id, guild.id, channel.id, content, remindAt);

        return message.reply({
          embeds: [EmbedManager.success('Reminder Impostato', `Ti ricorderò **${content}** <t:${Math.floor(remindAt.getTime() / 1000)}:R> (ID: #${id})`)]
        });
      }

      case 'ticketpanel': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('create_ticket').setLabel('Apri Ticket').setStyle(ButtonStyle.Primary)
        );
        return channel.send({
          embeds: [EmbedManager.info('Pannello Ticket', 'Premi il bottone qui sotto per aprire un ticket.')],
          components: [row]
        });
      }
      case 'ticket': return createTicket(message, message.author);
      case 'close': return closeTicket(message, message.author);

      case 'userinfo': {
        let user = message.mentions.users.first();
        const uid = args[0];
        if (!user && uid) {
          const id = extractUserId(uid);
          if (id) { try { user = await client.users.fetch(id); } catch {} }
        }
        if (!user) user = message.author;
        const m = await guild.members.fetch(user.id).catch(() => null);
        return channel.send({
          embeds: [EmbedManager.info(`Info ${user.username}`, `Info su ${user}`)
            .setThumbnail(user.displayAvatarURL({ dynamic: true }))
            .addFields(
              { name: 'ID', value: user.id, inline: true },
              { name: 'Bot', value: user.bot ? 'Sì' : 'No', inline: true },
              { name: 'Creato il', value: formatDate(user.createdAt), inline: true },
              { name: 'Entrato il', value: m ? formatDate(m.joinedAt) : 'N/A', inline: true },
              { name: 'Ruoli', value: getRoles(m, guild), inline: false }
            )]
        });
      }
      case 'warn': {
        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        let target = message.mentions.users.first();
        if (!target && args[0]) {
          const id = extractUserId(args[0]);
          if (id) { try { target = await client.users.fetch(id); } catch {} }
        }
        if (!target) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-warn <@utente o ID> [motivo]`')] });
        const m = await guild.members.fetch(target.id).catch(() => null);
        if (!m) return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non nel server.')] });
        if (target.id === message.author.id) return message.reply({ embeds: [EmbedManager.error('Errore', 'Non puoi warnare te stesso.')] });
        if (m.permissions.has(PermissionsBitField.Flags.Administrator)) return message.reply({ embeds: [EmbedManager.error('Errore', 'Non puoi warnare un admin.')] });
        const reason = args.slice(1).join(' ') || 'Nessun motivo specificato';
        await ModLogModule.logUserAction(guild, {
          type: 'Warn', title: 'Warn', targetId: target.id,
          target: `${target.username} (${target.id})`,
          moderator: `${message.author.username} (${message.author.id})`, reason
        });
        return channel.send({
          embeds: [EmbedManager.warning('Warn', 'Utente warnato').addFields(
            { name: 'Utente', value: `${target.username} (${target.id})`, inline: true },
            { name: 'Moderatore', value: message.author.username, inline: true },
            { name: 'Motivo', value: reason, inline: false }
          )]
        });
      }
      case 'timeout': {
        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        let target = message.mentions.users.first();
        if (!target && args[0]) {
          const id = extractUserId(args[0]);
          if (id) { try { target = await client.users.fetch(id); } catch {} }
        }
        const seconds = parseInt(args[1]);
        if (!target || isNaN(seconds))
          return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-timeout <@utente o ID> <secondi> [motivo]`')] });
        if (seconds < 1 || seconds > 2419200)
          return message.reply({ embeds: [EmbedManager.error('Durata non valida', 'Secondi tra 1 e 2419200 (28 giorni).')] });
        const m = await guild.members.fetch(target.id).catch(() => null);
        if (!m) return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non nel server.')] });
        if (target.id === message.author.id) return message.reply({ embeds: [EmbedManager.error('Errore', 'Non puoi timeout te stesso.')] });
        if (m.permissions.has(PermissionsBitField.Flags.Administrator)) return message.reply({ embeds: [EmbedManager.error('Errore', 'Non puoi timeout un admin.')] });
        const bot = guild.members.me;
        if (!bot.permissions.has(PermissionsBitField.Flags.ModerateMembers))
          return message.reply({ embeds: [EmbedManager.error('Permessi', 'Manca "Modera Membri".')] });
        if (!m.moderatable)
          return message.reply({ embeds: [EmbedManager.error('Errore', 'Non posso timeout questo utente.')] });
        if (!outranks(member, m, guild))
          return message.reply({ embeds: [EmbedManager.error('Errore', 'Non puoi timeout un utente con ruolo uguale o superiore al tuo.')] });
        const reason = args.slice(2).join(' ') || 'Nessun motivo specificato';
        try { await m.timeout(seconds * 1000, reason); }
        catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Non posso timeout questo utente.')] }); }
        const durata = formatDuration(seconds);
        await ModLogModule.logUserAction(guild, {
          type: 'Timeout', title: 'Timeout', targetId: target.id,
          target: `${target.username} (${target.id})`,
          moderator: `${message.author.username} (${message.author.id})`, reason, duration: durata
        });
        return channel.send({
          embeds: [EmbedManager.createEmbed({
            title: '⏱️ Timeout',
            color: 0xFFA500,
            fields: [
              { name: 'Utente', value: `${target.username} (${target.id})`, inline: true },
              { name: 'Moderatore', value: message.author.username, inline: true },
              { name: 'Durata', value: durata, inline: true },
              { name: 'Motivo', value: reason, inline: false }
            ],
            timestamp: true
          })]
        });
      }
      case 'modlogs':
      case 'md': {
        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-modlogs <id o @utente>`')] });
        const id = extractUserId(args[0]);
        if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
        let target;
        try { target = await client.users.fetch(id); }
        catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
        return handleModlogs(message, target, false);
      }
      case 'dashboard': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('create_lobby').setLabel('Crea Lobby').setStyle(ButtonStyle.Primary)
        );
        return channel.send({
          embeds: [EmbedManager.info('Crea Lobby', 'Clicca per creare una lobby privata.')],
          components: [row]
        });
      }
      case 'bl':
      case 'blacklist': {
        const sub = args.shift()?.toLowerCase();

        if (sub === 'list') {
          if (!hasStaffOrAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
          return listBlacklist(message, false);
        }
        if (sub === 'check' || sub === 'info') {
          if (!hasStaffOrAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-bl check <id o @utente>`')] });
          const id = extractUserId(args[0]);
          if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          let target;
          try { target = await client.users.fetch(id); }
          catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
          return checkBlacklist(message, target, false);
        }

        if (sub === 'add') {
          if (!isAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-bl add <id o @utente> [motivo]`')] });
          const id = extractUserId(args[0]);
          if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          let target;
          try { target = await client.users.fetch(id); }
          catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
          return addBlacklist(message, target, args.slice(1).join(' ') || 'Nessun motivo specificato', message.author, false);
        }
        if (sub === 'remove' || sub === 'rm') {
          if (!isAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-bl remove <id o @utente>`')] });
          const id = extractUserId(args[0]);
          if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          let target;
          try { target = await client.users.fetch(id); }
          catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
          return removeBlacklist(message, target, message.author, false);
        }

        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        return message.reply({
          embeds: [EmbedManager.info('Blacklist', [
            '`-bl add <id o @utente> [motivo]` (Admin)',
            '`-bl remove <id o @utente>` (Admin)',
            '`-bl list` (Staff)',
            '`-bl check <id o @utente>` (Staff)'
          ].join('\n'))]
        });
      }

      case 'note':
      case 'notes': {
        const sub = args.shift()?.toLowerCase();

        if (sub === 'add') {
          if (!hasStaffOrAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-note add <@utente o ID> <testo>`')] });
          const id = extractUserId(args[0]);
          if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          let target;
          try { target = await client.users.fetch(id); }
          catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
          const content = args.slice(1).join(' ');
          return addNote(message, target, content, member, false);
        }
        if (sub === 'list') {
          if (!hasStaffOrAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-note list <@utente o ID>`')] });
          const id = extractUserId(args[0]);
          if (!id) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          let target;
          try { target = await client.users.fetch(id); }
          catch { return message.reply({ embeds: [EmbedManager.error('Errore', 'Utente non trovato.')] }); }
          return listNotes(message, target, false);
        }
        if (sub === 'remove' || sub === 'rm') {
          if (!isAdmin(member))
            return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
          const noteId = parseInt(args[0]);
          if (isNaN(noteId)) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-note remove <id_nota>`')] });
          return removeNote(message, noteId, member, false);
        }

        if (!hasStaffOrAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')] });
        return message.reply({
          embeds: [EmbedManager.info('Note', [
            '`-note add <@utente o ID> <testo>` (Staff)',
            '`-note list <@utente o ID>` (Staff)',
            '`-note remove <id_nota>` (Admin)'
          ].join('\n'))]
        });
      }

      case 'autorole': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });
        const sub = args.shift()?.toLowerCase();
        if (sub === 'set') {
          if (!args[0]) return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `-autorole set <@ruolo o ID>`')] });
          const roleId = extractRoleId(args[0]);
          if (!roleId) return message.reply({ embeds: [EmbedManager.error('ID non valido', 'Deve essere 17-20 cifre.')] });
          const role = guild.roles.cache.get(roleId);
          if (!role) return message.reply({ embeds: [EmbedManager.error('Errore', 'Ruolo non trovato.')] });
          return setAutorole(message, role, member, false);
        }
        if (sub === 'clear' || sub === 'off') {
          return clearAutorole(message, member, false);
        }
        return message.reply({
          embeds: [EmbedManager.info('Autorole', [
            '`-autorole set <@ruolo o ID>` — Imposta il ruolo automatico',
            '`-autorole clear` — Rimuovi il ruolo automatico'
          ].join('\n'))]
        });
      }

      case 'welcome': {
        if (!isAdmin(member))
          return message.reply({ embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')] });

        const sub = args.shift()?.toLowerCase();
        const gid = guild.id;
        const fill = (t, u) => t
          .replace(/{user}/g, u.toString())
          .replace(/{username}/g, u.username)
          .replace(/{server}/g, guild.name)
          .replace(/{memberCount}/g, guild.memberCount);

        if (sub === 'channel') {
          const raw = args[0] || '';
          const mm = raw.match(/^<#(\d{17,20})>$/);
          const chId = mm ? mm[1] : (/^\d{17,20}$/.test(raw) ? raw : null);
          const ch = chId ? guild.channels.cache.get(chId) : null;
          if (!ch || ch.type !== ChannelType.GuildText)
            return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `&welcome channel <#canale o ID>` (canale di testo)')] });
          storage.setWelcomeConfig(gid, { channelId: ch.id, message: null, embedEnabled: undefined });
          return message.reply({ embeds: [EmbedManager.success('Canale Impostato', `Benvenuto in ${ch}`)] });
        }

        if (sub === 'message') {
          const testo = args.join(' ').trim();
          if (!testo)
            return message.reply({ embeds: [EmbedManager.error('Sintassi', 'Uso: `&welcome message <testo>`\nUsa `{user}`, `{username}`, `{server}`, `{memberCount}`')] });
          storage.setWelcomeConfig(gid, { channelId: null, message: testo, embedEnabled: undefined });
          return message.reply({ embeds: [EmbedManager.success('Messaggio Impostato', `**Anteprima:**\n\n${fill(testo, message.author)}`)] });
        }

        if (sub === 'toggle') {
          const current = storage.getWelcomeConfig(gid);
          const newVal = !(current?.embed_enabled);
          storage.setWelcomeConfig(gid, { channelId: null, message: null, embedEnabled: newVal });
          return message.reply({ embeds: [EmbedManager.success('Formato Cambiato', newVal ? 'Ora uso **embed**' : 'Ora uso **testo semplice**')] });
        }

        if (sub === 'test') {
          const config = storage.getWelcomeConfig(gid);
          if (!config || !config.channel_id)
            return message.reply({ embeds: [EmbedManager.error('Non Configurato', 'Imposta prima il canale con `&welcome channel <#canale>`')] });
          const text = fill(config.message || 'Benvenuto {user} in {server}!', message.author);
          if (config.embed_enabled) {
            const embed = new EmbedBuilder()
              .setTitle('👋 Benvenuto!')
              .setDescription(text)
              .setColor(0x00FF00)
              .setThumbnail(message.author.displayAvatarURL({ dynamic: true }))
              .setFooter({ text: `Sei il membro #${guild.memberCount}` })
              .setTimestamp();
            return message.reply({ embeds: [embed] });
          }
          return message.reply({ content: text, allowedMentions: { parse: [], repliedUser: false } });
        }

        if (sub === 'disable' || sub === 'off') {
          storage.disableWelcome(gid);
          return message.reply({ embeds: [EmbedManager.warning('Benvenuto Disattivato', 'Il sistema di benvenuto è disattivato. Riattivalo con `&welcome channel <#canale>`.')] });
        }

        return message.reply({
          embeds: [EmbedManager.info('Welcome', [
            '`&welcome channel <#canale o ID>` — Imposta il canale',
            '`&welcome message <testo>` — Imposta il messaggio',
            '`&welcome toggle` — Embed / testo semplice',
            '`&welcome test` — Anteprima',
            '`&welcome disable` — Disattiva'
          ].join('\n'))]
        });
      }
    }
  } catch (err) {
    log.err('handlePrefixCommand', err);
    return message.reply('❌ Errore durante l\'esecuzione del comando.');
  }
}

// ==================== SLASH HANDLER ====================
async function handleSlashCommand(interaction) {
  const { commandName, member, guild } = interaction;

  switch (commandName) {
    case 'help':
      return interaction.reply({ embeds: [buildHelpEmbed()] });

    case 'stats':
      if (!hasStaffOrAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
      return showStats(interaction, true);

    case 'ping': {
      const latency = Date.now() - interaction.createdTimestamp;
      const apiLatency = Math.round(client.ws.ping);
      return interaction.reply({
        embeds: [EmbedManager.info('🏓 Pong!',
          `**Latenza Bot:** ${latency}ms\n**Latenza API:** ${apiLatency}ms`
        )]
      });
    }

    case 'uptime': {
      const uptimeMs = Date.now() - botStartTime;
      const seconds = Math.floor(uptimeMs / 1000);
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      const secs = seconds % 60;

      const parts = [];
      if (days > 0) parts.push(`${days}g`);
      if (hours > 0) parts.push(`${hours}h`);
      if (minutes > 0) parts.push(`${minutes}m`);
      parts.push(`${secs}s`);

      return interaction.reply({
        embeds: [EmbedManager.info('⏱️ Uptime',
          `Il bot è online da: **${parts.join(' ')}**`
        )]
      });
    }

    case 'ticketpanel': {
      if (!isAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('create_ticket').setLabel('Apri Ticket').setStyle(ButtonStyle.Primary)
      );
      return interaction.reply({
        embeds: [EmbedManager.info('Pannello Ticket', 'Premi il bottone qui sotto per aprire un ticket.')],
        components: [row]
      });
    }
    case 'ticket': return createTicket(interaction, interaction.user);
    case 'close': return closeTicket(interaction, interaction.user);

    case 'userinfo': {
      const user = interaction.options.getUser('utente') || interaction.user;
      const m = await guild.members.fetch(user.id).catch(() => null);
      return interaction.reply({
        embeds: [EmbedManager.info(`Info ${user.username}`, `Info su ${user}`)
          .setThumbnail(user.displayAvatarURL({ dynamic: true }))
          .addFields(
            { name: 'ID', value: user.id, inline: true },
            { name: 'Bot', value: user.bot ? 'Sì' : 'No', inline: true },
            { name: 'Creato il', value: formatDate(user.createdAt), inline: true },
            { name: 'Entrato il', value: m ? formatDate(m.joinedAt) : 'N/A', inline: true },
            { name: 'Ruoli', value: getRoles(m, guild), inline: false }
          )]
      });
    }

    case 'roles': {
      const res = await CommandLogic.listRoles(guild);
      return interaction.reply({ content: res.message, ephemeral: true });
    }

    case 'warn': {
      if (!hasStaffOrAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
      const target = interaction.options.getUser('utente');
      const reason = interaction.options.getString('motivo') || 'Nessun motivo specificato';
      const m = await guild.members.fetch(target.id).catch(() => null);
      if (!m) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Utente non nel server.')], ephemeral: true });
      if (target.id === interaction.user.id) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non puoi warnare te stesso.')], ephemeral: true });
      if (m.permissions.has(PermissionsBitField.Flags.Administrator)) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non puoi warnare un admin.')], ephemeral: true });
      await ModLogModule.logUserAction(guild, {
        type: 'Warn', title: 'Warn', targetId: target.id,
        target: `${target.username} (${target.id})`,
        moderator: `${interaction.user.username} (${interaction.user.id})`, reason
      });
      return interaction.reply({
        embeds: [EmbedManager.warning('Warn', 'Utente warnato').addFields(
          { name: 'Utente', value: `${target.username} (${target.id})`, inline: true },
          { name: 'Moderatore', value: interaction.user.username, inline: true },
          { name: 'Motivo', value: reason, inline: false }
        )]
      });
    }

    case 'timeout': {
      if (!hasStaffOrAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
      const target = interaction.options.getUser('utente');
      const seconds = interaction.options.getInteger('secondi');
      const reason = interaction.options.getString('motivo') || 'Nessun motivo specificato';
      if (seconds < 1 || seconds > 2419200)
        return safeReply(interaction, { embeds: [EmbedManager.error('Durata non valida', 'Tra 1 e 2419200 secondi.')], ephemeral: true });
      const m = await guild.members.fetch(target.id).catch(() => null);
      if (!m) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Utente non nel server.')], ephemeral: true });
      if (target.id === interaction.user.id) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non puoi timeout te stesso.')], ephemeral: true });
      if (m.permissions.has(PermissionsBitField.Flags.Administrator)) return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non puoi timeout un admin.')], ephemeral: true });
      const bot = guild.members.me;
      if (!bot.permissions.has(PermissionsBitField.Flags.ModerateMembers))
        return safeReply(interaction, { embeds: [EmbedManager.error('Permessi', 'Manca "Modera Membri".')], ephemeral: true });
      if (!m.moderatable)
        return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non posso timeout questo utente.')], ephemeral: true });
      if (!outranks(member, m, guild))
        return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non puoi timeout un utente con ruolo uguale o superiore al tuo.')], ephemeral: true });
      try { await m.timeout(seconds * 1000, reason); }
      catch { return safeReply(interaction, { embeds: [EmbedManager.error('Errore', 'Non posso timeout questo utente.')], ephemeral: true }); }
      const durata = formatDuration(seconds);
      await ModLogModule.logUserAction(guild, {
        type: 'Timeout', title: 'Timeout', targetId: target.id,
        target: `${target.username} (${target.id})`,
        moderator: `${interaction.user.username} (${interaction.user.id})`, reason, duration: durata
      });
      return interaction.reply({
        embeds: [EmbedManager.createEmbed({
          title: '⏱️ Timeout', color: 0xFFA500,
          fields: [
            { name: 'Utente', value: `${target.username} (${target.id})`, inline: true },
            { name: 'Moderatore', value: interaction.user.username, inline: true },
            { name: 'Durata', value: durata, inline: true },
            { name: 'Motivo', value: reason, inline: false }
          ],
          timestamp: true
        })]
      });
    }

    case 'kick': {
      if (!member.permissions.has(PermissionsBitField.Flags.KickMembers))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Espelli Membri".')], ephemeral: true });
      const u = interaction.options.getUser('utente');
      const r = interaction.options.getString('motivo') || 'Nessun motivo';
      const res = await CommandLogic.kick(guild, member, u.id, r);
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Kick' })], ephemeral: !res.success });
    }
    case 'ban': {
      if (!member.permissions.has(PermissionsBitField.Flags.BanMembers))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Banna Membri".')], ephemeral: true });
      const u = interaction.options.getUser('utente');
      const r = interaction.options.getString('motivo') || 'Nessun motivo';
      const res = await CommandLogic.ban(guild, member, u.id, r);
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Ban' })], ephemeral: !res.success });
    }
    case 'unban': {
      if (!member.permissions.has(PermissionsBitField.Flags.BanMembers))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Banna Membri".')], ephemeral: true });
      const res = await CommandLogic.unban(guild, member, interaction.options.getString('id'));
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Unban' })], ephemeral: !res.success });
    }
    case 'clear': {
      if (!member.permissions.has(PermissionsBitField.Flags.ManageMessages))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Gestisci Messaggi".')], ephemeral: true });
      const amount = interaction.options.getInteger('quantita');
      const res = await CommandLogic.clear(interaction.channel, member, amount);
      await interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Clear' })], ephemeral: true });
      if (res.success) setTimeout(() => interaction.deleteReply().catch(() => {}), 5000);
      return;
    }
    case 'purge': {
      const u = interaction.options.getUser('utente');
      const amount = interaction.options.getInteger('quantita') || 100;
      return purgeUser(interaction, u, amount, member, true);
    }
    case 'modlogs': {
      if (!hasStaffOrAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
      return handleModlogs(interaction, interaction.options.getUser('utente'), true);
    }

    case 'addcmd': {
      if (!isAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
      const name = interaction.options.getString('nome').toLowerCase();
      const resp = interaction.options.getString('risposta');
      if (resp.length > 4096) return safeReply(interaction, { embeds: [EmbedManager.error('Troppo lungo', 'Max 4096.')], ephemeral: true });
      storage.saveCommand(name, resp);
      return interaction.reply({ embeds: [EmbedManager.success('Comando Aggiunto', `"${name}" salvato.`)], ephemeral: true });
    }
    case 'delcmd': {
      if (!isAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
      const name = interaction.options.getString('nome').toLowerCase();
      if (!storage.deleteCommand(name))
        return safeReply(interaction, { embeds: [EmbedManager.error('Non Trovato', `"${name}" non esiste.`)], ephemeral: true });
      return interaction.reply({ embeds: [EmbedManager.success('Comando Eliminato', `"${name}" rimosso.`)], ephemeral: true });
    }
    case 'listcmd': {
      if (!hasStaffOrAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });

      const cmds = storage.loadCommands();
      const names = Object.keys(cmds);

      if (!names.length) {
        return interaction.reply({ embeds: [EmbedManager.info('Comandi Custom', 'Nessun comando custom salvato.')], ephemeral: true });
      }

      const list = names.sort().slice(0, 50).map(n => `\`-${n}\``).join(', ');
      const extra = names.length > 50 ? `\n\n*...e altri ${names.length - 50} comandi*` : '';

      return interaction.reply({
        embeds: [EmbedManager.info(`Comandi Custom (${names.length})`, `${list}${extra}`)],
        ephemeral: true
      });
    }

    case 'remind': {
      const timeArg = interaction.options.getString('tempo');
      const content = interaction.options.getString('testo');

      const ms = parseDuration(timeArg);
      if (!ms) {
        return safeReply(interaction, { embeds: [EmbedManager.error('Formato non valido', 'Usa `10m`, `1h`, `2d`, `30s`.')], ephemeral: true });
      }
      if (ms < 5000) {
        return safeReply(interaction, { embeds: [EmbedManager.error('Troppo corto', 'Minimo 5 secondi.')], ephemeral: true });
      }
      if (ms > 30 * 24 * 60 * 60 * 1000) {
        return safeReply(interaction, { embeds: [EmbedManager.error('Troppo lungo', 'Massimo 30 giorni.')], ephemeral: true });
      }
      if (content.length > 500) {
        return safeReply(interaction, { embeds: [EmbedManager.error('Testo troppo lungo', 'Max 500 caratteri.')], ephemeral: true });
      }

      const remindAt = new Date(Date.now() + ms);
      const id = storage.addReminder(interaction.user.id, interaction.guild.id, interaction.channel.id, content, remindAt);

      return interaction.reply({
        embeds: [EmbedManager.success('Reminder Impostato', `Ti ricorderò **${content}** <t:${Math.floor(remindAt.getTime() / 1000)}:R> (ID: #${id})`)]
      });
    }

    case 'dashboard': {
      if (!isAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('create_lobby').setLabel('Crea Lobby').setStyle(ButtonStyle.Primary)
      );
      return interaction.reply({
        embeds: [EmbedManager.info('Crea Lobby', 'Clicca per creare una lobby privata.')],
        components: [row]
      });
    }

    case 'blacklist': {
      const sub = interaction.options.getSubcommand();

      if (sub === 'list') {
        if (!hasStaffOrAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
        return listBlacklist(interaction, true);
      }
      if (sub === 'check') {
        if (!hasStaffOrAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
        return checkBlacklist(interaction, interaction.options.getUser('utente'), true);
      }

      if (sub === 'add') {
        if (!isAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
        return addBlacklist(interaction, interaction.options.getUser('utente'), interaction.options.getString('motivo') || 'Nessun motivo specificato', interaction.user, true);
      }
      if (sub === 'remove') {
        if (!isAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
        return removeBlacklist(interaction, interaction.options.getUser('utente'), interaction.user, true);
      }
      break;
    }

    case 'note': {
      const sub = interaction.options.getSubcommand();

      if (sub === 'add') {
        if (!hasStaffOrAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
        return addNote(interaction, interaction.options.getUser('utente'), interaction.options.getString('testo'), member, true);
      }
      if (sub === 'list') {
        if (!hasStaffOrAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve il ruolo Staff o superiore.')], ephemeral: true });
        return listNotes(interaction, interaction.options.getUser('utente'), true);
      }
      if (sub === 'remove') {
        if (!isAdmin(member))
          return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
        return removeNote(interaction, interaction.options.getInteger('id'), member, true);
      }
      break;
    }

    case 'autorole': {
      if (!isAdmin(member))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Solo Admin.')], ephemeral: true });
      const sub = interaction.options.getSubcommand();
      if (sub === 'set') return setAutorole(interaction, interaction.options.getRole('ruolo'), member, true);
      if (sub === 'clear') return clearAutorole(interaction, member, true);
      break;
    }

    case 'invite': {
      const u = interaction.options.getUser('utente');
      return CommandLogic.invite(interaction, guild, member, u.id, async (r) => interaction.reply({
        embeds: [buildResultEmbed(r, 'Invito')],
        ephemeral: !r.success
      }));
    }

    case 'giverole': {
      if (!member.permissions.has(PermissionsBitField.Flags.ManageRoles))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Gestisci Ruoli".')], ephemeral: true });
      const u = interaction.options.getUser('utente');
      const role = interaction.options.getRole('ruolo');
      const res = await CommandLogic.addRole(guild, member, u.id, role.id);
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Give Role' })], ephemeral: !res.success });
    }
    case 'removerole': {
      if (!member.permissions.has(PermissionsBitField.Flags.ManageRoles))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Gestisci Ruoli".')], ephemeral: true });
      const u = interaction.options.getUser('utente');
      const role = interaction.options.getRole('ruolo');
      const res = await CommandLogic.removeRole(guild, member, u.id, role.id);
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Remove Role' })], ephemeral: !res.success });
    }

    case 'lock': {
      if (!member.permissions.has(PermissionsBitField.Flags.ManageChannels))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Gestisci Canali".')], ephemeral: true });
      const res = await CommandLogic.lockChannel(interaction.channel, member, interaction.options.getString('motivo') || 'Nessun motivo');
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Canale Bloccato' })], ephemeral: !res.success });
    }
    case 'unlock': {
      if (!member.permissions.has(PermissionsBitField.Flags.ManageChannels))
        return safeReply(interaction, { embeds: [EmbedManager.error('Accesso Negato', 'Serve "Gestisci Canali".')], ephemeral: true });
      const res = await CommandLogic.unlockChannel(interaction.channel, member);
      return interaction.reply({ embeds: [buildResultEmbed({ ...res, title: 'Canale Sbloccato' })], ephemeral: !res.success });
    }

    default:
      return safeReply(interaction, {
        embeds: [EmbedManager.error('Comando Sconosciuto', `Il comando \`/${commandName}\` non è gestito.`)],
        ephemeral: true
      });
  }
}

// ==================== BUTTONS ====================
async function handleButton(interaction) {
  if (interaction.customId === 'create_ticket') return createTicket(interaction, interaction.user);
  if (interaction.customId === 'close_ticket') return closeTicket(interaction, interaction.user);
  if (interaction.customId === 'create_lobby') return createLobby(interaction);

  if (interaction.customId === 'claim_ticket') {
    const embed = EmbedManager.success('Ticket Claimato', `Il ticket è stato preso in carico da ${interaction.user}.`);
    await interaction.reply({ embeds: [embed] });
    return;
  }

  if (interaction.customId === 'priority_ticket') {
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('prio_low').setLabel('🟢 Bassa').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId('prio_med').setLabel('🟡 Media').setStyle(ButtonStyle.Secondary),
      new ButtonBuilder().setCustomId('prio_high').setLabel('🟠 Alta').setStyle(ButtonStyle.Primary),
      new ButtonBuilder().setCustomId('prio_urgent').setLabel('🔴 Urgente').setStyle(ButtonStyle.Danger)
    );
    return interaction.reply({ content: 'Scegli la priorità:', components: [row], ephemeral: true });
  }

  if (['prio_low', 'prio_med', 'prio_high', 'prio_urgent'].includes(interaction.customId)) {
    await interaction.update({ content: `✅ Priorità impostata a: **${interaction.customId.replace('prio_', '').toUpperCase()}**`, components: [] });
    return;
  }
}

// ==================== FEATURES ====================
let features = [];
try {
  features = require('./features');
  log.ok(`📦 Caricamento ${features.length} feature(s)...`);
  const ctx = {
    client,
    storage,
    log,
    EmbedManager,
    safeReply,
    safeReplySource,
    hasStaffOrAdmin,
    isAdmin
  };
  for (const feature of features) {
    if (feature.setup) {
      feature.setup(ctx);
      log.ok(`   ✅ Feature "${feature.name}" caricata`);
    }
    if (Array.isArray(feature.slashCommands)) {
      slashCommands.push(...feature.slashCommands);
    }
  }
} catch (err) {
  log.warn('⚠️ features.js non trovato o non valido. Il bot parte senza feature extra.');
  log.err('Dettagli', err);
}

// ==================== EVENTS ====================
client.once(Events.ClientReady, () => {
  log.ok(`Bot online come ${client.user.tag}`);
  log.info(`Slash commands preparati: ${slashCommands.length}`);
  log.info(`Prefix: - & (es. -help, -ticket, -warn @user)`);
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (interaction.isChatInputCommand()) {
      for (const feature of features) {
        if (
          feature.handleSlash &&
          feature.slashCommands?.some(c => c.name === interaction.commandName)
        ) {
          const ctx = {
            client, storage, log, EmbedManager,
            safeReply, safeReplySource, hasStaffOrAdmin, isAdmin
          };
          return await feature.handleSlash(interaction, ctx);
        }
      }
      await handleSlashCommand(interaction);
    } else if (interaction.isButton()) {
      for (const feature of features) {
        if (feature.handleButton) {
          const ctx = {
            client, storage, log, EmbedManager,
            safeReply, safeReplySource, hasStaffOrAdmin, isAdmin
          };
          const handled = await feature.handleButton(interaction, ctx);
          if (handled) return;
        }
      }
      await handleButton(interaction);
    }
  } catch (err) {
    log.err('interaction', err);
    const embed = EmbedManager.error('Errore', "Errore durante l'interazione.");
    if (interaction.replied || interaction.deferred) await interaction.followUp({ embeds: [embed], ephemeral: true }).catch(() => {});
    else await interaction.reply({ embeds: [embed], ephemeral: true }).catch(() => {});
  }
});

client.on(Events.MessageCreate, handlePrefixCommand);
client.on(Events.GuildMemberAdd, handleGuildMemberAdd);

process.on('unhandledRejection', (err) => log.err('unhandledRejection', err));
process.on('uncaughtException', (err) => log.err('uncaughtException', err));

// ==================== STARTUP ====================
let webServer = null;

(async () => {
  try {
    await client.login(TOKEN);
    log.ok('✅ Bot online');

    webServer = createWebServer({ storage, client, log, botStartTime });

    registerSlashCommands(CLIENT_ID, TOKEN).catch(err => {
      log.err('❌ Registrazione comandi fallita (ma il bot è online)', err);
    });
  } catch (err) {
    log.err('❌ Login fallito', err);
    process.exit(1);
  }
})();

process.on('SIGINT', () => {
  log.warn('Shutdown...');
  if (webServer) try { webServer.close(); } catch {}
  if (typeof storage.close === 'function') storage.close();
  client.destroy();
  process.exit(0);
});
