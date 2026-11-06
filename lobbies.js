// lobbies.js — Lobby custom: dashboard web + comandi Discord (Sistema Avanzato stile Nova)
const { ChannelType, PermissionsBitField, EmbedBuilder, SlashCommandBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const { z } = require('zod');

const LOBBY_PREFIX = 'lobby-';
const RECENT_CHAT_MS = 10 * 60 * 1000;
const VOICE_LABEL = { free: 'Libera', live: 'In corso', full: 'Vocale pieno', chat: 'Chat attiva' };
const VOICE_ORDER = { live: 0, full: 1, chat: 2, free: 3 };
const REG_LABEL = { open: 'Iscrizioni aperte', closed: 'Iscrizioni chiuse', full: 'Lobby piena' };
const LOBBY_NAME_RE = /^[\p{L}\p{N} _-]+$/u;
const CODE_RE = /^[A-Za-z0-9-]{1,30}$/;
const ID_RE = /^\d{17,20}$/;

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
  reg_channel_id TEXT,
  dropmap_channel_id TEXT,
  code_channel_id TEXT,
  chat_channel_id TEXT,
  staff_channel_id TEXT,
  unreg_channel_id TEXT,
  fills_channel_id TEXT,
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
    staff,
    regChannelId: row?.reg_channel_id || null,
    dropmapChannelId: row?.dropmap_channel_id || null,
    codeChannelId: row?.code_channel_id || null,
    chatChannelId: row?.chat_channel_id || null,
    staffChannelId: row?.staff_channel_id || null,
    unregChannelId: row?.unreg_channel_id || null,
    fillsChannelId: row?.fills_channel_id || null
  };
}

function saveMeta(db, categoryId, guildId, patch) {
  const next = { ...readMeta(db, categoryId), ...patch };
  db.prepare(`
    INSERT INTO lobby_meta (category_id, guild_id, host_id, dropmap, code, slots, reg_open, staff, reg_channel_id, dropmap_channel_id, code_channel_id, chat_channel_id, staff_channel_id, unreg_channel_id, fills_channel_id, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(category_id) DO UPDATE SET
      host_id = excluded.host_id,
      dropmap = excluded.dropmap,
      code = excluded.code,
      slots = excluded.slots,
      reg_open = excluded.reg_open,
      staff = excluded.staff,
      reg_channel_id = excluded.reg_channel_id,
      dropmap_channel_id = excluded.dropmap_channel_id,
      code_channel_id = excluded.code_channel_id,
      chat_channel_id = excluded.chat_channel_id,
      staff_channel_id = excluded.staff_channel_id,
      unreg_channel_id = excluded.unreg_channel_id,
      fills_channel_id = excluded.fills_channel_id,
      updated_at = excluded.updated_at
  `).run(
    categoryId, guildId, next.hostId, next.dropmap, next.code, next.slots,
    next.regOpen ? 1 : 0, JSON.stringify(next.staff),
    next.regChannelId, next.dropmapChannelId, next.codeChannelId, next.chatChannelId,
    next.staffChannelId, next.unregChannelId, next.fillsChannelId,
    new Date().toISOString()
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
async function applyAccess(guild, category, member, level, reason, log, channels) {
  const perms = level === 'staff' ? STAFF_PERMS : level === 'player' ? PLAYER_PERMS : null;
  const chs = channels || [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
  for (const ch of chs) {
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
  const text = children.find(c => c.type === ChannelType.GuildText && c.name.includes('chat')) || children.find(c => c.type === ChannelType.GuildText) || null;
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

// ==================== COMANDI DISCORD ====================
function findLobbyByName(guild, name) {
  if (!name || !guild) return null;
  const key = slugify(String(name).trim());
  if (!key) return null;
  return [...guild.channels.cache.values()].find(c => {
    if (!isLobbyCategory(c)) return false;
    const rest = c.name.slice(LOBBY_PREFIX.length);
    return slugify(rest) === key || rest.toLowerCase() === String(name).trim().toLowerCase();
  }) || null;
}

function listLobbyCategories(guild) {
  return [...guild.channels.cache.values()].filter(isLobbyCategory);
}

function isLobbyAdmin(member) {
  return !!member?.permissions?.has(PermissionsBitField.Flags.Administrator);
}

function canManageLobby(member, meta) {
  if (!member) return false;
  if (isLobbyAdmin(member)) return true;
  if (meta.hostId === member.id) return true;
  return meta.staff.some(s => s.id === member.id);
}

function channelByIdOrSuffix(guild, category, id, suffix) {
  if (id) {
    const ch = guild.channels.cache.get(id);
    if (ch) return ch;
  }
  return [...guild.channels.cache.values()].find(c => c.parentId === category.id && c.name.endsWith(suffix)) || null;
}

function playerChannels(guild, category, meta) {
  return [
    channelByIdOrSuffix(guild, category, meta.chatChannelId, '-chat'),
    channelByIdOrSuffix(guild, category, meta.codeChannelId, '-code'),
    channelByIdOrSuffix(guild, category, meta.dropmapChannelId, '-dropmap'),
    [...guild.channels.cache.values()].find(c => c.parentId === category.id && c.type === ChannelType.GuildVoice) || null
  ].filter(Boolean);
}

async function runLobbyCommand({ guild, member, sub, name, targetUser, map, code, db, log, reply }) {
  if (sub === 'lista') {
    const cats = listLobbyCategories(guild);
    if (!cats.length) return reply({ content: 'Nessuna lobby in questo server. Creane una con `/lobby crea` o `-lobby crea <nome>`.' });
    const lines = cats.slice(0, 25).map(c => {
      const meta = readMeta(db, c.id);
      const count = listRegistrations(db, c.id).length;
      const label = c.name.slice(LOBBY_PREFIX.length);
      return `• **${label}** — iscritti: ${count}${meta.dropmap ? ` — mappa: ${meta.dropmap}` : ''}`;
    }).join('\n');
    return reply({ embeds: [new EmbedBuilder().setTitle('Lobby').setDescription(lines).setColor(0x0099FF)] });
  }

  if (sub === 'crea') {
    const clean = String(name || '').trim().replace(/\s+/g, ' ');
    if (!clean || !LOBBY_NAME_RE.test(clean) || clean.length > 30) {
      return reply({ content: '❌ Nome non valido: usa lettere, numeri, spazi, - e _ (max 30).' });
    }
    const slug = slugify(clean);
    const catName = LOBBY_PREFIX + slug;
    if (findLobbyByName(guild, clean) || guild.channels.cache.some(c => c.type === ChannelType.GuildCategory && c.name === catName)) {
      return reply({ content: '❌ Esiste già una lobby con questo nome.' });
    }
    const me = guild.members.me;
    if (me && !me.permissions.has(PermissionsBitField.Flags.ManageChannels)) {
      return reply({ content: '❌ Il bot non ha il permesso di gestire i canali.' });
    }

    const allow = [
      PermissionsBitField.Flags.ViewChannel,
      PermissionsBitField.Flags.SendMessages,
      PermissionsBitField.Flags.ReadMessageHistory,
      PermissionsBitField.Flags.Connect,
      PermissionsBitField.Flags.Speak
    ];
    const overwrites = [
      { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
      { id: member.id, allow }
    ];
    if (me) overwrites.push({ id: me.id, allow });

    const category = await guild.channels.create({ name: catName, type: ChannelType.GuildCategory, permissionOverwrites: overwrites, reason: `Lobby creata da ${member.user.tag}` });
    const regChannel = await guild.channels.create({ name: `${catName}-registration`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const dropmapChannel = await guild.channels.create({ name: `${catName}-dropmap`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const codeChannel = await guild.channels.create({ name: `${catName}-code`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const chatChannel = await guild.channels.create({ name: `${catName}-chat`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const staffChannel = await guild.channels.create({ name: `${catName}-staff`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const unregChannel = await guild.channels.create({ name: `${catName}-unreg`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    const fillsChannel = await guild.channels.create({ name: `${catName}-fills`, type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
    await guild.channels.create({ name: catName, type: ChannelType.GuildVoice, parent: category.id, userLimit: 0, permissionOverwrites: overwrites });

    saveMeta(db, category.id, guild.id, {
      hostId: member.id,
      regChannelId: regChannel.id,
      dropmapChannelId: dropmapChannel.id,
      codeChannelId: codeChannel.id,
      chatChannelId: chatChannel.id,
      staffChannelId: staffChannel.id,
      unregChannelId: unregChannel.id,
      fillsChannelId: fillsChannel.id
    });

    const regEmbed = new EmbedBuilder()
      .setTitle(`Lobby: ${clean}`)
      .setDescription(`Clicca **Register** per iscriverti.\nLa lobby è **${clean}**.\n\n**Host:** <@${member.id}>`)
      .setColor(0x0099FF)
      .setTimestamp();
    await regChannel.send({
      embeds: [regEmbed],
      components: [new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`register_lobby_${category.id}`).setLabel('Register').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId(`host_ingame_${category.id}`).setLabel('Host in game').setStyle(ButtonStyle.Secondary)
      )]
    });
    await unregChannel.send({
      content: 'Clicca **Unregister** per disiscriverti dalla lobby.',
      components: [new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId(`unregister_lobby_${category.id}`).setLabel('Unregister').setStyle(ButtonStyle.Danger))]
    });
    await fillsChannel.send({
      content: 'Qui puoi offrirti come rimpiazzo per la lobby.',
      components: [new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId(`fill_lobby_${category.id}`).setLabel('Offriti come rimpiazzo').setStyle(ButtonStyle.Primary))]
    });

    return reply({ content: `✅ Lobby **${clean}** creata.\nRegistrazione: <#${regChannel.id}>` });
  }

  const category = findLobbyByName(guild, name);
  if (!category) return reply({ content: '❌ Lobby non trovata. Controlla il nome con `/lobby lista`.' });
  const meta = readMeta(db, category.id);
  const label = category.name.slice(LOBBY_PREFIX.length);

  if (sub === 'info') {
    const regs = listRegistrations(db, category.id);
    const names = regs.slice(0, 20).map(r => r.username).join(', ') || 'nessuno';
    const seeCode = canManageLobby(member, meta) || hasRegistration(db, category.id, member.id);
    return reply({
      embeds: [new EmbedBuilder()
        .setTitle(`Lobby ${label}`)
        .setColor(0x0099FF)
        .addFields(
          { name: 'Host', value: meta.hostId ? `<@${meta.hostId}>` : 'N/D', inline: true },
          { name: 'Iscritti', value: meta.slots > 0 ? `${regs.length}/${meta.slots}` : String(regs.length), inline: true },
          { name: 'Iscrizioni', value: meta.regOpen ? 'Aperte' : 'Chiuse', inline: true },
          { name: 'Dropmap', value: meta.dropmap || 'Non impostata', inline: true },
          { name: 'Codice', value: meta.code ? (seeCode ? meta.code : 'Impostato') : 'Non impostato', inline: true },
          { name: 'Nomi', value: names.slice(0, 1024), inline: false }
        )]
    });
  }

  if (sub === 'iscriviti') {
    const targetMember = targetUser
      ? await guild.members.fetch(targetUser.id).catch(() => null)
      : member;
    if (!targetMember) return reply({ content: '❌ Utente non trovato nel server.' });
    if (targetUser && targetUser.id !== member.id && !canManageLobby(member, meta)) {
      return reply({ content: '❌ Solo host, staff o admin possono iscrivere un altro utente.' });
    }
    if (targetMember.user.bot) return reply({ content: '❌ Un bot non può iscriversi.' });
    if (!meta.regOpen && !canManageLobby(member, meta)) return reply({ content: '❌ Iscrizioni chiuse.' });
    const count = listRegistrations(db, category.id).length;
    if (meta.slots > 0 && count >= meta.slots && !hasRegistration(db, category.id, targetMember.id)) {
      return reply({ content: '❌ Lobby piena.' });
    }
    if (hasRegistration(db, category.id, targetMember.id)) return reply({ content: '❌ Già iscritto.' });
    addRegistration(db, category.id, targetMember.id, targetMember.displayName);
    await applyAccess(guild, category, targetMember, 'player', 'Iscrizione lobby', log, playerChannels(guild, category, meta));
    return reply({ content: `✅ <@${targetMember.id}> iscritto a **${label}**.` });
  }

  if (sub === 'rimuovi') {
    if (!canManageLobby(member, meta)) return reply({ content: '❌ Solo host, staff o admin possono rimuovere un iscritto.' });
    if (!targetUser) return reply({ content: '❌ Indica l\'utente da rimuovere.' });
    if (targetUser.id === meta.hostId) return reply({ content: '❌ Non puoi rimuovere l\'host.' });
    if (!removeRegistration(db, category.id, targetUser.id)) return reply({ content: '❌ Quell\'utente non è iscritto.' });
    const targetMember = await guild.members.fetch(targetUser.id).catch(() => null);
    if (targetMember) {
      const level = accessLevel(meta, targetMember.id, false);
      await applyAccess(guild, category, targetMember, level === 'none' ? 'none' : level, 'Rimozione lobby', log, playerChannels(guild, category, meta));
    }
    return reply({ content: `✅ <@${targetUser.id}> rimosso da **${label}**.` });
  }

  if (sub === 'dropmap') {
    if (!canManageLobby(member, meta)) return reply({ content: '❌ Solo host, staff o admin possono impostare la dropmap.' });
    const value = String(map || '').trim().slice(0, 80);
    if (!value) return reply({ content: '❌ Indica il nome della mappa.' });
    saveMeta(db, category.id, guild.id, { dropmap: value });
    const ch = channelByIdOrSuffix(guild, category, meta.dropmapChannelId, '-dropmap');
    if (ch) await ch.send({ embeds: [new EmbedBuilder().setTitle('Dropmap').setDescription(`**${value}**`).setColor(0x0099FF)] }).catch(() => {});
    return reply({ content: `✅ Dropmap di **${label}** impostata: **${value}**.` });
  }

  if (sub === 'codice') {
    if (!canManageLobby(member, meta)) return reply({ content: '❌ Solo host, staff o admin possono impostare il codice.' });
    const value = String(code || '').trim();
    if (!CODE_RE.test(value)) return reply({ content: '❌ Codice non valido: lettere, numeri e trattino, max 30.' });
    saveMeta(db, category.id, guild.id, { code: value });
    const ch = channelByIdOrSuffix(guild, category, meta.codeChannelId, '-code');
    if (ch) await ch.send({ embeds: [new EmbedBuilder().setTitle('Codice lobby').setDescription(`\`${value}\``).setColor(0x0099FF)] }).catch(() => {});
    return reply({ content: `✅ Codice di **${label}** impostato.` });
  }

  if (sub === 'elimina') {
    if (!(isLobbyAdmin(member) || meta.hostId === member.id)) return reply({ content: '❌ Solo l\'host o un admin possono eliminare la lobby.' });
    const reason = `Lobby eliminata da ${member.user.tag}`;
    const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
    for (const ch of children) await ch.delete(reason).catch(err => log.warn(`Impossibile eliminare ${ch.name}: ${err.message}`));
    await category.delete(reason);
    deleteLobbyData(db, category.id);
    return reply({ content: `✅ Lobby **${label}** eliminata.` });
  }

  return reply({ content: '❌ Comando non riconosciuto. Usa crea, iscriviti, rimuovi, dropmap, codice, info, lista, elimina.' });
}

async function handleLobbyCommand(interaction, db, log) {
  if (!interaction.isChatInputCommand() || interaction.commandName !== 'lobby') return false;
  await interaction.deferReply({ ephemeral: false }).catch(() => {});
  const sub = interaction.options.getSubcommand();
  try {
    return await runLobbyCommand({
      guild: interaction.guild,
      member: interaction.member,
      sub,
      name: interaction.options.getString('nome') || interaction.options.getString('lobby'),
      targetUser: interaction.options.getUser('utente'),
      map: interaction.options.getString('mappa'),
      code: interaction.options.getString('codice'),
      db,
      log,
      reply: (payload) => interaction.editReply(payload)
    });
  } catch (e) {
    log.err('lobby command', e);
    return interaction.editReply({ content: '❌ Errore durante l\'esecuzione del comando.' });
  }
}

const LOBBY_HELP = [
  '**Lobby** — slash `/lobby` oppure prefisso `-lobby` / `&lobby`',
  '`crea <nome>` — crea la lobby',
  '`lista` — elenca le lobby',
  '`info <nome>` — dettagli',
  '`iscriviti <nome>` — iscriviti',
  '`rimuovi <nome> @utente` — togli un iscritto',
  '`dropmap <nome> | <mappa>` — imposta la mappa',
  '`codice <nome> | <codice>` — imposta il codice',
  '`elimina <nome>` — elimina la lobby'
].join('\n');

async function handleLobbyPrefix(message, args, db, log) {
  const reply = (payload) => message.channel.send(payload);
  const sub = (args.shift() || '').toLowerCase();
  if (!sub || sub === 'help') return reply({ content: LOBBY_HELP });

  let targetUser = null;
  const mentionIdx = args.findIndex(a => /^<@!?\d{17,20}>$/.test(a) || /^\d{17,20}$/.test(a));
  if (mentionIdx !== -1) {
    const id = (args[mentionIdx].match(/\d{17,20}/) || [])[0];
    args.splice(mentionIdx, 1);
    targetUser = await message.client.users.fetch(id).catch(() => null);
  }

  let name = null;
  let map = null;
  let code = null;
  const rest = args.join(' ').trim();
  if (sub === 'crea' || sub === 'info' || sub === 'elimina' || sub === 'iscriviti') {
    name = rest;
  } else if (sub === 'rimuovi') {
    name = rest;
  } else if (sub === 'dropmap' || sub === 'codice') {
    const [left, right] = rest.split('|').map(s => s.trim());
    name = left;
    if (sub === 'dropmap') map = right;
    else code = right;
  }

  try {
    return await runLobbyCommand({
      guild: message.guild,
      member: message.member,
      sub,
      name,
      targetUser,
      map,
      code,
      db,
      log,
      reply
    });
  } catch (e) {
    log.err('lobby prefix', e);
    return reply({ content: '❌ Errore durante l\'esecuzione del comando.' });
  }
}

const lobbyCommandBuilder = new SlashCommandBuilder()
  .setName('lobby')
  .setDescription('Gestisci le lobby del server')
  .addSubcommand(sub => sub.setName('crea').setDescription('Crea una nuova lobby').addStringOption(o => o.setName('nome').setDescription('Nome della lobby').setRequired(true)))
  .addSubcommand(sub => sub.setName('iscriviti').setDescription('Iscriviti a una lobby').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)).addUserOption(o => o.setName('utente').setDescription('Utente da iscrivere (opzionale)')))
  .addSubcommand(sub => sub.setName('rimuovi').setDescription('Rimuovi un utente da una lobby').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)).addUserOption(o => o.setName('utente').setDescription('Utente da rimuovere').setRequired(true)))
  .addSubcommand(sub => sub.setName('dropmap').setDescription('Imposta la dropmap').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)).addStringOption(o => o.setName('mappa').setDescription('Nome della mappa').setRequired(true)))
  .addSubcommand(sub => sub.setName('codice').setDescription('Imposta il codice').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)).addStringOption(o => o.setName('codice').setDescription('Codice della lobby').setRequired(true)))
  .addSubcommand(sub => sub.setName('info').setDescription('Mostra info su una lobby').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)))
  .addSubcommand(sub => sub.setName('lista').setDescription('Elenca tutte le lobby'))
  .addSubcommand(sub => sub.setName('elimina').setDescription('Elimina una lobby').addStringOption(o => o.setName('lobby').setDescription('Nome della lobby').setRequired(true)));

// ==================== GESTIONE BOTTONI ====================
async function handleLobbyButton(interaction, db, log) {
  const customId = interaction.customId;
  if (!customId.startsWith('register_lobby_') && !customId.startsWith('unregister_lobby_') && !customId.startsWith('host_ingame_') && !customId.startsWith('fill_lobby_')) return false;

  const parts = customId.split('_');
  const action = parts[0];
  const lobbyId = parts[2];

  const guild = interaction.guild;
  const member = interaction.member;

  try {
    if (action === 'register') {
      const category = guild.channels.cache.get(lobbyId);
      if (!category) return interaction.reply({ content: '❌ Lobby non trovata.', ephemeral: true });

      const meta = readMeta(db, category.id);
      const count = listRegistrations(db, category.id).length;

      if (!meta.regOpen) return interaction.reply({ content: '❌ Iscrizioni chiuse.', ephemeral: true });
      if (meta.slots > 0 && count >= meta.slots) return interaction.reply({ content: '❌ Lobby piena.', ephemeral: true });
      if (hasRegistration(db, category.id, member.id)) return interaction.reply({ content: '❌ Sei già iscritto.', ephemeral: true });

      addRegistration(db, category.id, member.id, member.displayName);

      const channelsToGive = [
        meta.chatChannelId ? guild.channels.cache.get(meta.chatChannelId) : null,
        meta.codeChannelId ? guild.channels.cache.get(meta.codeChannelId) : null,
        meta.dropmapChannelId ? guild.channels.cache.get(meta.dropmapChannelId) : null
      ].filter(Boolean);

      await applyAccess(guild, category, member, accessLevel(meta, member.id, true), 'Iscrizione da bottone', log, channelsToGive);
      return interaction.reply({ content: '✅ Iscrizione avvenuta con successo!', ephemeral: true });
    }

    if (action === 'unregister') {
      const category = guild.channels.cache.get(lobbyId);
      if (!category) return interaction.reply({ content: '❌ Lobby non trovata.', ephemeral: true });

      if (!removeRegistration(db, category.id, member.id)) return interaction.reply({ content: '❌ Non eri iscritto.', ephemeral: true });

      const meta = readMeta(db, category.id);
      const channelsToRemove = [
        meta.chatChannelId ? guild.channels.cache.get(meta.chatChannelId) : null,
        meta.codeChannelId ? guild.channels.cache.get(meta.codeChannelId) : null,
        meta.dropmapChannelId ? guild.channels.cache.get(meta.dropmapChannelId) : null
      ].filter(Boolean);

      await applyAccess(guild, category, member, accessLevel(meta, member.id, false), 'Disiscrizione da bottone', log, channelsToRemove);
      return interaction.reply({ content: '✅ Disiscrizione avvenuta con successo!', ephemeral: true });
    }

    if (action === 'host') {
      const category = guild.channels.cache.get(lobbyId);
      if (!category) return interaction.reply({ content: '❌ Lobby non trovata.', ephemeral: true });

      const meta = readMeta(db, category.id);
      if (meta.hostId !== member.id) return interaction.reply({ content: '❌ Solo l\'host può usare questo bottone.', ephemeral: true });

      return interaction.reply({ content: '✅ Host in game! La lobby è ora in corso.', ephemeral: true });
    }

    if (action === 'fill') {
      const category = guild.channels.cache.get(lobbyId);
      if (!category) return interaction.reply({ content: '❌ Lobby non trovata.', ephemeral: true });

      return interaction.reply({ content: '✅ Ti sei offerto come rimpiazzo!', ephemeral: true });
    }

    return false;
  } catch (e) {
    log.err('lobby button', e);
    return interaction.reply({ content: '❌ Errore durante l\'esecuzione dell\'azione.', ephemeral: true });
  }
}

// ==================== ROTTE DASHBOARD WEB ====================
function mountLobbies(app, deps) {
  const { client, storage, log, requireAuth, actionLimiter, parseOrFail, apiError, assertGuildAccess, canManageGuild, logMod, dashMod } = deps;
  const db = storage.db;
  db.exec(SCHEMA);

  // --- INIZIO MIGRAZIONE AUTOMATICA ---
  try {
    const tableInfo = db.prepare("PRAGMA table_info(lobby_meta)").all();
    const existingCols = tableInfo.map(c => c.name);
    const newCols = [
      'reg_channel_id TEXT',
      'dropmap_channel_id TEXT',
      'code_channel_id TEXT',
      'chat_channel_id TEXT',
      'staff_channel_id TEXT',
      'unreg_channel_id TEXT',
      'fills_channel_id TEXT'
    ];
    for (const colDef of newCols) {
      const colName = colDef.split(' ')[0];
      if (!existingCols.includes(colName)) {
        db.exec(`ALTER TABLE lobby_meta ADD COLUMN ${colDef}`);
        log.info(`✅ Aggiunta colonna ${colName} a lobby_meta`);
      }
    }
  } catch (err) {
    log.err('Migrazione DB fallita', err);
  }
  // --- FINE MIGRAZIONE AUTOMATICA ---

  const schemaLobbyCreate = z.object({ name: z.string().min(1).max(30), userLimit: z.number().int().min(0).max(99).optional().default(0) });
  const schemaSettings = z.object({ dropmap: z.string().max(60).nullable().optional(), code: z.string().max(30).nullable().optional(), slots: z.number().int().min(0).max(99).optional(), regOpen: z.boolean().optional() });
  const schemaUserId = z.object({ userId: z.string().regex(ID_RE, 'ID utente non valido') });
  const schemaAnnounce = z.object({ kind: z.enum(['code', 'dropmap', 'fill']) });

  async function loadCategoryOrFail(req, res, categoryId) {
    if (!ID_RE.test(categoryId)) { res.status(400).json({ error: 'ID non valido' }); return null; }
    const category = await client.channels.fetch(categoryId).catch(() => null);
    if (!category || !category.guild || !isLobbyCategory(category)) { res.status(404).json({ error: 'Lobby non trovata' }); return null; }
    if (!(await canManageGuild(req.session.user.id, category.guild))) { res.status(403).json({ error: 'Non hai i permessi su questo server' }); return null; }
    return category;
  }

  app.get('/api/lobbies/:guildId', requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    if (!(await assertGuildAccess(req, res, guildId))) return;
    try {
      const guild = client.guilds.cache.get(guildId);
      const now = Date.now();
      const lobbies = [...guild.channels.cache.values()].filter(isLobbyCategory).map(c => buildLobby(guild, c, now, db)).sort((a, b) => (VOICE_ORDER[a.voice.status] - VOICE_ORDER[b.voice.status]) || a.name.localeCompare(b.name));
      res.json({ guildName: guild.name, lobbies });
    } catch (e) { apiError(res, e, 'Errore mappa lobby'); }
  });

  // (le altre rotte API sono identiche a prima, le includo per completezza)
  app.get('/api/lobbies/:guildId/members/search', requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const q = String(req.query.q || '').trim().slice(0, 32);
    if (q.length < 2) return res.json([]);
    if (!(await assertGuildAccess(req, res, guildId))) return;
    try {
      const guild = client.guilds.cache.get(guildId);
      let found;
      try { found = [...(await guild.members.search({ query: q, limit: 10 })).values()]; }
      catch { const needle = q.toLowerCase(); found = [...guild.members.cache.values()].filter(m => m.user.username.toLowerCase().includes(needle) || m.displayName.toLowerCase().includes(needle)); }
      res.json(found.filter(m => !m.user.bot).slice(0, 10).map(m => ({ id: m.id, name: m.displayName, username: m.user.username, avatar: m.displayAvatarURL({ size: 32 }) })));
    } catch (e) { apiError(res, e, 'Errore ricerca membri'); }
  });

  app.post('/api/lobbies/:guildId', actionLimiter, requireAuth, async (req, res) => {
    const guildId = req.params.guildId;
    if (!ID_RE.test(guildId)) return res.status(400).json({ error: 'ID server non valido' });
    const data = parseOrFail(schemaLobbyCreate, req.body || {}, res);
    if (!data) return;
    const name = data.name.trim().replace(/\s+/g, ' ');
    if (!name || !LOBBY_NAME_RE.test(name)) return res.status(400).json({ error: 'Nome non valido: usa lettere, numeri, spazi, - e _' });
    if (!(await assertGuildAccess(req, res, guildId))) return;
    try {
      const guild = client.guilds.cache.get(guildId);
      if (!guild.members.me.permissions.has(PermissionsBitField.Flags.ManageChannels)) return res.status(403).json({ error: 'Il bot non ha "Gestisci Canali"' });
      const categoryName = LOBBY_PREFIX + name;
      if (guild.channels.cache.some(c => c.type === ChannelType.GuildCategory && c.name === categoryName)) return res.status(409).json({ error: 'Esiste già una lobby con questo nome' });
      const hostMember = await guild.members.fetch(req.session.user.id).catch(() => null);
      const overwrites = [{ id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] }];
      if (hostMember) overwrites.push({ id: hostMember.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory, PermissionsBitField.Flags.Connect, PermissionsBitField.Flags.Speak] });
      const category = await guild.channels.create({ name: categoryName, type: ChannelType.GuildCategory, permissionOverwrites: overwrites, reason: `Lobby creata dalla dashboard (${req.session.user.username})` });
      try {
        await guild.channels.create({ name: 'chat-' + slugify(name), type: ChannelType.GuildText, parent: category.id, permissionOverwrites: overwrites });
        await guild.channels.create({ name: categoryName, type: ChannelType.GuildVoice, parent: category.id, userLimit: data.userLimit, permissionOverwrites: overwrites });
      } catch (err) { await category.delete('Creazione lobby incompleta').catch(() => {}); throw err; }
      saveMeta(db, category.id, guild.id, { hostId: hostMember ? hostMember.id : null });
      await logMod(guild, { type: 'Lobby Creata', title: 'Lobby Creata', moderator: dashMod(req), channel: categoryName, reason: data.userLimit ? `Limite ${data.userLimit} giocatori` : undefined });
      res.status(201).json({ ok: true, id: category.id });
    } catch (e) { apiError(res, e, 'Errore creazione lobby'); }
  });

  app.patch('/api/lobbies/:categoryId/settings', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaSettings, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const patch = {};
    if (data.dropmap !== undefined) { const dm = data.dropmap ? data.dropmap.trim() : ''; patch.dropmap = dm || null; }
    if (data.code !== undefined) { const code = data.code ? data.code.trim() : ''; if (code && !CODE_RE.test(code)) return res.status(400).json({ error: 'Codice non valido' }); patch.code = code || null; }
    if (data.slots !== undefined) patch.slots = data.slots;
    if (data.regOpen !== undefined) patch.regOpen = data.regOpen;
    try { saveMeta(db, category.id, category.guild.id, patch); res.json({ ok: true }); }
    catch (e) { apiError(res, e, 'Errore impostazioni lobby'); }
  });

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
      await logMod(guild, { type: 'Lobby Iscrizione', title: 'Iscrizione Lobby', targetId: member.id, target: `${member.user.username} (${member.id})`, moderator: dashMod(req), channel: category.name });
      res.status(201).json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore iscrizione'); }
  });

  app.delete('/api/lobbies/:categoryId/registrations/:userId', actionLimiter, requireAuth, async (req, res) => {
    if (!ID_RE.test(req.params.userId)) return res.status(400).json({ error: 'ID utente non valido' });
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    try {
      if (!removeRegistration(db, category.id, req.params.userId)) return res.status(404).json({ error: 'Non iscritto' });
      const meta = readMeta(db, category.id);
      const member = await category.guild.members.fetch(req.params.userId).catch(() => null);
      if (member) await applyAccess(category.guild, category, member, accessLevel(meta, member.id, false), 'Rimozione iscrizione', log);
      await logMod(category.guild, { type: 'Lobby Rimozione', title: 'Rimozione Iscritto', targetId: req.params.userId, target: req.params.userId, moderator: dashMod(req), channel: category.name });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore rimozione iscritto'); }
  });

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
      await logMod(guild, { type: 'Lobby Staff', title: 'Staff Lobby Assegnato', targetId: member.id, target: `${member.user.username} (${member.id})`, moderator: dashMod(req), channel: category.name });
      res.status(201).json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore nomina staff'); }
  });

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
      if (member) { const registered = hasRegistration(db, category.id, member.id); await applyAccess(guild, category, member, accessLevel({ staff }, member.id, registered), 'Rimozione staff lobby', log); }
      await logMod(guild, { type: 'Lobby Staff Rimosso', title: 'Staff Lobby Rimosso', targetId: req.params.userId, target: req.params.userId, moderator: dashMod(req), channel: category.name });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore rimozione staff'); }
  });

  app.post('/api/lobbies/:categoryId/announce', actionLimiter, requireAuth, async (req, res) => {
    const data = parseOrFail(schemaAnnounce, req.body || {}, res);
    if (!data) return;
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    const guild = category.guild;
    try {
      const text = textChannelOf(guild, category);
      if (!text) return res.status(404).json({ error: 'Chat della lobby non trovata' });
      if (!text.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.SendMessages)) return res.status(403).json({ error: 'Il bot non può scrivere nella chat della lobby' });
      const meta = readMeta(db, category.id);
      const regs = listRegistrations(db, category.id);
      let embed;
      if (data.kind === 'code') { if (!meta.code) return res.status(400).json({ error: 'Nessun codice impostato' }); embed = lobbyEmbed('🔑 Codice lobby', `**Codice:** \`${meta.code}\``); }
      else if (data.kind === 'dropmap') { if (!meta.dropmap) return res.status(400).json({ error: 'Nessuna dropmap impostata' }); embed = lobbyEmbed('🗺️ Dropmap', `**${meta.dropmap}**`); }
      else { const fill = meta.slots > 0 ? `${regs.length}/${meta.slots}` : `${regs.length}`; const list = regs.map(r => '• ' + r.username).join('\n') || '_nessun iscritto_'; embed = lobbyEmbed('👥 Iscritti', `**Iscritti:** ${fill}\n${list}`); }
      await text.send({ embeds: [embed] });
      res.json({ ok: true });
    } catch (e) { apiError(res, e, 'Errore invio in chat'); }
  });

  app.delete('/api/lobbies/:categoryId', actionLimiter, requireAuth, async (req, res) => {
    const category = await loadCategoryOrFail(req, res, req.params.categoryId);
    if (!category) return;
    try {
      const guild = category.guild;
      const reason = `Lobby eliminata dalla dashboard (${req.session.user.username})`;
      const children = [...guild.channels.cache.values()].filter(c => c.parentId === category.id);
      for (const ch of children) await ch.delete(reason).catch(err => log.warn(`Impossibile eliminare ${ch.name}: ${err.message}`));
      await category.delete(reason);
      deleteLobbyData(db, category.id);
      await logMod(guild, { type: 'Lobby Eliminata', title: 'Lobby Eliminata', moderator: dashMod(req), channel: category.name });
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

module.exports = {
  mountLobbies,
  renderLobbiesContent,
  handleLobbyCommand,
  handleLobbyPrefix,
  lobbyCommandBuilder,
  handleLobbyButton,
  saveMeta
};
