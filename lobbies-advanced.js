// lobbies-advanced.js — Sistema di lobby avanzate (stile Nova)
const { ChannelType, PermissionsBitField, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const { saveMeta } = require('./lobbies');

function slugify(name) {
  const slug = String(name || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return slug || 'lobby';
}

function findChild(guild, categoryId, suffix) {
  return guild.channels.cache.find(c => c.parentId === categoryId && c.name.endsWith(suffix)) || null;
}

// Crea la struttura completa di una lobby e la registra in lobby_meta
async function createAdvancedLobby(guild, hostMember, lobbyName, log, db) {
  const slug = slugify(lobbyName);
  const categoryName = `lobby-${slug}`;

  const existing = guild.channels.cache.find(
    c => c.type === ChannelType.GuildCategory && c.name === categoryName
  );
  if (existing) {
    const err = new Error('EXISTS');
    err.category = existing;
    throw err;
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
    { id: hostMember.id, allow }
  ];
  if (guild.members.me) {
    overwrites.push({ id: guild.members.me.id, allow });
  }

  const category = await guild.channels.create({
    name: categoryName,
    type: ChannelType.GuildCategory,
    permissionOverwrites: overwrites,
    reason: `Lobby avanzata creata da ${hostMember.user.tag}`
  });

  const channels = {};
  const channelNames = [
    { key: 'reg', name: `lobby-${slug}-registration`, type: ChannelType.GuildText },
    { key: 'dropmap', name: `lobby-${slug}-dropmap`, type: ChannelType.GuildText },
    { key: 'code', name: `lobby-${slug}-code`, type: ChannelType.GuildText },
    { key: 'chat', name: `lobby-${slug}-chat`, type: ChannelType.GuildText },
    { key: 'staff', name: `lobby-${slug}-staff`, type: ChannelType.GuildText },
    { key: 'unreg', name: `lobby-${slug}-unreg`, type: ChannelType.GuildText },
    { key: 'fills', name: `lobby-${slug}-fills`, type: ChannelType.GuildText },
    { key: 'voice', name: `lobby-${slug}`, type: ChannelType.GuildVoice }
  ];

  for (const ch of channelNames) {
    channels[ch.key] = await guild.channels.create({
      name: ch.name,
      type: ch.type,
      parent: category.id,
      permissionOverwrites: overwrites,
      reason: `Lobby avanzata creata da ${hostMember.user.tag}`
    });
  }

  if (db) {
    saveMeta(db, category.id, guild.id, {
      hostId: hostMember.id,
      regChannelId: channels.reg.id,
      dropmapChannelId: channels.dropmap.id,
      codeChannelId: channels.code.id,
      chatChannelId: channels.chat.id,
      staffChannelId: channels.staff.id,
      unregChannelId: channels.unreg.id,
      fillsChannelId: channels.fills.id
    });
  }

  const regEmbed = new EmbedBuilder()
    .setTitle(`Lobby: ${lobbyName}`)
    .setDescription(`Clicca **Register** per iscriverti.\n**Host:** <@${hostMember.id}>`)
    .setColor(0x0099FF);

  const regRow = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(`adv_register_${category.id}`).setLabel('Register').setStyle(ButtonStyle.Success),
    new ButtonBuilder().setCustomId(`adv_host_${category.id}`).setLabel('Host in game').setStyle(ButtonStyle.Secondary)
  );
  await channels.reg.send({ embeds: [regEmbed], components: [regRow] });

  const unregRow = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(`adv_unregister_${category.id}`).setLabel('Unregister').setStyle(ButtonStyle.Danger)
  );
  await channels.unreg.send({ content: 'Clicca per disiscriverti.', components: [unregRow] });

  const fillRow = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(`adv_fill_${category.id}`).setLabel('Offriti come rimpiazzo').setStyle(ButtonStyle.Primary)
  );
  await channels.fills.send({ content: 'Clicca se vuoi essere un rimpiazzo.', components: [fillRow] });

  log.ok(`Lobby avanzata "${lobbyName}" creata con successo.`);
  return { category, channels };
}

function accessChannels(guild, categoryId) {
  return [
    findChild(guild, categoryId, '-chat'),
    findChild(guild, categoryId, '-code'),
    findChild(guild, categoryId, '-dropmap')
  ].filter(Boolean);
}

async function handleAdvancedLobbyButton(interaction, db, log) {
  const id = interaction.customId;
  if (!id.startsWith('adv_')) return false;

  const parts = id.split('_');
  const action = parts[1];
  const categoryId = parts[2];
  const guild = interaction.guild;
  const member = interaction.member;

  const category = guild.channels.cache.get(categoryId);
  if (!category) return interaction.reply({ content: '❌ Lobby non trovata.', ephemeral: true });

  try {
    if (action === 'register') {
      if (db) {
        const already = db.prepare('SELECT 1 FROM lobby_registrations WHERE category_id = ? AND user_id = ?').get(categoryId, member.id);
        if (already) return interaction.reply({ content: '❌ Sei già iscritto.', ephemeral: true });
        db.prepare('INSERT OR IGNORE INTO lobby_registrations (category_id, user_id, username, registered_at) VALUES (?, ?, ?, ?)')
          .run(categoryId, member.id, member.displayName, new Date().toISOString());
      }
      for (const ch of accessChannels(guild, category.id)) {
        await ch.permissionOverwrites.edit(member, { ViewChannel: true, SendMessages: true, ReadMessageHistory: true });
      }
      return interaction.reply({ content: '✅ Iscrizione avvenuta con successo!', ephemeral: true });
    }

    if (action === 'unregister') {
      if (db) {
        const removed = db.prepare('DELETE FROM lobby_registrations WHERE category_id = ? AND user_id = ?').run(categoryId, member.id).changes > 0;
        if (!removed) return interaction.reply({ content: '❌ Non eri iscritto.', ephemeral: true });
      }
      for (const ch of accessChannels(guild, category.id)) {
        await ch.permissionOverwrites.delete(member.id).catch(() => {});
      }
      return interaction.reply({ content: '✅ Disiscrizione avvenuta con successo!', ephemeral: true });
    }

    if (action === 'host') {
      if (db) {
        const meta = db.prepare('SELECT host_id FROM lobby_meta WHERE category_id = ?').get(categoryId);
        if (meta?.host_id && meta.host_id !== member.id) {
          return interaction.reply({ content: '❌ Solo l\'host può usare questo bottone.', ephemeral: true });
        }
      }
      return interaction.reply({ content: '✅ Host in game! La lobby è ora in corso.', ephemeral: true });
    }

    if (action === 'fill') {
      return interaction.reply({ content: '✅ Ti sei offerto come rimpiazzo!', ephemeral: true });
    }

    return false;
  } catch (err) {
    log.err('advanced lobby button', err);
    return interaction.reply({ content: '❌ Errore durante l\'azione sulla lobby.', ephemeral: true });
  }
}

module.exports = { createAdvancedLobby, handleAdvancedLobbyButton };
