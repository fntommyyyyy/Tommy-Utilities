// lobbies-advanced.js — Sistema di lobby avanzate (stile Nova)
const { ChannelType, PermissionsBitField, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');

// Questa funzione crea la struttura completa di una lobby
async function createAdvancedLobby(guild, hostMember, lobbyName, log) {
  const slug = lobbyName.toLowerCase().replace(/\s+/g, '-');

  // Permessi base: nessuno può vedere, tranne l'host
  const overwrites = [
    { id: guild.roles.everyone.id, deny: [PermissionsBitField.Flags.ViewChannel] },
    { id: hostMember.id, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory, PermissionsBitField.Flags.Connect, PermissionsBitField.Flags.Speak] }
  ];

  // 1. Crea la categoria
  const category = await guild.channels.create({
    name: `lobby-${slug}`,
    type: ChannelType.GuildCategory,
    permissionOverwrites: overwrites,
    reason: `Lobby avanzata creata da ${hostMember.user.tag}`
  });

  // 2. Crea i canali
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
      permissionOverwrites: overwrites
    });
  }

  // 3. Invia i messaggi con i bottoni nei canali principali
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
  return category;
}

// Questa funzione gestisce i bottoni (da chiamare in index.js)
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

  if (action === 'register') {
    // Diamo i permessi per chat, code e dropmap
    const channelsToGive = [
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-chat')),
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-code')),
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-dropmap'))
    ].filter(Boolean);

    for (const ch of channelsToGive) {
      await ch.permissionOverwrites.edit(member, { ViewChannel: true, SendMessages: true, ReadMessageHistory: true });
    }
    return interaction.reply({ content: '✅ Iscrizione avvenuta con successo!', ephemeral: true });
  }

  if (action === 'unregister') {
    const channelsToRemove = [
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-chat')),
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-code')),
      guild.channels.cache.find(c => c.parentId === category.id && c.name.endsWith('-dropmap'))
    ].filter(Boolean);

    for (const ch of channelsToRemove) {
      await ch.permissionOverwrites.delete(member);
    }
    return interaction.reply({ content: '✅ Disiscrizione avvenuta con successo!', ephemeral: true });
  }

  if (action === 'host') {
    return interaction.reply({ content: '✅ Host in game! La lobby è ora in corso.', ephemeral: true });
  }

  if (action === 'fill') {
    return interaction.reply({ content: '✅ Ti sei offerto come rimpiazzo!', ephemeral: true });
  }

  return false;
}

module.exports = { createAdvancedLobby, handleAdvancedLobbyButton };
