// ==================== FEATURES ====================
const {
  SlashCommandBuilder,
  ChannelType,
  EmbedBuilder,
  PermissionsBitField,
  Events
} = require('discord.js');

// ==================== FEATURE 1 — BENVENUTO ====================
const welcomeFeature = {
  name: 'welcome',

  setup({ client, storage, log }) {
    if (!client || typeof client.on !== 'function') {
      log.warn('welcome: client non ancora disponibile, setup saltato');
      return;
    }
    if (this._listenerRegistered) return;
    this._listenerRegistered = true;

    client.on('guildMemberAdd', async member => {
      try {
        if (storage.isBlacklisted(member.user.id)) return;

        const config = storage.getWelcomeConfig(member.guild.id);
        if (!config || !config.channel_id) return;

        const channel = member.guild.channels.cache.get(config.channel_id);
        if (!channel) {
          // FIX: log esplicito se il canale è stato cancellato/rinominato
          log.warn(`welcome: canale ${config.channel_id} non trovato in ${member.guild.name} (può essere stato cancellato).`);
          return;
        }

        if (!channel.isTextBased()) {
          log.warn(`welcome: canale ${channel.name} non è testuale in ${member.guild.name}`);
          return;
        }

        // FIX: verifico che il bot possa scrivere nel canale
        const botMember = member.guild.members.me;
        if (botMember && !channel.permissionsFor(botMember)?.has('SendMessages')) {
          log.warn(`welcome: manca permesso SendMessages in ${channel.name} (${member.guild.name})`);
          return;
        }

        const text = (config.message || 'Benvenuto {user} in {server}!')
          .replace(/{user}/g, member.toString())
          .replace(/{username}/g, member.user.username)
          .replace(/{server}/g, member.guild.name)
          .replace(/{memberCount}/g, member.guild.memberCount);

        if (config.embed_enabled) {
          const embed = new EmbedBuilder()
            .setTitle('👋 Benvenuto!')
            .setDescription(text)
            .setColor(0x00FF00)
            .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
            .setFooter({ text: `Sei il membro #${member.guild.memberCount}` })
            .setTimestamp();
          await channel.send({ embeds: [embed] }).catch(err => log.warn(`welcome send embed: ${err.message}`));
        } else {
          await channel.send({ content: text }).catch(err => log.warn(`welcome send text: ${err.message}`));
        }
      } catch (err) {
        log.err('welcome guildMemberAdd', err);
      }
    });
  },

  slashCommands: [
    new SlashCommandBuilder()
      .setName('welcome')
      .setDescription('Configura il sistema di benvenuto')
      .addSubcommand(sub => sub
        .setName('channel')
        .setDescription('Imposta il canale di benvenuto')
        .addChannelOption(o => o
          .setName('canale')
          .setDescription('Canale di testo')
          .addChannelTypes(ChannelType.GuildText)
          .setRequired(true)))
      .addSubcommand(sub => sub
        .setName('message')
        .setDescription('Imposta il messaggio di benvenuto')
        .addStringOption(o => o
          .setName('testo')
          .setDescription('Usa {user}, {username}, {server}, {memberCount}')
          .setRequired(true)))
      .addSubcommand(sub => sub
        .setName('toggle')
        .setDescription('Attiva/disattiva il formato embed'))
      .addSubcommand(sub => sub
        .setName('test')
        .setDescription('Mostra un anteprima del messaggio'))
      .addSubcommand(sub => sub
        .setName('disable')
        .setDescription('Disattiva il sistema di benvenuto'))
  ],

  async handleSlash(interaction, ctx) {
    const { storage, isAdmin, safeReply } = ctx;
    const sub = interaction.options.getSubcommand();

    // FIX: controllo esplicito se member è null (es. in DM, ma il bot non ha DM)
    if (!interaction.member || !isAdmin(interaction.member)) {
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('❌ Accesso Negato').setDescription('Solo Admin.').setColor(0xFF0000)],
        ephemeral: true
      });
    }

    if (!['channel', 'message', 'toggle', 'test', 'disable'].includes(sub)) {
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('❌ Subcommand sconosciuto').setDescription(`\`${sub}\` non è gestito.`).setColor(0xFF0000)],
        ephemeral: true
      });
    }

    const gid = interaction.guild.id;

    if (sub === 'channel') {
      const channel = interaction.options.getChannel('canale');
      if (!channel || channel.type !== ChannelType.GuildText) {
        return safeReply(interaction, {
          embeds: [new EmbedBuilder().setTitle('❌ Errore').setDescription('Devi selezionare un canale testuale.').setColor(0xFF0000)],
          ephemeral: true
        });
      }
      storage.setWelcomeConfig(gid, { channelId: channel.id, message: null, embedEnabled: undefined });
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Canale Impostato').setDescription(`Benvenuto in ${channel}`).setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'message') {
      const testo = interaction.options.getString('testo');
      if (!testo || testo.trim().length < 1) {
        return safeReply(interaction, {
          embeds: [new EmbedBuilder().setTitle('❌ Errore').setDescription('Il messaggio non può essere vuoto.').setColor(0xFF0000)],
          ephemeral: true
        });
      }
      if (testo.length > 2000) {
        return safeReply(interaction, {
          embeds: [new EmbedBuilder().setTitle('❌ Troppo Lungo').setDescription('Max 2000 caratteri.').setColor(0xFF0000)],
          ephemeral: true
        });
      }
      storage.setWelcomeConfig(gid, { channelId: null, message: testo, embedEnabled: undefined });

      const preview = testo
        .replace(/{user}/g, interaction.user.toString())
        .replace(/{username}/g, interaction.user.username)
        .replace(/{server}/g, interaction.guild.name)
        .replace(/{memberCount}/g, interaction.guild.memberCount);

      return safeReply(interaction, {
        embeds: [new EmbedBuilder()
          .setTitle('✅ Messaggio Impostato')
          .setDescription(`**Anteprima:**\n\n${preview}`)
          .setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'toggle') {
      const current = storage.getWelcomeConfig(gid);
      const newVal = !(current?.embed_enabled);
      storage.setWelcomeConfig(gid, { channelId: null, message: null, embedEnabled: newVal });
      return safeReply(interaction, {
        embeds: [new EmbedBuilder()
          .setTitle('✅ Formato Cambiato')
          .setDescription(newVal ? 'Ora uso **embed**' : 'Ora uso **testo semplice**')
          .setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'test') {
      const config = storage.getWelcomeConfig(gid);
      if (!config || !config.channel_id) {
        return safeReply(interaction, {
          embeds: [new EmbedBuilder().setTitle('❌ Non Configurato').setDescription('Imposta prima il canale con `/welcome channel`').setColor(0xFF0000)],
          ephemeral: true
        });
      }
      const text = (config.message || 'Benvenuto {user} in {server}!')
        .replace(/{user}/g, interaction.user.toString())
        .replace(/{username}/g, interaction.user.username)
        .replace(/{server}/g, interaction.guild.name)
        .replace(/{memberCount}/g, interaction.guild.memberCount);

      if (config.embed_enabled) {
        const embed = new EmbedBuilder()
          .setTitle('👋 Benvenuto!')
          .setDescription(text)
          .setColor(0x00FF00)
          .setThumbnail(interaction.user.displayAvatarURL({ dynamic: true }))
          .setFooter({ text: `Sei il membro #${interaction.guild.memberCount}` })
          .setTimestamp();
        return safeReply(interaction, { embeds: [embed], ephemeral: true });
      } else {
        return safeReply(interaction, { content: text, ephemeral: true });
      }
    }

    if (sub === 'disable') {
      storage.disableWelcome(gid);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Benvenuto Disattivato').setDescription('Il sistema di benvenuto è ora disattivato. Riattivalo con `/welcome channel`.').setColor(0xFFA500)],
        ephemeral: true
      });
    }
  }
};

function denied(title, description) {
  return {
    embeds: [new EmbedBuilder().setTitle(title).setDescription(description).setColor(0xFF0000)],
    ephemeral: true
  };
}

function emojiKeyFromInput(raw) {
  const s = String(raw || '').trim();
  const custom = s.match(/^<a?:([\w~]+):(\d+)>$/);
  if (custom) return `${custom[1]}:${custom[2]}`;
  return s;
}

function emojiToReact(raw) {
  const s = String(raw || '').trim();
  const custom = s.match(/^<a?:[\w~]+:(\d+)>$/);
  if (custom) return custom[1];
  return s;
}

function reactionEmojiKey(emoji) {
  if (emoji.id) return `${emoji.name}:${emoji.id}`;
  return emoji.name;
}

async function resolveGuildMessage(guild, raw, channelOpt) {
  const text = String(raw || '').trim();
  const link = text.match(/channels\/(\d+)\/(\d+)\/(\d+)/);
  if (link) {
    if (link[1] !== guild.id) return { error: 'Il messaggio non è di questo server.' };
    const channel = await guild.channels.fetch(link[2]).catch(() => null);
    if (!channel || !channel.isTextBased()) return { error: 'Canale del messaggio non trovato.' };
    const message = await channel.messages.fetch(link[3]).catch(() => null);
    if (!message) return { error: 'Messaggio non trovato.' };
    return { message };
  }
  if (!/^\d{17,20}$/.test(text)) return { error: 'Passa il link del messaggio, oppure l\'ID insieme al canale.' };
  const channel = channelOpt || null;
  if (!channel || !channel.isTextBased()) return { error: 'Con un ID serve anche il canale.' };
  const message = await channel.messages.fetch(text).catch(() => null);
  if (!message) return { error: 'Messaggio non trovato in quel canale.' };
  return { message };
}

// ==================== FEATURE 2 — REACTION ROLES ====================
const reactionRoleFeature = {
  name: 'reaction-roles',

  setup({ client, storage, log }) {
    if (!client || typeof client.on !== 'function') return;
    if (this._listenerRegistered) return;
    this._listenerRegistered = true;

    async function toggle(reaction, user, add) {
      try {
        if (!user || user.bot) return;
        if (reaction.partial) reaction = await reaction.fetch();
        if (reaction.message.partial) await reaction.message.fetch();
        const guild = reaction.message.guild;
        if (!guild) return;

        const row = storage.getReactionRoleByEmoji(guild.id, reaction.message.id, reactionEmojiKey(reaction.emoji));
        if (!row) return;

        const member = await guild.members.fetch(user.id).catch(() => null);
        if (!member) return;
        const role = guild.roles.cache.get(row.role_id);
        if (!role) {
          log.warn(`reaction-roles: ruolo ${row.role_id} non trovato in ${guild.name}`);
          return;
        }
        const me = guild.members.me;
        if (me && role.position >= me.roles.highest.position) {
          log.warn(`reaction-roles: ruolo ${role.name} sopra il bot in ${guild.name}`);
          return;
        }

        if (add) {
          if (!member.roles.cache.has(role.id)) await member.roles.add(role, 'Reaction role');
        } else if (member.roles.cache.has(role.id)) {
          await member.roles.remove(role, 'Reaction role');
        }
      } catch (err) {
        log.err(add ? 'reaction role add' : 'reaction role remove', err);
      }
    }

    client.on(Events.MessageReactionAdd, (reaction, user) => toggle(reaction, user, true));
    client.on(Events.MessageReactionRemove, (reaction, user) => toggle(reaction, user, false));
  },

  slashCommands: [
    new SlashCommandBuilder()
      .setName('reactionrole')
      .setDescription('Assegna un ruolo con una reazione')
      .setDefaultMemberPermissions(PermissionsBitField.Flags.ManageRoles)
      .addSubcommand(sub => sub
        .setName('add')
        .setDescription('Collega un emoji a un ruolo')
        .addStringOption(o => o.setName('messaggio').setDescription('Link del messaggio, oppure ID').setRequired(true))
        .addStringOption(o => o.setName('emoji').setDescription('Emoji unicode o custom').setRequired(true))
        .addRoleOption(o => o.setName('ruolo').setDescription('Ruolo da assegnare').setRequired(true))
        .addChannelOption(o => o.setName('canale').setDescription('Obbligatorio se passi solo l\'ID').addChannelTypes(ChannelType.GuildText)))
      .addSubcommand(sub => sub
        .setName('remove')
        .setDescription('Togli un collegamento emoji-ruolo')
        .addStringOption(o => o.setName('messaggio').setDescription('Link del messaggio, oppure ID').setRequired(true))
        .addStringOption(o => o.setName('emoji').setDescription('Emoji da scollegare').setRequired(true))
        .addChannelOption(o => o.setName('canale').setDescription('Obbligatorio se passi solo l\'ID').addChannelTypes(ChannelType.GuildText)))
      .addSubcommand(sub => sub
        .setName('list')
        .setDescription('Mostra i reaction role di un messaggio')
        .addStringOption(o => o.setName('messaggio').setDescription('Link del messaggio, oppure ID').setRequired(true))
        .addChannelOption(o => o.setName('canale').setDescription('Obbligatorio se passi solo l\'ID').addChannelTypes(ChannelType.GuildText)))
      .addSubcommand(sub => sub
        .setName('clear')
        .setDescription('Rimuovi tutti i reaction role di un messaggio')
        .addStringOption(o => o.setName('messaggio').setDescription('Link del messaggio, oppure ID').setRequired(true))
        .addChannelOption(o => o.setName('canale').setDescription('Obbligatorio se passi solo l\'ID').addChannelTypes(ChannelType.GuildText)))
  ],

  async handleSlash(interaction, ctx) {
    const { storage, safeReply, isAdmin } = ctx;
    const member = interaction.member;
    const can = member?.permissions?.has(PermissionsBitField.Flags.ManageRoles) || (member && isAdmin(member));
    if (!can) return safeReply(interaction, denied('❌ Accesso Negato', 'Serve il permesso Gestisci ruoli.'));

    const sub = interaction.options.getSubcommand();
    const found = await resolveGuildMessage(
      interaction.guild,
      interaction.options.getString('messaggio'),
      interaction.options.getChannel('canale')
    );
    if (found.error) return safeReply(interaction, denied('❌ Messaggio', found.error));
    const message = found.message;
    const gid = interaction.guild.id;

    if (sub === 'add') {
      const rawEmoji = interaction.options.getString('emoji');
      const key = emojiKeyFromInput(rawEmoji);
      if (!key || key.length > 64) return safeReply(interaction, denied('❌ Emoji', 'Emoji non valida.'));
      const role = interaction.options.getRole('ruolo');
      if (!role || role.id === interaction.guild.id) return safeReply(interaction, denied('❌ Ruolo', 'Ruolo non valido.'));
      const me = interaction.guild.members.me;
      if (me && role.position >= me.roles.highest.position) {
        return safeReply(interaction, denied('❌ Ruolo', 'Quel ruolo è sopra il bot. Sposta il ruolo del bot più in alto.'));
      }
      if (role.managed) return safeReply(interaction, denied('❌ Ruolo', 'Non posso assegnare un ruolo gestito da un\'integrazione.'));
      if (storage.getReactionRoleByEmoji(gid, message.id, key)) {
        return safeReply(interaction, denied('❌ Già presente', 'Questa emoji è già collegata su quel messaggio.'));
      }
      await message.react(emojiToReact(rawEmoji)).catch(() => null);
      storage.addReactionRole(gid, message.id, message.channel.id, key, role.id);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder()
          .setTitle('✅ Reaction role')
          .setDescription(`Su ${message.url}\n${rawEmoji} → ${role}`)
          .setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'remove') {
      const key = emojiKeyFromInput(interaction.options.getString('emoji'));
      const row = storage.getReactionRoleByEmoji(gid, message.id, key);
      if (!row) return safeReply(interaction, denied('❌ Non trovato', 'Nessun collegamento per questa emoji.'));
      storage.deleteReactionRole(gid, row.id);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Rimosso').setDescription(`Collegamento tolto da ${message.url}`).setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'list') {
      const rows = storage.getReactionRolesForMessage(gid, message.id);
      if (!rows.length) return safeReply(interaction, denied('ℹ️ Nessuno', 'Questo messaggio non ha reaction role.'));
      const lines = rows.map(r => `• \`${r.emoji}\` → <@&${r.role_id}>`).join('\n').slice(0, 3900);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('Reaction role').setDescription(lines).setColor(0x0099FF)],
        ephemeral: true
      });
    }

    if (sub === 'clear') {
      const n = storage.deleteReactionRolesForMessage(gid, message.id);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Pulito').setDescription(`Rimossi ${n} collegamenti.`).setColor(0x00FF00)],
        ephemeral: true
      });
    }
  }
};

// ==================== FEATURE 3 — REPORT ====================
const reportCooldowns = new Map();

const reportFeature = {
  name: 'reports',

  slashCommands: [
    new SlashCommandBuilder()
      .setName('report')
      .setDescription('Segnala un utente allo staff')
      .addUserOption(o => o.setName('utente').setDescription('Utente da segnalare').setRequired(true))
      .addStringOption(o => o.setName('motivo').setDescription('Cosa è successo').setRequired(true).setMaxLength(500)),
    new SlashCommandBuilder()
      .setName('reports')
      .setDescription('Gestisci le segnalazioni aperte')
      .setDefaultMemberPermissions(PermissionsBitField.Flags.ModerateMembers)
      .addSubcommand(sub => sub.setName('list').setDescription('Mostra le segnalazioni aperte'))
      .addSubcommand(sub => sub
        .setName('close')
        .setDescription('Chiudi una segnalazione')
        .addIntegerOption(o => o.setName('id').setDescription('ID della segnalazione').setRequired(true).setMinValue(1)))
  ],

  async handleSlash(interaction, ctx) {
    const { storage, safeReply, hasStaffOrAdmin, modLog } = ctx;
    const name = interaction.commandName;
    const gid = interaction.guild.id;

    if (name === 'report') {
      const target = interaction.options.getUser('utente');
      const reason = interaction.options.getString('motivo').trim();
      if (!target) return safeReply(interaction, denied('❌ Errore', 'Utente non valido.'));
      if (target.id === interaction.user.id) return safeReply(interaction, denied('❌ Errore', 'Non puoi segnalare te stesso.'));
      if (target.bot) return safeReply(interaction, denied('❌ Errore', 'Non puoi segnalare un bot.'));
      if (!reason) return safeReply(interaction, denied('❌ Errore', 'Il motivo non può essere vuoto.'));

      const now = Date.now();
      const until = reportCooldowns.get(`${gid}:${interaction.user.id}`) || 0;
      if (until > now) {
        const sec = Math.ceil((until - now) / 1000);
        return safeReply(interaction, denied('⏱️ Attendi', `Puoi inviare un altro report tra ${sec}s.`));
      }
      reportCooldowns.set(`${gid}:${interaction.user.id}`, now + 60 * 1000);

      const id = storage.addReport(gid, interaction.user.id, target.id, reason);
      if (typeof modLog === 'function') {
        await modLog(interaction.guild, {
          type: 'Report',
          title: `Report #${id}`,
          targetId: target.id,
          target: `${target.tag} (${target.id})`,
          user: `${interaction.user.tag} (${interaction.user.id})`,
          moderator: interaction.user.tag,
          channel: interaction.channel?.name || 'N/D',
          reason
        });
      }
      return safeReply(interaction, {
        embeds: [new EmbedBuilder()
          .setTitle('✅ Segnalazione inviata')
          .setDescription(`Report **#${id}** su ${target}. Lo staff lo vede in \`/reports list\`.`)
          .setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (!interaction.member || !hasStaffOrAdmin(interaction.member)) {
      return safeReply(interaction, denied('❌ Accesso Negato', 'Solo lo staff può gestire i report.'));
    }

    const sub = interaction.options.getSubcommand();
    if (sub === 'list') {
      const rows = storage.getOpenReports(gid).slice(0, 15);
      if (!rows.length) {
        return safeReply(interaction, {
          embeds: [new EmbedBuilder().setTitle('Nessun report').setDescription('Non ci sono segnalazioni aperte.').setColor(0x808080)],
          ephemeral: true
        });
      }
      const lines = rows.map(r => `**#${r.id}** <@${r.target_id}> — da <@${r.reporter_id}>\n${r.reason}`).join('\n\n').slice(0, 3900);
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('Report aperti').setDescription(lines).setColor(0xFFA500)],
        ephemeral: true
      });
    }

    if (sub === 'close') {
      const id = interaction.options.getInteger('id');
      const row = storage.getReport(gid, id);
      if (!row) return safeReply(interaction, denied('❌ Non trovato', `Nessun report #${id} in questo server.`));
      if (row.status !== 'open') return safeReply(interaction, denied('ℹ️ Già chiuso', `Il report #${id} è già \`${row.status}\`.`));
      storage.setReportStatus(gid, id, 'closed');
      if (typeof modLog === 'function') {
        await modLog(interaction.guild, {
          type: 'Report chiuso',
          title: `Report #${id} chiuso`,
          targetId: row.target_id,
          target: `<@${row.target_id}>`,
          moderator: `${interaction.user.tag} (${interaction.user.id})`,
          reason: row.reason
        });
      }
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Report chiuso').setDescription(`Segnalazione **#${id}** chiusa.`).setColor(0x00FF00)],
        ephemeral: true
      });
    }
  }
};

// ==================== EXPORT ====================
module.exports = [
  welcomeFeature,
  reactionRoleFeature,
  reportFeature
];
