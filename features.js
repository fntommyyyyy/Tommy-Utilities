// ==================== FEATURES ====================
const {
  SlashCommandBuilder,
  ChannelType,
  EmbedBuilder
} = require('discord.js');

// ==================== FEATURE 1 — BENVENUTO ====================
const welcomeFeature = {
  name: 'welcome',

  setup({ client, storage, log }) {
    if (!client || typeof client.on !== 'function') {
      log.warn('welcome: client non ancora disponibile, setup saltato');
      return;
    }
    if (this._listenerRegistered) return;   // fix doppio listener
    this._listenerRegistered = true;

    client.on('guildMemberAdd', async member => {
      try {
        if (storage.isBlacklisted(member.user.id)) return;

        const config = storage.getWelcomeConfig(member.guild.id);
        if (!config || !config.channel_id) return;

        const channel = member.guild.channels.cache.get(config.channel_id);
        if (!channel) return;

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
          await channel.send({ embeds: [embed] }).catch(() => {});
        } else {
          await channel.send({ content: text }).catch(() => {});
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

    if (!isAdmin(interaction.member)) {
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
      storage.setWelcomeConfig(gid, { channelId: channel.id, message: null, embedEnabled: undefined });
      return safeReply(interaction, {
        embeds: [new EmbedBuilder().setTitle('✅ Canale Impostato').setDescription(`Benvenuto in ${channel}`).setColor(0x00FF00)],
        ephemeral: true
      });
    }

    if (sub === 'message') {
      const testo = interaction.options.getString('testo');
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

// ==================== EXPORT ====================
module.exports = [
  welcomeFeature
];
