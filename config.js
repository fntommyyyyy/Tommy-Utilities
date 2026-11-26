function loadBotConfig(env = process.env) {
  const token = (env.DISCORD_TOKEN || env.TOKEN || '').trim();
  const clientId = (env.CLIENT_ID || '').trim();
  const modLogChannelId = (env.MOD_LOG_CHANNEL_ID || '').trim();

  if (!token) throw new Error('TOKEN mancante nel file .env');
  if (!clientId) throw new Error('CLIENT_ID mancante nel file .env');
  if (!modLogChannelId) throw new Error('MOD_LOG_CHANNEL_ID mancante nel file .env');

  return {
    token,
    clientId,
    modLogChannelId,
    blacklistAdminServers: (env.BLACKLIST_ADMIN_SERVERS || '')
      .split(',').map(value => value.trim()).filter(Boolean),
    guildId: (env.GUILD_ID || '').trim(),
    dbPath: env.DB_PATH || './data/bot.db',
    dbBackupDir: env.DB_BACKUP_DIR || '',
    dbBackupRetention: parseRetention(env.DB_BACKUP_RETENTION)
  };
}

function parseRetention(value) {
  if (value == null || value === '') return 7;
  const retention = Number(value);
  if (!Number.isSafeInteger(retention) || retention < 1 || retention > 365) {
    throw new Error('DB_BACKUP_RETENTION deve essere un numero intero tra 1 e 365');
  }
  return retention;
}

module.exports = { loadBotConfig };
