const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

class StorageService {
  constructor(dbPath = './data/bot.db') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this._migrate();
    this._prepare();
  }

  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS custom_commands (
        name TEXT PRIMARY KEY,
        response TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS mod_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        target_id TEXT,
        target TEXT,
        moderator TEXT,
        reason TEXT,
        duration TEXT,
        channel TEXT,
        timestamp TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_mod_logs_target ON mod_logs(target_id);

      CREATE TABLE IF NOT EXISTS blacklist (
        user_id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        reason TEXT NOT NULL,
        moderator_id TEXT NOT NULL,
        moderator_tag TEXT NOT NULL,
        added_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS guild_config (
        guild_id TEXT PRIMARY KEY,
        autorole_id TEXT,
        log_channel_id TEXT,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS member_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        author_id TEXT NOT NULL,
        author_tag TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_notes_user ON member_notes(guild_id, user_id);

      CREATE TABLE IF NOT EXISTS welcome_config (
        guild_id TEXT PRIMARY KEY,
        channel_id TEXT,
        message TEXT,
        embed_enabled INTEGER DEFAULT 1,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS reaction_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        emoji TEXT NOT NULL,
        role_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rr_message ON reaction_roles(guild_id, message_id);

      CREATE TABLE IF NOT EXISTS autoresponses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        trigger TEXT NOT NULL,
        response TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ar_trigger ON autoresponses(guild_id, trigger);

      CREATE TABLE IF NOT EXISTS birthdays (
        user_id TEXT PRIMARY KEY,
        guild_id TEXT NOT NULL,
        day INTEGER NOT NULL,
        month INTEGER NOT NULL,
        year INTEGER,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        guild_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        content TEXT NOT NULL,
        remind_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_remind_at ON reminders(remind_at);

      CREATE TABLE IF NOT EXISTS personal_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        guild_id TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pnotes_user ON personal_notes(guild_id, user_id);

      CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        moderator_id TEXT NOT NULL,
        action TEXT NOT NULL,
        reason TEXT,
        duration TEXT,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(guild_id, user_id);

      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        reporter_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_reports_guild ON reports(guild_id, status);

      CREATE TABLE IF NOT EXISTS dashboard_access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        timestamp TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ticket_transcripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id TEXT NOT NULL,
        channel_name TEXT NOT NULL,
        user_id TEXT NOT NULL,
        claimed_by TEXT,
        priority TEXT,
        html_content TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS antinuke_config (
        guild_id TEXT PRIMARY KEY,
        whitelist_ids TEXT DEFAULT '',
        threshold_channel INTEGER DEFAULT 3,
        threshold_role INTEGER DEFAULT 3,
        threshold_ban INTEGER DEFAULT 3,
        threshold_role_update INTEGER DEFAULT 3,
        window_ms INTEGER DEFAULT 10000,
        punishment TEXT DEFAULT 'quarantine',
        updated_at TEXT NOT NULL
      );
    `);
  }

  _prepare() {
    this._allCmds = this.db.prepare('SELECT name, response FROM custom_commands');
    this._getCmd = this.db.prepare('SELECT response FROM custom_commands WHERE name = ?');
    this._upsertCmd = this.db.prepare(`
      INSERT INTO custom_commands (name, response, created_at)
      VALUES (?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET response = excluded.response
    `);
    this._delCmd = this.db.prepare('DELETE FROM custom_commands WHERE name = ?');

    this._insertLog = this.db.prepare(`
      INSERT INTO mod_logs (type, target_id, target, moderator, reason, duration, channel, timestamp)
      VALUES (@type, @targetId, @target, @moderator, @reason, @duration, @channel, @timestamp)
    `);
    this._logsByTarget = this.db.prepare('SELECT * FROM mod_logs WHERE target_id = ? ORDER BY id DESC');
    this._countLogs = this.db.prepare('SELECT COUNT(*) as c FROM mod_logs');
    this._countByType = this.db.prepare('SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type');
    this._trimLogs = this.db.prepare(`
      DELETE FROM mod_logs WHERE id NOT IN (
        SELECT id FROM mod_logs ORDER BY id DESC LIMIT 5000
      )
    `);

    this._blGet = this.db.prepare('SELECT * FROM blacklist WHERE user_id = ?');
    this._blAll = this.db.prepare('SELECT * FROM blacklist ORDER BY added_at DESC');
    this._blInsert = this.db.prepare(`
      INSERT INTO blacklist (user_id, username, reason, moderator_id, moderator_tag, added_at)
      VALUES (@userId, @username, @reason, @moderatorId, @moderatorTag, @addedAt)
    `);
    this._blDelete = this.db.prepare('DELETE FROM blacklist WHERE user_id = ?');
    this._blCount = this.db.prepare('SELECT COUNT(*) as c FROM blacklist');

    this._getConfig = this.db.prepare('SELECT * FROM guild_config WHERE guild_id = ?');
    this._upsertConfig = this.db.prepare(`
      INSERT INTO guild_config (guild_id, autorole_id, log_channel_id, updated_at)
      VALUES (@guildId, @autoroleId, @logChannelId, @updatedAt)
      ON CONFLICT(guild_id) DO UPDATE SET
        autorole_id = excluded.autorole_id,
        log_channel_id = excluded.log_channel_id,
        updated_at = excluded.updated_at
    `);

    this._insertNote = this.db.prepare(`
      INSERT INTO member_notes (guild_id, user_id, author_id, author_tag, content, created_at)
      VALUES (@guildId, @userId, @authorId, @authorTag, @content, @createdAt)
    `);
    this._notesForUser = this.db.prepare('SELECT * FROM member_notes WHERE guild_id = ? AND user_id = ? ORDER BY id DESC');
    this._getNote = this.db.prepare('SELECT * FROM member_notes WHERE id = ? AND guild_id = ?');
    this._deleteNote = this.db.prepare('DELETE FROM member_notes WHERE id = ? AND guild_id = ?');
    this._countNotes = this.db.prepare('SELECT COUNT(*) as c FROM member_notes WHERE guild_id = ?');

    this._getWelcome = this.db.prepare(`
      SELECT guild_id, channel_id, message,
             COALESCE(embed_enabled, 1) AS embed_enabled,
             updated_at
      FROM welcome_config WHERE guild_id = ?
    `);
    this._setWelcome = this.db.prepare(`
      INSERT INTO welcome_config (guild_id, channel_id, message, embed_enabled, updated_at)
      VALUES (@guildId, @channelId, @message, COALESCE(@embedEnabled, 1), @updatedAt)
      ON CONFLICT(guild_id) DO UPDATE SET
        channel_id = COALESCE(@channelId, channel_id),
        message = COALESCE(@message, message),
        embed_enabled = COALESCE(@embedEnabled, embed_enabled),
        updated_at = @updatedAt
    `);
    this._disableWelcome = this.db.prepare(
      'UPDATE welcome_config SET channel_id = NULL, updated_at = ? WHERE guild_id = ?'
    );

    this._rrInsert = this.db.prepare(`
      INSERT INTO reaction_roles (guild_id, message_id, channel_id, emoji, role_id, created_at)
      VALUES (@guildId, @messageId, @channelId, @emoji, @roleId, @createdAt)
    `);
    this._rrByMessage = this.db.prepare('SELECT * FROM reaction_roles WHERE guild_id = ? AND message_id = ?');
    this._rrByEmoji = this.db.prepare('SELECT * FROM reaction_roles WHERE guild_id = ? AND message_id = ? AND emoji = ?');
    this._rrDelete = this.db.prepare('DELETE FROM reaction_roles WHERE id = ? AND guild_id = ?');
    this._rrDeleteByMessage = this.db.prepare('DELETE FROM reaction_roles WHERE guild_id = ? AND message_id = ?');

    this._arInsert = this.db.prepare(`
      INSERT INTO autoresponses (guild_id, trigger, response, created_at)
      VALUES (@guildId, @trigger, @response, @createdAt)
    `);
    this._arAll = this.db.prepare('SELECT * FROM autoresponses WHERE guild_id = ? ORDER BY id DESC');
    this._arByTrigger = this.db.prepare('SELECT * FROM autoresponses WHERE guild_id = ? AND trigger = ?');
    this._arDelete = this.db.prepare('DELETE FROM autoresponses WHERE id = ? AND guild_id = ?');

    this._bdSet = this.db.prepare(`
      INSERT INTO birthdays (user_id, guild_id, day, month, year, updated_at)
      VALUES (@userId, @guildId, @day, @month, @year, @updatedAt)
      ON CONFLICT(user_id) DO UPDATE SET
        guild_id = excluded.guild_id,
        day = excluded.day,
        month = excluded.month,
        year = excluded.year,
        updated_at = excluded.updated_at
    `);
    this._bdGet = this.db.prepare('SELECT * FROM birthdays WHERE user_id = ? AND guild_id = ?');
    this._bdToday = this.db.prepare('SELECT * FROM birthdays WHERE guild_id = ? AND day = ? AND month = ?');
    this._bdAll = this.db.prepare('SELECT * FROM birthdays WHERE guild_id = ? ORDER BY month, day');
    this._bdDelete = this.db.prepare('DELETE FROM birthdays WHERE user_id = ? AND guild_id = ?');

    this._remInsert = this.db.prepare(`
      INSERT INTO reminders (user_id, guild_id, channel_id, content, remind_at, created_at)
      VALUES (@userId, @guildId, @channelId, @content, @remindAt, @createdAt)
    `);
    this._remDue = this.db.prepare('SELECT * FROM reminders WHERE remind_at <= ?');
    this._remDelete = this.db.prepare('DELETE FROM reminders WHERE id = ?');
    this._remByUser = this.db.prepare('SELECT * FROM reminders WHERE user_id = ? AND guild_id = ? ORDER BY remind_at ASC');

    this._pnInsert = this.db.prepare(`
      INSERT INTO personal_notes (user_id, guild_id, content, created_at)
      VALUES (@userId, @guildId, @content, @createdAt)
    `);
    this._pnByUser = this.db.prepare('SELECT * FROM personal_notes WHERE user_id = ? AND guild_id = ? ORDER BY id DESC');
    this._pnDelete = this.db.prepare('DELETE FROM personal_notes WHERE id = ? AND user_id = ?');

    this._caseInsert = this.db.prepare(`
      INSERT INTO cases (guild_id, user_id, moderator_id, action, reason, duration, status, created_at, updated_at)
      VALUES (@guildId, @userId, @moderatorId, @action, @reason, @duration, 'active', @now, @now)
    `);
    this._caseGet = this.db.prepare('SELECT * FROM cases WHERE id = ? AND guild_id = ?');
    this._caseByUser = this.db.prepare('SELECT * FROM cases WHERE guild_id = ? AND user_id = ? ORDER BY id DESC');
    this._caseUpdate = this.db.prepare(`
      UPDATE cases SET reason = COALESCE(@reason, reason),
                       status = COALESCE(@status, status),
                       updated_at = @now
      WHERE id = @id AND guild_id = @guildId
    `);
    this._caseDelete = this.db.prepare('DELETE FROM cases WHERE id = ? AND guild_id = ?');

    this._repInsert = this.db.prepare(`
      INSERT INTO reports (guild_id, reporter_id, target_id, reason, status, created_at)
      VALUES (@guildId, @reporterId, @targetId, @reason, 'open', @createdAt)
    `);
    this._repAllOpen = this.db.prepare("SELECT * FROM reports WHERE guild_id = ? AND status = 'open' ORDER BY id DESC");
    this._repSetStatus = this.db.prepare('UPDATE reports SET status = ? WHERE id = ? AND guild_id = ?');

    this._dashLogInsert = this.db.prepare(`
      INSERT INTO dashboard_access_logs (user_id, username, ip, user_agent, timestamp)
      VALUES (@userId, @username, @ip, @userAgent, @timestamp)
    `);
    this._dashLogAll = this.db.prepare('SELECT * FROM dashboard_access_logs ORDER BY id DESC LIMIT 500');

    this._transcriptInsert = this.db.prepare(`
      INSERT INTO ticket_transcripts (channel_id, channel_name, user_id, claimed_by, priority, html_content, created_at)
      VALUES (@channelId, @channelName, @userId, @claimedBy, @priority, @htmlContent, @createdAt)
    `);
    this._transcriptAll = this.db.prepare('SELECT id, channel_id, channel_name, user_id, claimed_by, priority, created_at FROM ticket_transcripts ORDER BY id DESC LIMIT 100');
    this._transcriptGet = this.db.prepare('SELECT * FROM ticket_transcripts WHERE id = ?');

    this._getAntiNuke = this.db.prepare('SELECT * FROM antinuke_config WHERE guild_id = ?');
    this._setAntiNuke = this.db.prepare(`
      INSERT INTO antinuke_config (guild_id, whitelist_ids, threshold_channel, threshold_role, threshold_ban, threshold_role_update, window_ms, punishment, updated_at)
      VALUES (@guildId, @whitelistIds, @thresholdChannel, @thresholdRole, @thresholdBan, @thresholdRoleUpdate, @windowMs, @punishment, @updatedAt)
      ON CONFLICT(guild_id) DO UPDATE SET
        whitelist_ids = excluded.whitelist_ids,
        threshold_channel = excluded.threshold_channel,
        threshold_role = excluded.threshold_role,
        threshold_ban = excluded.threshold_ban,
        threshold_role_update = excluded.threshold_role_update,
        window_ms = excluded.window_ms,
        punishment = excluded.punishment,
        updated_at = excluded.updated_at
    `);

    this._logCounter = 0;
  }

  loadCommands() { return Object.fromEntries(this._allCmds.all().map(r => [r.name, r.response])); }
  getCommand(name) { return this._getCmd.get(name)?.response ?? null; }
  saveCommand(name, response) { this._upsertCmd.run(name, response, new Date().toISOString()); }
  deleteCommand(name) { return this._delCmd.run(name).changes > 0; }

  saveLog(entry) {
    try {
      this._insertLog.run({
        type: entry.type || 'N/A',
        targetId: entry.targetId || null, target: entry.target || null,
        moderator: entry.moderator || null, reason: entry.reason || null,
        duration: entry.duration || null, channel: entry.channel || null,
        timestamp: new Date().toISOString()
      });
      if (++this._logCounter % 100 === 0) this._trimLogs.run();
    } catch (err) { console.error('❌ saveLog error:', err); }
  }
  getLogsForUser(userId) { return this._logsByTarget.all(userId); }
  getAllLogs(limit = 500) { return this.db.prepare('SELECT * FROM mod_logs ORDER BY id DESC LIMIT ?').all(limit); }
  getStats() {
    return { total: this._countLogs.get().c, byType: this._countByType.all(), blacklist: this._blCount.get().c };
  }

  isBlacklisted(userId) { return !!this._blGet.get(userId); }
  getBlacklistEntry(userId) { return this._blGet.get(userId) || null; }
  getAllBlacklist() { return this._blAll.all(); }
  addToBlacklist(userId, username, reason, moderatorId, moderatorTag) {
    if (this.isBlacklisted(userId)) return false;
    this._blInsert.run({ userId, username, reason, moderatorId, moderatorTag, addedAt: new Date().toISOString() });
    return true;
  }
  removeFromBlacklist(userId) { return this._blDelete.run(userId).changes > 0; }

  getGuildConfig(guildId) {
    return this._getConfig.get(guildId) || { guild_id: guildId, autorole_id: null, log_channel_id: null };
  }
  setAutorole(guildId, roleId) {
    const current = this.getGuildConfig(guildId);
    this._upsertConfig.run({ guildId, autoroleId: roleId, logChannelId: current.log_channel_id, updatedAt: new Date().toISOString() });
  }
  clearAutorole(guildId) {
    const current = this.getGuildConfig(guildId);
    this._upsertConfig.run({ guildId, autoroleId: null, logChannelId: current.log_channel_id, updatedAt: new Date().toISOString() });
  }
  setLogChannel(guildId, channelId) {
    const current = this.getGuildConfig(guildId);
    this._upsertConfig.run({ guildId, autoroleId: current.autorole_id, logChannelId: channelId, updatedAt: new Date().toISOString() });
  }
  clearLogChannel(guildId) {
    const current = this.getGuildConfig(guildId);
    this._upsertConfig.run({ guildId, autoroleId: current.autorole_id, logChannelId: null, updatedAt: new Date().toISOString() });
  }

  addNote(guildId, userId, authorId, authorTag, content) {
    const res = this._insertNote.run({ guildId, userId, authorId, authorTag, content, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getNotesForUser(guildId, userId) { return this._notesForUser.all(guildId, userId); }
  getNote(guildId, noteId) { return this._getNote.get(noteId, guildId) || null; }
  deleteNote(guildId, noteId) { return this._deleteNote.run(noteId, guildId).changes > 0; }
  countNotes(guildId) { return this._countNotes.get(guildId).c; }
  getAllNotes() { return this.db.prepare('SELECT * FROM member_notes ORDER BY id DESC LIMIT 500').all(); }
  deleteNoteById(id) { return this.db.prepare('DELETE FROM member_notes WHERE id = ?').run(id).changes > 0; }

  getWelcomeConfig(guildId) { return this._getWelcome.get(guildId) || null; }
  setWelcomeConfig(guildId, { channelId, message, embedEnabled }) {
    this._setWelcome.run({
      guildId, channelId: channelId || null, message: message || null,
      embedEnabled: (embedEnabled === undefined) ? null : (embedEnabled === false ? 0 : 1),
      updatedAt: new Date().toISOString()
    });
  }
  disableWelcome(guildId) { return this._disableWelcome.run(new Date().toISOString(), guildId).changes > 0; }
  setWelcomeChannel(guildId, channelId) {
    const current = this.getWelcomeConfig(guildId);
    this.setWelcomeConfig(guildId, { channelId, message: current?.message ?? null, embedEnabled: current?.embed_enabled });
  }
  setWelcomeMessage(guildId, message) {
    const current = this.getWelcomeConfig(guildId);
    this.setWelcomeConfig(guildId, { channelId: current?.channel_id ?? null, message, embedEnabled: current?.embed_enabled });
  }

  addReactionRole(guildId, messageId, channelId, emoji, roleId) {
    this._rrInsert.run({ guildId, messageId, channelId, emoji, roleId, createdAt: new Date().toISOString() });
  }
  getReactionRolesForMessage(guildId, messageId) { return this._rrByMessage.all(guildId, messageId); }
  getReactionRoleByEmoji(guildId, messageId, emoji) { return this._rrByEmoji.get(guildId, messageId, emoji) || null; }
  deleteReactionRole(guildId, id) { return this._rrDelete.run(id, guildId).changes > 0; }
  deleteReactionRolesForMessage(guildId, messageId) { return this._rrDeleteByMessage.run(guildId, messageId).changes > 0; }

  addAutoresponse(guildId, trigger, response) {
    this._arInsert.run({ guildId, trigger: trigger.toLowerCase(), response, createdAt: new Date().toISOString() });
  }
  getAllAutoresponses(guildId) { return this._arAll.all(guildId); }
  getAutoresponseByTrigger(guildId, trigger) { return this._arByTrigger.get(guildId, trigger.toLowerCase()) || null; }
  deleteAutoresponse(guildId, id) { return this._arDelete.run(id, guildId).changes > 0; }

  setBirthday(userId, guildId, day, month, year) {
    this._bdSet.run({ userId, guildId, day, month, year: year || null, updatedAt: new Date().toISOString() });
  }
  getBirthday(userId, guildId) { return this._bdGet.get(userId, guildId) || null; }
  getBirthdaysToday(guildId, day, month) { return this._bdToday.all(guildId, day, month); }
  getAllBirthdays(guildId) { return this._bdAll.all(guildId); }
  deleteBirthday(userId, guildId) { return this._bdDelete.run(userId, guildId).changes > 0; }

  addReminder(userId, guildId, channelId, content, remindAt) {
    const res = this._remInsert.run({ userId, guildId, channelId, content, remindAt: remindAt.toISOString(), createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getDueReminders(now = new Date()) { return this._remDue.all(now.toISOString()); }
  deleteReminder(id) { return this._remDelete.run(id).changes > 0; }
  getRemindersForUser(userId, guildId) { return this._remByUser.all(userId, guildId); }

  addPersonalNote(userId, guildId, content) {
    const res = this._pnInsert.run({ userId, guildId, content, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getPersonalNotes(userId, guildId) { return this._pnByUser.all(userId, guildId); }
  deletePersonalNote(id, userId) { return this._pnDelete.run(id, userId).changes > 0; }

  addCase(guildId, userId, moderatorId, action, reason, duration) {
    const now = new Date().toISOString();
    const res = this._caseInsert.run({ guildId, userId, moderatorId, action, reason, duration, now });
    return res.lastInsertRowid;
  }
  getCase(guildId, id) { return this._caseGet.get(id, guildId) || null; }
  getCasesForUser(guildId, userId) { return this._caseByUser.all(guildId, userId); }
  updateCase(guildId, id, { reason, status }) {
    this._caseUpdate.run({ id, guildId, reason: reason || null, status: status || null, now: new Date().toISOString() });
  }
  deleteCase(guildId, id) { return this._caseDelete.run(id, guildId).changes > 0; }

  addReport(guildId, reporterId, targetId, reason) {
    const res = this._repInsert.run({ guildId, reporterId, targetId, reason, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getOpenReports(guildId) { return this._repAllOpen.all(guildId); }
  setReportStatus(guildId, id, status) { return this._repSetStatus.run(status, id, guildId).changes > 0; }

  saveDashboardAccess(userId, username, ip, userAgent) {
    try {
      this._dashLogInsert.run({ userId, username, ip, userAgent, timestamp: new Date().toISOString() });
    } catch (err) { console.error('saveDashboardAccess', err); }
  }
  getDashboardAccessLogs() { return this._dashLogAll.all(); }

  saveTranscript(channelId, channelName, userId, claimedBy, priority, htmlContent) {
    this._transcriptInsert.run({
      channelId, channelName, userId, claimedBy, priority, htmlContent,
      createdAt: new Date().toISOString()
    });
  }
  getAllTranscripts() { return this._transcriptAll.all(); }
  getTranscript(id) { return this._transcriptGet.get(id) || null; }

  getAntiNukeConfig(guildId) {
    return this._getAntiNuke.get(guildId) || {
      guild_id: guildId,
      whitelist_ids: '',
      threshold_channel: 1,
      threshold_role: 1,
      threshold_ban: 3,
      threshold_role_update: 1,
      window_ms: 10000,
      punishment: 'quarantine'
    };
  }
  setAntiNukeConfig(guildId, config) {
    this._setAntiNuke.run({
      guildId,
      whitelistIds: config.whitelist_ids || '',
      thresholdChannel: config.threshold_channel ?? 3,
      thresholdRole: config.threshold_role ?? 3,
      thresholdBan: config.threshold_ban ?? 3,
      thresholdRoleUpdate: config.threshold_role_update ?? 3,
      windowMs: config.window_ms ?? 10000,
      punishment: config.punishment || 'quarantine',
      updatedAt: new Date().toISOString()
    });
  }

  close() {
    try { if (this.db && this.db.open) this.db.close(); }
    catch (err) { console.error('❌ close error:', err); }
  }
}

module.exports = StorageService;
