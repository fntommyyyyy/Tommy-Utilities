const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

class StorageService {
  constructor(dbPath) {
    let finalPath;
    if (dbPath) {
      finalPath = path.isAbsolute(dbPath)
        ? dbPath
        : path.join(__dirname, dbPath);
    } else {
      finalPath = path.join(__dirname, 'data', 'bot.db');
    }

    const dir = path.dirname(finalPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.dbPath = finalPath;
    this.db = new Database(finalPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000'); // FIX: evita SQLITE_BUSY con accessi concorrenti
    this._migrate();
    this._prepare();

    try { this._trimLogs.run(); } catch {}
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

      CREATE TABLE IF NOT EXISTS dashboard_access (
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
      CREATE INDEX IF NOT EXISTS idx_tr_channel ON ticket_transcripts(channel_id);

      CREATE TABLE IF NOT EXISTS ticket_meta (
        channel_id TEXT PRIMARY KEY,
        claimed_by_id TEXT,
        claimed_by_tag TEXT,
        priority TEXT,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS antinuke_config (
        guild_id TEXT PRIMARY KEY,
        threshold_channel INTEGER DEFAULT 3,
        threshold_role INTEGER DEFAULT 3,
        threshold_ban INTEGER DEFAULT 3,
        threshold_role_update INTEGER DEFAULT 3,
        window_ms INTEGER DEFAULT 10000,
        punishment TEXT DEFAULT 'quarantine',
        whitelist_ids TEXT DEFAULT '',
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS quarantine_roles (
        user_id TEXT NOT NULL,
        guild_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (user_id, guild_id, role_id)
      );
    `);
  }

  _prepare() {
    // ===== CUSTOM COMMANDS =====
    this._allCmds = this.db.prepare('SELECT name, response FROM custom_commands');
    this._getCmd = this.db.prepare('SELECT response FROM custom_commands WHERE name = ?');
    this._upsertCmd = this.db.prepare(`
      INSERT INTO custom_commands (name, response, created_at)
      VALUES (?, ?, ?)
      ON CONFLICT(name) DO UPDATE SET response = excluded.response
    `);
    this._delCmd = this.db.prepare('DELETE FROM custom_commands WHERE name = ?');

    // ===== MOD LOGS =====
    this._insertLog = this.db.prepare(`
      INSERT INTO mod_logs (type, target_id, target, moderator, reason, duration, channel, timestamp)
      VALUES (@type, @targetId, @target, @moderator, @reason, @duration, @channel, @timestamp)
    `);
    this._logsByTarget = this.db.prepare('SELECT * FROM mod_logs WHERE target_id = ? ORDER BY id DESC');
    this._allLogs = this.db.prepare('SELECT * FROM mod_logs ORDER BY id DESC LIMIT ?');
    this._countLogs = this.db.prepare('SELECT COUNT(*) as c FROM mod_logs');
    this._countByType = this.db.prepare('SELECT type, COUNT(*) as c FROM mod_logs GROUP BY type');
    this._trimLogs = this.db.prepare(`
      DELETE FROM mod_logs WHERE id NOT IN (
        SELECT id FROM mod_logs ORDER BY id DESC LIMIT 5000
      )
    `);

    // ===== BLACKLIST =====
    this._blGet = this.db.prepare('SELECT * FROM blacklist WHERE user_id = ?');
    this._blAll = this.db.prepare('SELECT * FROM blacklist ORDER BY added_at DESC');
    this._blInsert = this.db.prepare(`
      INSERT INTO blacklist (user_id, username, reason, moderator_id, moderator_tag, added_at)
      VALUES (@userId, @username, @reason, @moderatorId, @moderatorTag, @addedAt)
    `);
    this._blDelete = this.db.prepare('DELETE FROM blacklist WHERE user_id = ?');
    this._blCount = this.db.prepare('SELECT COUNT(*) as c FROM blacklist');

    // ===== GUILD CONFIG =====
    this._getConfig = this.db.prepare('SELECT * FROM guild_config WHERE guild_id = ?');
    this._upsertConfig = this.db.prepare(`
      INSERT INTO guild_config (guild_id, autorole_id, log_channel_id, updated_at)
      VALUES (@guildId, @autoroleId, @logChannelId, @updatedAt)
      ON CONFLICT(guild_id) DO UPDATE SET
        autorole_id = excluded.autorole_id,
        log_channel_id = excluded.log_channel_id,
        updated_at = excluded.updated_at
    `);

    // ===== MEMBER NOTES =====
    this._insertNote = this.db.prepare(`
      INSERT INTO member_notes (guild_id, user_id, author_id, author_tag, content, created_at)
      VALUES (@guildId, @userId, @authorId, @authorTag, @content, @createdAt)
    `);
    this._notesForUser = this.db.prepare('SELECT * FROM member_notes WHERE guild_id = ? AND user_id = ? ORDER BY id DESC');
    this._allNotes = this.db.prepare('SELECT * FROM member_notes ORDER BY id DESC LIMIT 500');
    this._getNote = this.db.prepare('SELECT * FROM member_notes WHERE id = ? AND guild_id = ?');
    this._deleteNote = this.db.prepare('DELETE FROM member_notes WHERE id = ? AND guild_id = ?');
    this._deleteNoteById = this.db.prepare('DELETE FROM member_notes WHERE id = ?');
    this._countNotes = this.db.prepare('SELECT COUNT(*) as c FROM member_notes WHERE guild_id = ?');

    // ===== WELCOME =====
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
    this._clearWelcomeMessage = this.db.prepare(
      'UPDATE welcome_config SET message = NULL, updated_at = ? WHERE guild_id = ?'
    );

    // ===== REACTION ROLES =====
    this._rrInsert = this.db.prepare(`
      INSERT INTO reaction_roles (guild_id, message_id, channel_id, emoji, role_id, created_at)
      VALUES (@guildId, @messageId, @channelId, @emoji, @roleId, @createdAt)
    `);
    this._rrByMessage = this.db.prepare('SELECT * FROM reaction_roles WHERE guild_id = ? AND message_id = ?');
    this._rrByEmoji = this.db.prepare('SELECT * FROM reaction_roles WHERE guild_id = ? AND message_id = ? AND emoji = ?');
    this._rrDelete = this.db.prepare('DELETE FROM reaction_roles WHERE id = ? AND guild_id = ?');
    this._rrDeleteByMessage = this.db.prepare('DELETE FROM reaction_roles WHERE guild_id = ? AND message_id = ?');

    // ===== AUTORESPONSES =====
    this._arInsert = this.db.prepare(`
      INSERT INTO autoresponses (guild_id, trigger, response, created_at)
      VALUES (@guildId, @trigger, @response, @createdAt)
    `);
    this._arAll = this.db.prepare('SELECT * FROM autoresponses WHERE guild_id = ? ORDER BY id DESC');
    this._arByTrigger = this.db.prepare('SELECT * FROM autoresponses WHERE guild_id = ? AND trigger = ?');
    this._arDelete = this.db.prepare('DELETE FROM autoresponses WHERE id = ? AND guild_id = ?');

    // ===== BIRTHDAYS =====
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

    // ===== REMINDERS =====
    this._remInsert = this.db.prepare(`
      INSERT INTO reminders (user_id, guild_id, channel_id, content, remind_at, created_at)
      VALUES (@userId, @guildId, @channelId, @content, @remindAt, @createdAt)
    `);
    this._remDue = this.db.prepare('SELECT * FROM reminders WHERE remind_at <= ? ORDER BY remind_at ASC LIMIT 100');
    this._remAll = this.db.prepare('SELECT * FROM reminders ORDER BY remind_at DESC LIMIT ?');
    this._remDelete = this.db.prepare('DELETE FROM reminders WHERE id = ?');
    this._remByUser = this.db.prepare('SELECT * FROM reminders WHERE user_id = ? AND guild_id = ? ORDER BY remind_at ASC');
    this._remCount = this.db.prepare('SELECT COUNT(*) as c FROM reminders');

    // ===== PERSONAL NOTES =====
    this._pnInsert = this.db.prepare(`
      INSERT INTO personal_notes (user_id, guild_id, content, created_at)
      VALUES (@userId, @guildId, @content, @createdAt)
    `);
    this._pnByUser = this.db.prepare('SELECT * FROM personal_notes WHERE user_id = ? AND guild_id = ? ORDER BY id DESC');
    this._pnDelete = this.db.prepare('DELETE FROM personal_notes WHERE id = ? AND user_id = ?');

    // ===== CASES =====
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

    // ===== REPORTS =====
    this._repInsert = this.db.prepare(`
      INSERT INTO reports (guild_id, reporter_id, target_id, reason, status, created_at)
      VALUES (@guildId, @reporterId, @targetId, @reason, 'open', @createdAt)
    `);
    this._repAllOpen = this.db.prepare("SELECT * FROM reports WHERE guild_id = ? AND status = 'open' ORDER BY id DESC");
    this._repSetStatus = this.db.prepare('UPDATE reports SET status = ? WHERE id = ? AND guild_id = ?');

    // ===== DASHBOARD ACCESS =====
    this._saveAccess = this.db.prepare(`
      INSERT INTO dashboard_access (user_id, username, ip, user_agent, timestamp)
      VALUES (?, ?, ?, ?, ?)
    `);
    this._getAccess = this.db.prepare('SELECT * FROM dashboard_access ORDER BY id DESC LIMIT ?');

    // ===== TICKET TRANSCRIPTS =====
    this._trInsert = this.db.prepare(`
      INSERT INTO ticket_transcripts (channel_id, channel_name, user_id, claimed_by, priority, html_content, created_at)
      VALUES (@channelId, @channelName, @userId, @claimedBy, @priority, @html, @createdAt)
    `);
    this._trAll = this.db.prepare('SELECT id, channel_id, channel_name, user_id, claimed_by, priority, created_at FROM ticket_transcripts ORDER BY id DESC LIMIT 100');
    this._trGet = this.db.prepare('SELECT * FROM ticket_transcripts WHERE id = ?');
    this._trCount = this.db.prepare('SELECT COUNT(*) as c FROM ticket_transcripts');

    // ===== TICKET META =====
    this._tmGet = this.db.prepare('SELECT * FROM ticket_meta WHERE channel_id = ?');
    this._tmUpsert = this.db.prepare(`
      INSERT INTO ticket_meta (channel_id, claimed_by_id, claimed_by_tag, priority, updated_at)
      VALUES (@channelId, @claimedById, @claimedByTag, @priority, @updatedAt)
      ON CONFLICT(channel_id) DO UPDATE SET
        claimed_by_id = COALESCE(@claimedById, claimed_by_id),
        claimed_by_tag = COALESCE(@claimedByTag, claimed_by_tag),
        priority = COALESCE(@priority, priority),
        updated_at = @updatedAt
    `);

    // ===== ANTI-NUKE =====
    this._getAntiNuke = this.db.prepare('SELECT * FROM antinuke_config WHERE guild_id = ?');
    this._upsertAntiNuke = this.db.prepare(`
      INSERT INTO antinuke_config
        (guild_id, threshold_channel, threshold_role, threshold_ban, threshold_role_update, window_ms, punishment, whitelist_ids, updated_at)
      VALUES
        (@guildId, @threshold_channel, @threshold_role, @threshold_ban, @threshold_role_update, @window_ms, @punishment, @whitelist_ids, @updatedAt)
      ON CONFLICT(guild_id) DO UPDATE SET
        threshold_channel = excluded.threshold_channel,
        threshold_role = excluded.threshold_role,
        threshold_ban = excluded.threshold_ban,
        threshold_role_update = excluded.threshold_role_update,
        window_ms = excluded.window_ms,
        punishment = excluded.punishment,
        whitelist_ids = excluded.whitelist_ids,
        updated_at = excluded.updated_at
    `);

    // ===== QUARANTINE ROLES =====
    this._qrDel = this.db.prepare('DELETE FROM quarantine_roles WHERE user_id = ? AND guild_id = ?');
    this._qrIns = this.db.prepare('INSERT INTO quarantine_roles (user_id, guild_id, role_id) VALUES (?, ?, ?)');
    this._qrGet = this.db.prepare('SELECT role_id FROM quarantine_roles WHERE user_id = ? AND guild_id = ?');

    this._logCounter = 0;
  }

  // ==================== CUSTOM COMMANDS ====================
  loadCommands() { return Object.fromEntries(this._allCmds.all().map(r => [r.name, r.response])); }
  getCommand(name) { return this._getCmd.get(name)?.response ?? null; }
  saveCommand(name, response) { this._upsertCmd.run(name, response, new Date().toISOString()); }
  deleteCommand(name) { return this._delCmd.run(name).changes > 0; }

  // ==================== MOD LOGS ====================
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
  getAllLogs(limit = 500) { return this._allLogs.all(limit); }
  getStats() {
    return { total: this._countLogs.get().c, byType: this._countByType.all(), blacklist: this._blCount.get().c };
  }

  // ==================== BLACKLIST ====================
  isBlacklisted(userId) { return !!this._blGet.get(userId); }
  getBlacklistEntry(userId) { return this._blGet.get(userId) || null; }
  getAllBlacklist() { return this._blAll.all(); }
  addToBlacklist(userId, username, reason, moderatorId, moderatorTag) {
    if (this.isBlacklisted(userId)) return false;
    this._blInsert.run({ userId, username, reason, moderatorId, moderatorTag, addedAt: new Date().toISOString() });
    return true;
  }
  removeFromBlacklist(userId) { return this._blDelete.run(userId).changes > 0; }

  // ==================== GUILD CONFIG ====================
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

  // ==================== NOTES ====================
  addNote(guildId, userId, authorId, authorTag, content) {
    const res = this._insertNote.run({ guildId, userId, authorId, authorTag, content, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getNotesForUser(guildId, userId) { return this._notesForUser.all(guildId, userId); }
  getNote(guildId, noteId) { return this._getNote.get(noteId, guildId) || null; }
  deleteNote(guildId, noteId) { return this._deleteNote.run(noteId, guildId).changes > 0; }
  deleteNoteById(noteId) { return this._deleteNoteById.run(noteId).changes > 0; }
  countNotes(guildId) { return this._countNotes.get(guildId).c; }
  getAllNotes() { return this._allNotes.all(); }

  // ==================== WELCOME ====================
  getWelcomeConfig(guildId) { return this._getWelcome.get(guildId) || null; }
  setWelcomeConfig(guildId, { channelId, message, embedEnabled }) {
    this._setWelcome.run({
      guildId, channelId: channelId || null, message: message || null,
      embedEnabled: (embedEnabled === undefined) ? null : (embedEnabled === false ? 0 : 1),
      updatedAt: new Date().toISOString()
    });
  }
  disableWelcome(guildId) { return this._disableWelcome.run(new Date().toISOString(), guildId).changes > 0; }
  clearWelcomeMessage(guildId) { return this._clearWelcomeMessage.run(new Date().toISOString(), guildId).changes > 0; }
  setWelcomeChannel(guildId, channelId) {
    const current = this.getWelcomeConfig(guildId);
    this.setWelcomeConfig(guildId, { channelId, message: current?.message ?? null, embedEnabled: current?.embed_enabled });
  }
  setWelcomeMessage(guildId, message) {
    const current = this.getWelcomeConfig(guildId);
    this.setWelcomeConfig(guildId, { channelId: current?.channel_id ?? null, message, embedEnabled: current?.embed_enabled });
  }

  // ==================== REACTION ROLES ====================
  addReactionRole(guildId, messageId, channelId, emoji, roleId) {
    this._rrInsert.run({ guildId, messageId, channelId, emoji, roleId, createdAt: new Date().toISOString() });
  }
  getReactionRolesForMessage(guildId, messageId) { return this._rrByMessage.all(guildId, messageId); }
  getReactionRoleByEmoji(guildId, messageId, emoji) { return this._rrByEmoji.get(guildId, messageId, emoji) || null; }
  deleteReactionRole(guildId, id) { return this._rrDelete.run(id, guildId).changes > 0; }
  deleteReactionRolesForMessage(guildId, messageId) { return this._rrDeleteByMessage.run(guildId, messageId).changes > 0; }

  // ==================== AUTORESPONSES ====================
  addAutoresponse(guildId, trigger, response) {
    this._arInsert.run({ guildId, trigger: trigger.toLowerCase(), response, createdAt: new Date().toISOString() });
  }
  getAllAutoresponses(guildId) { return this._arAll.all(guildId); }
  getAutoresponseByTrigger(guildId, trigger) { return this._arByTrigger.get(guildId, trigger.toLowerCase()) || null; }
  deleteAutoresponse(guildId, id) { return this._arDelete.run(id, guildId).changes > 0; }

  // ==================== BIRTHDAYS ====================
  setBirthday(userId, guildId, day, month, year) {
    this._bdSet.run({ userId, guildId, day, month, year: year || null, updatedAt: new Date().toISOString() });
  }
  getBirthday(userId, guildId) { return this._bdGet.get(userId, guildId) || null; }
  getBirthdaysToday(guildId, day, month) { return this._bdToday.all(guildId, day, month); }
  getAllBirthdays(guildId) { return this._bdAll.all(guildId); }
  deleteBirthday(userId, guildId) { return this._bdDelete.run(userId, guildId).changes > 0; }

  // ==================== REMINDERS ====================
  addReminder(userId, guildId, channelId, content, remindAt) {
    const res = this._remInsert.run({ userId, guildId, channelId, content, remindAt: remindAt.toISOString(), createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getDueReminders(now = new Date()) { return this._remDue.all(now.toISOString()); }
  getAllReminders(limit = 200) { return this._remAll.all(limit); }
  countReminders() { return this._remCount.get().c; }
  deleteReminder(id) { return this._remDelete.run(id).changes > 0; }
  getRemindersForUser(userId, guildId) { return this._remByUser.all(userId, guildId); }

  // ==================== PERSONAL NOTES ====================
  addPersonalNote(userId, guildId, content) {
    const res = this._pnInsert.run({ userId, guildId, content, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getPersonalNotes(userId, guildId) { return this._pnByUser.all(userId, guildId); }
  deletePersonalNote(id, userId) { return this._pnDelete.run(id, userId).changes > 0; }

  // ==================== CASES ====================
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

  // ==================== REPORTS ====================
  addReport(guildId, reporterId, targetId, reason) {
    const res = this._repInsert.run({ guildId, reporterId, targetId, reason, createdAt: new Date().toISOString() });
    return res.lastInsertRowid;
  }
  getOpenReports(guildId) { return this._repAllOpen.all(guildId); }
  setReportStatus(guildId, id, status) { return this._repSetStatus.run(status, id, guildId).changes > 0; }

  // ==================== DASHBOARD ACCESS ====================
  saveDashboardAccess(userId, username, ip, userAgent) {
    this._saveAccess.run(userId, username, ip || null, userAgent || null, new Date().toISOString());
  }
  getDashboardAccessLogs(limit = 500) { return this._getAccess.all(limit); }

  // ==================== TICKET TRANSCRIPTS ====================
  saveTranscript(channelId, channelName, userId, claimedBy, priority, html) {
    const res = this._trInsert.run({
      channelId, channelName, userId,
      claimedBy: claimedBy || null,
      priority: priority || null,
      html,
      createdAt: new Date().toISOString()
    });
    return res.lastInsertRowid;
  }
  getAllTranscripts() { return this._trAll.all(); }
  getTranscript(id) { return this._trGet.get(id) || null; }
  countTranscripts() { return this._trCount.get().c; }

  // ==================== TICKET META ====================
  getTicketMeta(channelId) { return this._tmGet.get(channelId) || null; }
  setTicketMeta(channelId, { claimedById, claimedByTag, priority }) {
    this._tmUpsert.run({
      channelId,
      claimedById: claimedById ?? null,
      claimedByTag: claimedByTag ?? null,
      priority: priority ?? null,
      updatedAt: new Date().toISOString()
    });
  }

  // ==================== ANTI-NUKE ====================
  getAntiNukeConfig(guildId) {
    const row = this._getAntiNuke.get(guildId);
    const defaults = {
      threshold_channel: 3,
      threshold_role: 3,
      threshold_ban: 3,
      threshold_role_update: 3,
      window_ms: 10000,
      punishment: 'quarantine',
      whitelist_ids: ''
    };
    if (!row) return defaults;
    return {
      threshold_channel: row.threshold_channel ?? defaults.threshold_channel,
      threshold_role: row.threshold_role ?? defaults.threshold_role,
      threshold_ban: row.threshold_ban ?? defaults.threshold_ban,
      threshold_role_update: row.threshold_role_update ?? defaults.threshold_role_update,
      window_ms: row.window_ms ?? defaults.window_ms,
      punishment: row.punishment ?? defaults.punishment,
      whitelist_ids: row.whitelist_ids ?? defaults.whitelist_ids
    };
  }
  setAntiNukeConfig(guildId, data = {}) {
    const current = this.getAntiNukeConfig(guildId);
    this._upsertAntiNuke.run({
      guildId,
      threshold_channel: data.threshold_channel ?? current.threshold_channel,
      threshold_role: data.threshold_role ?? current.threshold_role,
      threshold_ban: data.threshold_ban ?? current.threshold_ban,
      threshold_role_update: data.threshold_role_update ?? current.threshold_role_update,
      window_ms: data.window_ms ?? current.window_ms,
      punishment: data.punishment ?? current.punishment,
      whitelist_ids: data.whitelist_ids ?? current.whitelist_ids,
      updatedAt: new Date().toISOString()
    });
  }

  // ==================== QUARANTINE ====================
  saveQuarantineRoles(userId, guildId, roleIds) {
    const tx = this.db.transaction((roles) => {
      this._qrDel.run(userId, guildId);
      for (const r of roles) this._qrIns.run(userId, guildId, r);
    });
    tx(roleIds);
  }

  getQuarantineRoles(userId, guildId) {
    return this._qrGet.all(userId, guildId).map(r => r.role_id);
  }

  clearQuarantineRoles(userId, guildId) {
    this._qrDel.run(userId, guildId);
  }

  // ==================== CLOSE ====================
  close() {
    try { if (this.db && this.db.open) this.db.close(); }
    catch (err) { console.error('❌ close error:', err); }
  }
}

module.exports = StorageService;
