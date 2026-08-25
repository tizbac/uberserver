package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// sqlitePath converts a SQLAlchemy sqlite URL to a path for the modernc
// sqlite driver:
//
//	sqlite:///server.db   -> server.db
//	sqlite:////abs.db     -> /abs.db
//	sqlite:///:memory:    -> :memory:
func sqlitePath(url string) string {
	p := strings.TrimPrefix(url, "sqlite://")
	if strings.HasPrefix(p, "//") {
		return p[1:]
	}
	return strings.TrimPrefix(p, "/")
}

// openDB mirrors session_manager in SQLUsers.py (PRAGMAs, create_all,
// single serialized connection).
//
// The foreign_keys pragma is deliberately left OFF, matching python's
// pysqlite under sqlalchemy 1.3: ON DELETE actions are not applied at the
// db level there, so the ORM-side cascades are ported as explicit deletes
// (see removeUser) instead of relying on them.
//
// Datetimes: python stored naive local wall-clock strings. The driver
// parses those as UTC, so rows written by the python server come back
// shifted by the local UTC offset. The shift is bounded by a couple of
// hours and only affects day-scale thresholds, so it is negligible; rows
// written by this server round-trip as exact instants.
func openDB(url string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqlitePath(url))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode = MEMORY"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA synchronous = OFF"); err != nil {
		db.Close()
		return nil, err
	}
	if err := createTablesIfNotExist(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// createTablesIfNotExist mirrors Base.metadata.create_all in
// SQLUsers.py, so a fresh db ends up with the same schema.
func createTablesIfNotExist(db *sql.DB) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER NOT NULL,
			username VARCHAR(40),
			password VARCHAR(256),
			register_date DATETIME,
			last_login DATETIME,
			last_ip VARCHAR(15),
			last_agent VARCHAR(254),
			last_sys_id VARCHAR(16),
			last_mac_id VARCHAR(16),
			ingame_time INTEGER,
			access VARCHAR(32),
			email VARCHAR(254),
			bot INTEGER,
			PRIMARY KEY (id),
			CONSTRAINT unnamed UNIQUE (username),
			CONSTRAINT unnamed_1 UNIQUE (email)
		)`,
		`CREATE TABLE IF NOT EXISTS bridged_users (
			id INTEGER NOT NULL,
			external_id VARCHAR(20),
			location VARCHAR(20),
			external_username VARCHAR(20),
			last_bridged DATETIME,
			PRIMARY KEY (id),
			CONSTRAINT uix_bridged_users_1 UNIQUE (external_id, location),
			CONSTRAINT uix_bridged_users_2 UNIQUE (external_username, location)
		)`,
		`CREATE TABLE IF NOT EXISTS min_spring_version (
			id INTEGER NOT NULL,
			min_spring_version VARCHAR(128),
			start_time DATETIME,
			PRIMARY KEY (id)
		)`,
		`CREATE TABLE IF NOT EXISTS verifications (
			id INTEGER NOT NULL,
			user_id INTEGER,
			email VARCHAR(254),
			code INTEGER,
			expiry DATETIME,
			attempts INTEGER,
			resends INTEGER,
			reason TEXT,
			PRIMARY KEY (id),
			CONSTRAINT unnamed UNIQUE (email),
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS logins (
			id INTEGER NOT NULL,
			user_id INTEGER,
			ip_address VARCHAR(15),
			time DATETIME,
			agent VARCHAR(254),
			last_sys_id VARCHAR(16),
			last_mac_id VARCHAR(16),
			local_ip VARCHAR(15),
			country VARCHAR(2),
			"end" DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS renames (
			id INTEGER NOT NULL,
			user_id INTEGER,
			original VARCHAR(40),
			time DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS ignores (
			id INTEGER NOT NULL,
			user_id INTEGER,
			ignored_user_id INTEGER,
			reason VARCHAR(128),
			time DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY(ignored_user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS friends (
			id INTEGER NOT NULL,
			first_user_id INTEGER,
			second_user_id INTEGER,
			time DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(first_user_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY(second_user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS "friendRequests" (
			id INTEGER NOT NULL,
			user_id INTEGER,
			friend_user_id INTEGER,
			msg VARCHAR(128),
			time DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY(friend_user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channels (
			id INTEGER NOT NULL,
			name VARCHAR(40),
			"key" VARCHAR(32),
			owner_user_id INTEGER,
			topic TEXT,
			topic_user_id INTEGER,
			antispam BOOLEAN,
			censor BOOLEAN,
			store_history BOOLEAN,
			last_used DATETIME,
			PRIMARY KEY (id),
			CONSTRAINT unnamed UNIQUE (name),
			FOREIGN KEY(owner_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL,
			FOREIGN KEY(topic_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ban (
			id INTEGER NOT NULL,
			issuer_user_id INTEGER,
			user_id INTEGER,
			ip VARCHAR(60),
			email VARCHAR(254),
			reason TEXT,
			end_date DATETIME,
			PRIMARY KEY (id),
			FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL,
			FOREIGN KEY(user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS blacklisted_email_domains (
			id INTEGER NOT NULL,
			issuer_user_id INTEGER,
			domain VARCHAR(254),
			reason TEXT,
			start_time DATETIME,
			PRIMARY KEY (id),
			CONSTRAINT unnamed UNIQUE (domain),
			FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL
		)`,
		`CREATE TABLE IF NOT EXISTS channel_history (
			id INTEGER NOT NULL,
			channel_id INTEGER,
			user_id INTEGER,
			bridged_id INTEGER,
			time DATETIME,
			msg TEXT,
			ex_msg BOOLEAN,
			PRIMARY KEY (id),
			FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
			FOREIGN KEY(bridged_id) REFERENCES bridged_users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channel_ops (
			id INTEGER NOT NULL,
			channel_id INTEGER,
			user_id INTEGER,
			PRIMARY KEY (id),
			FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channel_bans (
			id INTEGER NOT NULL,
			channel_id INTEGER,
			issuer_user_id INTEGER,
			user_id INTEGER,
			ip_address VARCHAR(15),
			expires DATETIME,
			reason TEXT,
			PRIMARY KEY (id),
			FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL,
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channel_bridged_bans (
			id INTEGER NOT NULL,
			channel_id INTEGER,
			issuer_user_id INTEGER,
			bridged_id INTEGER,
			expires DATETIME,
			reason TEXT,
			PRIMARY KEY (id),
			FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL,
			FOREIGN KEY(bridged_id) REFERENCES bridged_users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channel_mutes (
			id INTEGER NOT NULL,
			channel_id INTEGER,
			issuer_user_id INTEGER,
			user_id INTEGER,
			expires DATETIME,
			reason TEXT,
			PRIMARY KEY (id),
			FOREIGN KEY(channel_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON UPDATE CASCADE ON DELETE SET NULL,
			FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS channel_forwards (
			id INTEGER NOT NULL,
			channel_from_id INTEGER,
			channel_to_id INTEGER,
			PRIMARY KEY (id),
			UNIQUE (channel_from_id, channel_to_id),
			FOREIGN KEY(channel_from_id) REFERENCES channels (id) ON DELETE CASCADE,
			FOREIGN KEY(channel_to_id) REFERENCES channels (id) ON DELETE CASCADE
		)`,
	}
	for _, t := range tables {
		if _, err := db.Exec(t); err != nil {
			return err
		}
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

// toTime converts a scanned value to time.Time. The driver auto-parses
// DATETIME columns to time.Time; anything else (NULL) becomes zero time.
func toTime(v any) time.Time {
	if t, ok := v.(time.Time); ok {
		// the driver parses naive (no-offset) datetime strings as UTC; the
		// python server stores and compares them as local wall clock, so
		// reinterpret in the local zone
		return t.In(time.Local)
	}
	return time.Time{}
}

// pyTime formats t the way python's sqlite3 adapter stores naive datetimes:
// local wall clock, no timezone, fractional seconds only if non-zero.
func pyTime(t time.Time) string {
	return t.In(time.Local).Format("2006-01-02 15:04:05.999999")
}

// OfflineUser mirrors SQLUsers.OfflineClient: a user loaded from the db.
type OfflineUser struct {
	userID       int
	username     string
	Password     string
	LastLogin    time.Time
	RegisterDate time.Time
	lastIP       string
	LastAgent    string
	LastSysID    string
	LastMacID    string
	IngameTime   int
	access       string
	Email        string
	bot          int

	accessLevels map[string]bool
}

// channelUser interface (offline counterpart of the *Client methods).
func (u *OfflineUser) UserID() int      { return u.userID }
func (u *OfflineUser) Username() string { return u.username }
func (u *OfflineUser) LastIP() string   { return u.lastIP }

// calcAccess mirrors Protocol._calc_access (see clientFromUsernameDB).
func (u *OfflineUser) calcAccess() {
	u.accessLevels = calcAccessMap(u.access)
}

// userRef interface.
func (u *OfflineUser) Access() string              { return u.access }
func (u *OfflineUser) HasAccess(level string) bool { return u.accessLevels[level] }
func (u *OfflineUser) Bot() bool                   { return u.bot != 0 }

const userSelect = `SELECT id, username, password, last_login, register_date, last_ip, last_agent, last_sys_id, last_mac_id, ingame_time, access, email, bot FROM users`

func scanUser(row scanner) *OfflineUser {
	var u OfflineUser
	var lastLogin, registerDate, email any
	if err := row.Scan(&u.userID, &u.username, &u.Password, &lastLogin, &registerDate,
		&u.lastIP, &u.LastAgent, &u.LastSysID, &u.LastMacID, &u.IngameTime,
		&u.access, &email, &u.bot); err != nil {
		return nil
	}
	u.LastLogin = toTime(lastLogin)
	u.RegisterDate = toTime(registerDate)
	if e, ok := email.(string); ok {
		u.Email = e
	}
	return &u
}

// UserDB mirrors SQLUsers.UsersHandler.
type UserDB struct {
	db *sql.DB
}

// getClientFromID mirrors clientFromID.
func (d *UserDB) getClientFromID(id int) *OfflineUser {
	return scanUser(d.db.QueryRow(userSelect+` WHERE id = ?`, id))
}

// getClientFromUsername mirrors clientFromUsername.
func (d *UserDB) getClientFromUsername(username string) *OfflineUser {
	return scanUser(d.db.QueryRow(userSelect+` WHERE username = ?`, username))
}

// remainingBanStr mirrors UsersHandler.remaining_ban_str.
func remainingBanStr(dbban *BanEntry, now time.Time) string {
	timeleft := int(dbban.EndDate.Sub(now).Seconds())
	remaining := "less than one hour remaining"
	if timeleft > 60*60*24*900 {
		remaining = ""
	} else if timeleft > 60*60*24 {
		remaining = fmt.Sprintf("%d days remaining", timeleft/(60*60*24))
	} else if timeleft > 60*60 {
		remaining = fmt.Sprintf("%d hours remaining", timeleft/(60*60))
	}
	return remaining
}

// checkBanned mirrors check_banned.
func (d *UserDB) checkBanned(username, ip string) (bool, string) {
	dbuser := d.getClientFromUsername(username)
	if dbuser == nil {
		return false, ""
	}
	now := time.Now()
	dbban := server.banDB.checkBanAt(dbuser.userID, ip, dbuser.Email, now)
	if dbban != nil && dbuser.access != "admin" {
		reason := fmt.Sprintf("You are banned: (%s), ", dbban.Reason)
		reason += remainingBanStr(dbban, now)
		return true, reason
	}
	return false, ""
}

// checkLoginUser mirrors check_login_user. password is BASE64(MD5(...)).
func (d *UserDB) checkLoginUser(username, password string) (bool, string) {
	dbuser := d.getClientFromUsername(username)
	if dbuser == nil {
		return false, "Invalid username or password"
	}
	if dbuser.username != username {
		// user tried to login with wrong upper/lower case somewhere in their username
		return false, fmt.Sprintf("Invalid username -- did you mean '%s'", dbuser.username)
	}
	if !VerifyPassword(dbuser.Password, password) {
		return false, "Invalid username or password"
	}
	return true, ""
}

// loginUser mirrors login_user (the password arg is unused there too).
func (d *UserDB) loginUser(username, password, ip, agent, lastSysID, lastMacID, localIP, country string) *OfflineUser {
	now := time.Now()
	dbuser := d.getClientFromUsername(username)
	if dbuser == nil {
		return nil
	}
	d.db.Exec(`INSERT INTO logins (user_id, ip_address, time, agent, last_sys_id, last_mac_id, local_ip, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		dbuser.userID, ip, pyTime(now), agent, lastSysID, lastMacID, localIP, country)
	d.db.Exec(`UPDATE users SET last_ip = ?, last_agent = ?, last_sys_id = ?, last_mac_id = ?, last_login = ? WHERE id = ?`,
		ip, agent, lastSysID, lastMacID, pyTime(now), dbuser.userID)
	dbuser.lastIP = ip
	dbuser.LastAgent = agent
	dbuser.LastSysID = lastSysID
	dbuser.LastMacID = lastMacID
	dbuser.LastLogin = now
	return dbuser
}

// setUserPassword mirrors set_user_password.
func (d *UserDB) setUserPassword(username, password string) {
	hashed, err := HashPassword(password)
	if err != nil {
		return
	}
	d.db.Exec(`UPDATE users SET password = ? WHERE username = ?`, hashed, username)
}

// endSession mirrors end_session.
func (d *UserDB) endSession(userID int) {
	now := time.Now()
	var end any
	err := d.db.QueryRow(`SELECT "end" FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT 1`, userID).Scan(&end)
	if err != nil || toTime(end).IsZero() {
		return
	}
	d.db.Exec(`UPDATE logins SET "end" = ? WHERE id = (SELECT id FROM logins WHERE user_id = ? ORDER BY id DESC LIMIT 1)`, pyTime(now), userID)
	d.db.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, pyTime(now), userID)
}

// checkUserName mirrors check_user_name.
func (d *UserDB) checkUserName(name string) (bool, string) {
	if len(name) > 20 {
		return false, "Username too long"
	}
	if server.censor && !sayHooks.nastyWordCensor(name) {
		return false, "Name failed to pass profanity filter."
	}
	return true, ""
}

// checkRegisterUser mirrors check_register_user.
func (d *UserDB) checkRegisterUser(username, email, ip string) (bool, string) {
	ok, reason := d.checkUserName(username)
	if !ok {
		return ok, reason
	}
	if d.getClientFromUsername(username) != nil {
		return false, "Username is already in use."
	}
	if email != "" {
		_, good, _ := d.getUserIDWithEmail(email)
		if good {
			return false, "Email address is already in use."
		}
	}
	now := time.Now()
	dbban := server.banDB.checkBanAt(0, ip, "", now)
	if dbban != nil {
		return false, fmt.Sprintf("Account registration failed: %s", dbban.Reason)
	}
	return true, ""
}

// registerUser mirrors register_user. password is BASE64(MD5(...)).
// The python default access is "user" (set with the argon2 migration), so
// agreement is only enforced for the online session right after
// registering, not for the stored account.
func (d *UserDB) registerUser(username, password, ip, email, access string) (bool, string) {
	hashed, err := HashPassword(password)
	if err != nil {
		return false, err.Error()
	}
	if access == "" {
		access = "user"
	}
	now := time.Now()
	var emailArg any
	if email != "" {
		emailArg = email
	}
	if _, err := d.db.Exec(
		`INSERT INTO users (username, password, register_date, last_login, last_ip, last_agent, last_sys_id, last_mac_id, ingame_time, access, email, bot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)`,
		username, hashed, pyTime(now), pyTime(now), ip, "", "", "", access, emailArg); err != nil {
		return false, err.Error()
	}
	return true, "Account registered successfully."
}

// pyInt renders a bool the way python stores it in INTEGER columns.
func pyInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// saveUser mirrors save_user.
func (d *UserDB) saveUser(client *Client) {
	var email any
	if client.email != "" {
		email = client.email
	}
	d.db.Exec(`UPDATE users SET password = ?, ingame_time = ?, access = ?, bot = ?, last_sys_id = ?, last_mac_id = ?, email = ? WHERE username = ?`,
		client.password, client.ingameTime, client.access, pyInt(client.bot),
		client.lastSysID, client.lastMacID, email, client.username)
}

// saveUserDB mirrors save_user when the target is an offline db user (the
// python code constructs a temporary Client from the db and calls save_user).
func (d *UserDB) saveUserDB(u *OfflineUser) {
	var email any
	if u.Email != "" {
		email = u.Email
	}
	d.db.Exec(`UPDATE users SET password = ?, ingame_time = ?, access = ?, bot = ?, last_sys_id = ?, last_mac_id = ?, email = ? WHERE username = ?`,
		u.Password, u.IngameTime, u.access, u.bot,
		u.LastSysID, u.LastMacID, email, u.username)
}

// confirmAgreement mirrors confirm_agreement.
func (d *UserDB) confirmAgreement(client *Client) {
	d.db.Exec(`UPDATE users SET access = 'user' WHERE username = ?`, client.username)
}

// renameUser mirrors rename_user.
func (d *UserDB) renameUser(username, newname string) (bool, string) {
	if newname == username {
		return false, "You already have that username."
	}
	if d.getClientFromUsername(newname) != nil {
		return false, "Username already exists."
	}
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return false, "You don't seem to exist anymore. Contact an admin or moderator."
	}
	d.db.Exec(`INSERT INTO renames (user_id, original, time) VALUES (?, ?, ?)`, entry.userID, username, pyTime(time.Now()))
	d.db.Exec(`UPDATE users SET username = ? WHERE id = ?`, newname, entry.userID)
	return true, "Account renamed successfully."
}

// getUserIDWithEmail mirrors get_user_id_with_email. The python
// "pick oldest with a valid date" loop is dead code (typo db_user vs
// dbuser, and email is unique anyway); the first matching row is
// returned, as in python.
func (d *UserDB) getUserIDWithEmail(email string) (int, bool, string) {
	if email == "" {
		return 0, false, "Email address is blank"
	}
	var id int
	err := d.db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, fmt.Sprintf("No user with email address %s was found", email)
	}
	if err != nil {
		return 0, false, err.Error()
	}
	return id, true, ""
}

// getLastLogin mirrors get_lastlogin.
func (d *UserDB) getLastLogin(username string) (bool, time.Time) {
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return false, time.Time{}
	}
	return true, entry.LastLogin
}

// getRegistrationDate mirrors get_registration_date.
func (d *UserDB) getRegistrationDate(username string) (bool, time.Time) {
	entry := d.getClientFromUsername(username)
	if entry == nil || entry.RegisterDate.IsZero() {
		return false, time.Time{}
	}
	return true, entry.RegisterDate
}

// getIngameTime mirrors get_ingame_time.
func (d *UserDB) getIngameTime(username string) (bool, int) {
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return false, 0
	}
	return true, entry.IngameTime
}

// getAccountAccess mirrors get_account_access. The python code calls
// self.session (an AttributeError, the method is only sess()); this is
// the intended behavior.
func (d *UserDB) getAccountAccess(username string) (bool, string) {
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return false, "User not found in database"
	}
	return true, entry.access
}

// findIP mirrors find_ip.
func (d *UserDB) findIP(ip string) []*OfflineUser {
	rows, err := d.db.Query(userSelect+` WHERE last_ip = ?`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var users []*OfflineUser
	for rows.Next() {
		if u := scanUser(rows); u != nil {
			users = append(users, u)
		}
	}
	return users
}

// getIP mirrors get_ip.
func (d *UserDB) getIP(username string) *string {
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return nil
	}
	return &entry.lastIP
}

// listMods mirrors list_mods: names joined with a trailing space, admins first.
func (d *UserDB) listMods() (admins, mods string) {
	for _, access := range []string{"mod", "admin"} {
		rows, err := d.db.Query(`SELECT username FROM users WHERE access = ?`, access)
		if err != nil {
			continue
		}
		var list string
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				list += name + " "
			}
		}
		rows.Close()
		if access == "mod" {
			mods = list
		} else {
			admins = list
		}
	}
	return admins, mods
}

// removeUser mirrors remove_user. python's User mapper cascades
// delete-orphan onto logins, renames, ignores (as ignorer), friends and
// friend requests (both directions); the sqlite foreign_keys pragma is
// off, so those cascades are ported as explicit deletes. Everything
// else (verifications, ignores as ignored, bans, channels, ...) is left
// orphaned, as in python.
func (d *UserDB) removeUser(username string) (bool, string) {
	entry := d.getClientFromUsername(username)
	if entry == nil {
		return false, "User not found."
	}
	id := entry.userID
	d.db.Exec(`DELETE FROM logins WHERE user_id = ?`, id)
	d.db.Exec(`DELETE FROM renames WHERE user_id = ?`, id)
	d.db.Exec(`DELETE FROM ignores WHERE user_id = ?`, id)
	d.db.Exec(`DELETE FROM friends WHERE first_user_id = ? OR second_user_id = ?`, id, id)
	d.db.Exec(`DELETE FROM "friendRequests" WHERE user_id = ? OR friend_user_id = ?`, id, id)
	if _, err := d.db.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return false, err.Error()
	}
	return true, "Success."
}

// clean mirrors clean. The python query().delete() is a bulk sql delete
// with no cascades, so related rows are left orphaned as in python.
func (d *UserDB) clean() {
	now := time.Now()
	// users which didn't accept agreement after three days
	d.db.Exec(`DELETE FROM users WHERE register_date < ? AND access = 'agreement'`, pyTime(now.AddDate(0, 0, -3)))
	// users with no ingame time, last login > 1 month ago, not bot, not mod
	d.db.Exec(`DELETE FROM users WHERE ingame_time = 0 AND last_login < ? AND bot = 0 AND access = 'user'`, pyTime(now.AddDate(0, 0, -28)))
	// last login > 5 years
	d.db.Exec(`DELETE FROM users WHERE last_login < ?`, pyTime(now.AddDate(0, 0, -1825)))
	// old channel history messages > 2 weeks
	d.db.Exec(`DELETE FROM channel_history WHERE time < ?`, pyTime(now.AddDate(0, 0, -14)))
}

// auditAccess mirrors audit_access.
func (d *UserDB) auditAccess() {
	now := time.Now()
	// remove botflag from users that didn't log in for 1 year
	d.db.Exec(`UPDATE users SET bot = 0 WHERE last_login < ? AND bot = 1`, pyTime(now.AddDate(0, 0, -365)))
	// remove moderator/admin access from users that didn't log in for 1 year
	d.db.Exec(`UPDATE users SET access = 'user' WHERE last_login < ? AND access = 'admin'`, pyTime(now.AddDate(0, 0, -365)))
	d.db.Exec(`UPDATE users SET access = 'user' WHERE last_login < ? AND access = 'mod'`, pyTime(now.AddDate(0, 0, -365)))
}

// ignoreUser mirrors ignore_user.
func (d *UserDB) ignoreUser(userID, ignoreUserID int, reason string) {
	d.db.Exec(`INSERT INTO ignores (user_id, ignored_user_id, reason, time) VALUES (?, ?, ?, ?)`,
		userID, ignoreUserID, reason, pyTime(time.Now()))
}

// unignoreUser mirrors unignore_user.
func (d *UserDB) unignoreUser(userID, unignoreUserID int) {
	d.db.Exec(`DELETE FROM ignores WHERE user_id = ? AND ignored_user_id = ?`, userID, unignoreUserID)
}

// globallyUnignoreUser mirrors globally_unignore_user.
func (d *UserDB) globallyUnignoreUser(unignoreUserID int) []int {
	rows, err := d.db.Query(`SELECT user_id FROM ignores WHERE ignored_user_id = ?`, unignoreUserID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var userIDs []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			userIDs = append(userIDs, id)
		}
	}
	d.db.Exec(`DELETE FROM ignores WHERE ignored_user_id = ?`, unignoreUserID)
	return userIDs
}

// isIgnored mirrors is_ignored.
func (d *UserDB) isIgnored(userID, ignoreUserID int) bool {
	var n int
	d.db.QueryRow(`SELECT COUNT(*) FROM ignores WHERE user_id = ? AND ignored_user_id = ?`, userID, ignoreUserID).Scan(&n)
	return n > 0
}

// IgnoreEntry mirrors an (ignored_user_id, reason) pair.
type IgnoreEntry struct {
	UserID int
	Reason string
}

// getIgnoreList mirrors get_ignore_list: (ignored_user_id, reason) pairs.
func (d *UserDB) getIgnoreList(userID int) []IgnoreEntry {
	rows, err := d.db.Query(`SELECT ignored_user_id, reason FROM ignores WHERE user_id = ?`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []IgnoreEntry
	for rows.Next() {
		var e IgnoreEntry
		var reason any
		if rows.Scan(&e.UserID, &reason) == nil {
			if r, ok := reason.(string); ok {
				e.Reason = r
			}
			list = append(list, e)
		}
	}
	return list
}

// getIgnoredUserIDs mirrors get_ignored_user_ids.
func (d *UserDB) getIgnoredUserIDs(userID int) []int {
	rows, err := d.db.Query(`SELECT ignored_user_id FROM ignores WHERE user_id = ?`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// friendUsers mirrors friend_users.
func (d *UserDB) friendUsers(userID, friendUserID int) {
	d.db.Exec(`INSERT INTO friends (first_user_id, second_user_id, time) VALUES (?, ?, ?)`,
		userID, friendUserID, pyTime(time.Now()))
}

// unfriendUsers mirrors unfriend_users.
func (d *UserDB) unfriendUsers(firstUserID, secondUserID int) {
	d.db.Exec(`DELETE FROM friends WHERE first_user_id = ? AND second_user_id = ?`, firstUserID, secondUserID)
	d.db.Exec(`DELETE FROM friends WHERE second_user_id = ? AND first_user_id = ?`, firstUserID, secondUserID)
}

// areFriends mirrors are_friends. The python queries check "A has any
// friend row (as first)" UNION "B has any friend row (as second)"
// rather than the A<->B pair; this is ported faithfully.
func (d *UserDB) areFriends(firstUserID, secondUserID int) bool {
	var n int
	d.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM friends WHERE first_user_id = ? UNION SELECT 1 FROM friends WHERE second_user_id = ?)`,
		firstUserID, secondUserID).Scan(&n)
	return n > 0
}

// getFriendUserIDs mirrors get_friend_user_ids.
func (d *UserDB) getFriendUserIDs(userID int) []int {
	rows, err := d.db.Query(`SELECT second_user_id FROM friends WHERE first_user_id = ? UNION SELECT first_user_id FROM friends WHERE second_user_id = ?`, userID, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// hasFriendRequest mirrors has_friend_request.
func (d *UserDB) hasFriendRequest(userID, friendUserID int) bool {
	var n int
	d.db.QueryRow(`SELECT COUNT(*) FROM "friendRequests" WHERE user_id = ? AND friend_user_id = ?`, userID, friendUserID).Scan(&n)
	return n > 0
}

// addFriendRequest mirrors add_friend_request.
func (d *UserDB) addFriendRequest(userID, friendUserID int, msg string) {
	var msgArg any
	if msg != "" {
		msgArg = msg
	}
	d.db.Exec(`INSERT INTO "friendRequests" (user_id, friend_user_id, msg, time) VALUES (?, ?, ?, ?)`,
		userID, friendUserID, msgArg, pyTime(time.Now()))
}

// removeFriendRequest mirrors remove_friend_request.
func (d *UserDB) removeFriendRequest(userID, friendUserID int) {
	d.db.Exec(`DELETE FROM "friendRequests" WHERE user_id = ? AND friend_user_id = ?`, userID, friendUserID)
}

// RequestEntry mirrors a (user_id, msg) friend request pair.
type RequestEntry struct {
	UserID int
	Msg    string
}

// getFriendRequestList mirrors get_friend_request_list: requests sent to
// user_id, as (user_id, msg) pairs.
func (d *UserDB) getFriendRequestList(userID int) []RequestEntry {
	rows, err := d.db.Query(`SELECT user_id, msg FROM "friendRequests" WHERE friend_user_id = ?`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []RequestEntry
	for rows.Next() {
		var e RequestEntry
		var msg any
		if rows.Scan(&e.UserID, &msg) == nil {
			if m, ok := msg.(string); ok {
				e.Msg = m
			}
			list = append(list, e)
		}
	}
	return list
}

// ChannelMessage mirrors a [date, username, msg, ex_msg, id] tuple.
type ChannelMessage struct {
	Time     time.Time
	Username string
	Msg      string
	ExMsg    bool
	ID       int
}

// addChannelMessage mirrors add_channel_message.
func (d *UserDB) addChannelMessage(channelID, userID int, bridgedID *int, msg string, exMsg bool, date time.Time) (int, error) {
	if date.IsZero() {
		date = time.Now()
	}
	var bridged any
	if bridgedID != nil {
		bridged = *bridgedID
	}
	res, err := d.db.Exec(`INSERT INTO channel_history (channel_id, user_id, bridged_id, time, msg, ex_msg) VALUES (?, ?, ?, ?, ?, ?)`,
		channelID, userID, bridged, pyTime(date), msg, pyInt(exMsg))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

// getChannelMessages mirrors get_channel_messages (the python user_id
// argument is unused).
func (d *UserDB) getChannelMessages(channelID, lastMsgID int) []ChannelMessage {
	rows, err := d.db.Query(`SELECT ch.time, ch.msg, ch.ex_msg, u.username, bu.external_username, bu.location, ch.id
		FROM channel_history ch
		LEFT JOIN users u ON u.id = ch.user_id
		LEFT JOIN bridged_users bu ON bu.id = ch.bridged_id
		WHERE ch.channel_id = ? AND ch.id > ?
		ORDER BY ch.id`, channelID, lastMsgID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var msgs []ChannelMessage
	for rows.Next() {
		var m ChannelMessage
		var t, username, externalUsername, location any
		if rows.Scan(&t, &m.Msg, &m.ExMsg, &username, &externalUsername, &location, &m.ID) != nil {
			continue
		}
		m.Time = toTime(t)
		u, _ := username.(string)
		eu, _ := externalUsername.(string)
		loc, _ := location.(string)
		switch {
		case u == "":
			m.Username = "?"
		case eu != "":
			m.Username = eu + ":" + loc
		default:
			m.Username = u
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// BanEntry mirrors SQLUsers.Ban.
type BanEntry struct {
	ID           int
	IssuerUserID *int
	UserID       *int
	IP           *string
	Email        *string
	Reason       string
	EndDate      time.Time
}

// BlacklistEntry mirrors SQLUsers.BlacklistedEmailDomain.
type BlacklistEntry struct {
	ID           int
	IssuerUserID *int
	Domain       string
	Reason       string
	StartTime    time.Time
}

const banSelect = `SELECT id, issuer_user_id, user_id, ip, email, reason, end_date FROM ban`

func scanBan(row scanner) *BanEntry {
	var b BanEntry
	var issuer, user sql.NullInt64
	var ip, email, reason sql.NullString
	var endDate any
	if err := row.Scan(&b.ID, &issuer, &user, &ip, &email, &reason, &endDate); err != nil {
		return nil
	}
	if issuer.Valid {
		v := int(issuer.Int64)
		b.IssuerUserID = &v
	}
	if user.Valid {
		v := int(user.Int64)
		b.UserID = &v
	}
	if ip.Valid {
		b.IP = &ip.String
	}
	if email.Valid {
		b.Email = &email.String
	}
	b.Reason = reason.String
	b.EndDate = toTime(endDate)
	return &b
}

// pyNone renders a missing optional string the way python's %s does.
func pyNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

// pyFloatString renders a float the way python's str() does: integer
// values keep a trailing .0.
func pyFloatString(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}

// banEnd mirrors Ban.__init__: now + duration days.
func banEnd(durationDays float64) time.Time {
	return time.Now().Add(time.Duration(durationDays * float64(24*time.Hour)))
}

// BanDB mirrors SQLUsers.BansHandler.
type BanDB struct {
	db *sql.DB
}

// checkBanAt mirrors check_ban. Falsy args (0 user id, empty ip/email)
// are skipped, as in python.
func (d *BanDB) checkBanAt(userID int, ip, email string, now time.Time) *BanEntry {
	if userID != 0 {
		if ban := scanBan(d.db.QueryRow(banSelect+` WHERE user_id = ? AND ? <= end_date`, userID, pyTime(now))); ban != nil {
			return ban
		}
	}
	if ip != "" {
		if ban := scanBan(d.db.QueryRow(banSelect+` WHERE ip = ? AND ? <= end_date`, ip, pyTime(now))); ban != nil {
			return ban
		}
	}
	if email != "" {
		if ban := scanBan(d.db.QueryRow(banSelect+` WHERE email = ? AND ? <= end_date`, email, pyTime(now))); ban != nil {
			return ban
		}
	}
	return nil
}

// ban mirrors ban.
func (d *BanDB) ban(issuer *Client, duration, reason, username string) (bool, string) {
	dur, err := strconv.ParseFloat(duration, 64)
	if err != nil {
		return false, fmt.Sprintf("Duration must be a float, cannot convert %s", duration)
	}
	entry := server.userDB.getClientFromUsername(username)
	if entry == nil {
		return false, fmt.Sprintf("Unable to ban %s, user doesn't exist", username)
	}
	var email any
	if entry.Email != "" {
		email = entry.Email
	}
	d.db.Exec(`INSERT INTO ban (issuer_user_id, user_id, ip, email, reason, end_date) VALUES (?, ?, ?, ?, ?, ?)`,
		issuer.userID, entry.userID, entry.lastIP, email, reason, pyTime(banEnd(dur)))
	return true, fmt.Sprintf("Successfully banned %s, %s, %s for %s days.", username, entry.lastIP, pyNone(entry.Email), pyFloatString(dur))
}

var ipRe = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// banSpecific mirrors ban_specific.
func (d *BanDB) banSpecific(issuer *Client, duration, reason, arg string) (bool, string) {
	dur, err := strconv.ParseFloat(duration, 64)
	if err != nil {
		return false, fmt.Sprintf("Duration must be a float, cannot convert %s", duration)
	}
	emailMatch, _ := server.verificationDB.validEmailAddr(arg)
	ipMatch := ipRe.MatchString(arg)
	entry := server.userDB.getClientFromUsername(arg)
	var userID, ip, email any
	switch {
	case emailMatch:
		email = arg
	case ipMatch:
		ip = arg
	case entry != nil:
		userID = entry.userID
	default:
		return false, fmt.Sprintf("Unable to match '%s' to username/ip/email", arg)
	}
	d.db.Exec(`INSERT INTO ban (issuer_user_id, user_id, ip, email, reason, end_date) VALUES (?, ?, ?, ?, ?, ?)`,
		issuer.userID, userID, ip, email, reason, pyTime(banEnd(dur)))
	return true, fmt.Sprintf("Successfully banned %s for %s days", arg, pyFloatString(dur))
}

// unban mirrors unban.
func (d *BanDB) unban(issuer *Client, arg string) (bool, string) {
	emailMatch, _ := server.verificationDB.validEmailAddr(arg)
	ipMatch := ipRe.MatchString(arg)
	entry := server.userDB.getClientFromUsername(arg)
	if !emailMatch && !ipMatch && entry == nil {
		return false, fmt.Sprintf("Unable to match '%s' to username/ip/email", arg)
	}
	nUnban := 0
	if emailMatch {
		if res, err := d.db.Exec(`DELETE FROM ban WHERE email = ?`, arg); err == nil {
			if n, err := res.RowsAffected(); err == nil {
				nUnban += int(n)
			}
		}
	}
	if ipMatch {
		if res, err := d.db.Exec(`DELETE FROM ban WHERE ip = ?`, arg); err == nil {
			if n, err := res.RowsAffected(); err == nil {
				nUnban += int(n)
			}
		}
	}
	if entry != nil {
		if res, err := d.db.Exec(`DELETE FROM ban WHERE user_id = ?`, entry.userID); err == nil {
			if n, err := res.RowsAffected(); err == nil {
				nUnban += int(n)
			}
		}
	}
	if nUnban > 0 {
		return true, fmt.Sprintf("Successfully removed %d bans relating to %s", nUnban, arg)
	}
	return false, fmt.Sprintf("No matching bans for %s", arg)
}

// checkBlacklist mirrors check_blacklist.
func (d *BanDB) checkBlacklist(email string) *BlacklistEntry {
	at := strings.IndexByte(email, '@')
	if at < 0 {
		return nil
	}
	domain := email[at+1:]
	var b BlacklistEntry
	var issuer sql.NullInt64
	var reason sql.NullString
	var startTime any
	err := d.db.QueryRow(`SELECT id, issuer_user_id, domain, reason, start_time FROM blacklisted_email_domains WHERE domain = ?`, domain).
		Scan(&b.ID, &issuer, &b.Domain, &reason, &startTime)
	if err != nil {
		return nil
	}
	if issuer.Valid {
		v := int(issuer.Int64)
		b.IssuerUserID = &v
	}
	b.Reason = reason.String
	b.StartTime = toTime(startTime)
	return &b
}

// blacklist mirrors blacklist.
func (d *BanDB) blacklist(issuer *Client, domain, reason string) (bool, string) {
	if !strings.Contains(domain, ".") {
		return false, fmt.Sprintf("invalid domain '%s', contains no '.'", domain)
	}
	if strings.Contains(domain, "www") || strings.Contains(domain, "http") || strings.Contains(domain, "/") {
		return false, fmt.Sprintf("invalid domain '%s', do not include www or http(s) part, example: hawtmail.com", domain)
	}
	var exists int
	d.db.QueryRow(`SELECT COUNT(*) FROM blacklisted_email_domains WHERE domain = ?`, domain).Scan(&exists)
	if exists > 0 {
		return false, fmt.Sprintf("Domain %s is already blacklisted", domain)
	}
	d.db.Exec(`INSERT INTO blacklisted_email_domains (issuer_user_id, domain, reason, start_time) VALUES (?, ?, ?, ?)`,
		issuer.userID, domain, reason, pyTime(time.Now()))
	return true, fmt.Sprintf("Successfully added %s to blacklist", domain)
}

// unblacklist mirrors unblacklist (the python typo in the success
// message is kept).
func (d *BanDB) unblacklist(issuer *Client, domain string) (bool, string) {
	res, err := d.db.Exec(`DELETE FROM blacklisted_email_domains WHERE domain = ?`, domain)
	if err != nil {
		return false, err.Error()
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, fmt.Sprintf("Unable to remove %s, entry doesn't exist", domain)
	}
	return true, fmt.Sprintf("Sucessfully removed %s from blacklist", domain)
}

// BanInfo mirrors a list_bans dict entry.
type BanInfo struct {
	Username string
	UserID   *int
	IP       string
	Email    string
	EndDate  string
	Reason   string
	Issuer   string
}

// listBans mirrors list_bans. The python code crashes (NameError) when a
// ban's issuer user is missing; this defaults the issuer to "" instead.
//
// Usernames are resolved only after the ban rows are fully read and closed:
// the pool is capped at one connection, so issuing a nested query while the
// ban rows are still open would deadlock.
func (d *BanDB) listBans() []BanInfo {
	rows, err := d.db.Query(banSelect)
	if err != nil {
		return nil
	}
	var bans []BanEntry
	for rows.Next() {
		if b := scanBan(rows); b != nil {
			bans = append(bans, *b)
		}
	}
	rows.Close()
	var list []BanInfo
	for _, b := range bans {
		info := BanInfo{UserID: b.UserID, Reason: b.Reason}
		if b.UserID != nil {
			if u := server.userDB.getClientFromID(*b.UserID); u != nil {
				info.Username = u.Username()
			}
		}
		if b.IP != nil {
			info.IP = *b.IP
		}
		if b.Email != nil {
			info.Email = *b.Email
		}
		if !b.EndDate.IsZero() {
			info.EndDate = b.EndDate.Format("2006-01-02 15:04")
		}
		if b.IssuerUserID != nil {
			if u := server.userDB.getClientFromID(*b.IssuerUserID); u != nil {
				info.Issuer = u.Username()
			}
		}
		list = append(list, info)
	}
	return list
}

// BlacklistInfo mirrors a list_blacklist dict entry.
type BlacklistInfo struct {
	Domain    string
	StartTime string
	Reason    string
	Issuer    string
}

// listBlacklist mirrors list_blacklist; the python issuer NameError is
// avoided the same way as in listBans, and issuer usernames are resolved
// after the rows are closed (see listBans for why).
func (d *BanDB) listBlacklist() []BlacklistInfo {
	rows, err := d.db.Query(`SELECT id, issuer_user_id, domain, reason, start_time FROM blacklisted_email_domains`)
	if err != nil {
		return nil
	}
	var entries []BlacklistEntry
	for rows.Next() {
		var b BlacklistEntry
		var issuer sql.NullInt64
		var reason sql.NullString
		var startTime any
		if rows.Scan(&b.ID, &issuer, &b.Domain, &reason, &startTime) != nil {
			continue
		}
		b.Reason = reason.String
		b.StartTime = toTime(startTime)
		if issuer.Valid {
			v := int(issuer.Int64)
			b.IssuerUserID = &v
		}
		entries = append(entries, b)
	}
	rows.Close()
	var list []BlacklistInfo
	for _, b := range entries {
		info := BlacklistInfo{Domain: b.Domain, Reason: b.Reason}
		if !b.StartTime.IsZero() {
			info.StartTime = b.StartTime.Format("2006-01-02 15:04")
		}
		if b.IssuerUserID != nil {
			if u := server.userDB.getClientFromID(*b.IssuerUserID); u != nil {
				info.Issuer = u.Username()
			}
		}
		list = append(list, info)
	}
	return list
}

// clean mirrors BansHandler.clean.
func (d *BanDB) clean() {
	d.db.Exec(`DELETE FROM ban WHERE end_date < ?`, pyTime(time.Now()))
}

// VerificationEntry mirrors SQLUsers.Verification.
type VerificationEntry struct {
	ID       int
	UserID   int
	Email    string
	Code     int
	Expiry   time.Time
	Attempts int
	Resends  int
	Reason   string
}

const verificationSelect = `SELECT id, user_id, email, code, expiry, attempts, resends, reason FROM verifications`

func scanVerification(row scanner) *VerificationEntry {
	var v VerificationEntry
	var code, expiry, reason any
	if err := row.Scan(&v.ID, &v.UserID, &v.Email, &code, &expiry, &v.Attempts, &v.Resends, &reason); err != nil {
		return nil
	}
	if c, ok := code.(int64); ok {
		v.Code = int(c)
	}
	v.Expiry = toTime(expiry)
	if r, ok := reason.(string); ok {
		v.Reason = r
	}
	return &v
}

// emailRe mirrors VerificationsHandler.valid_email_addr's regex: anchored
// at the start only, and case-sensitive.
var emailRe = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,6}`)

// VerificationDB mirrors SQLUsers.VerificationsHandler.
type VerificationDB struct {
	db *sql.DB
	// requireVerification is true when the server is configured with an
	// outbound mail address (root.mail_user != '').
	requireVerification bool
}

// active mirrors active.
func (d *VerificationDB) active() bool {
	return d.requireVerification
}

// validEmailAddr mirrors valid_email_addr.
func (d *VerificationDB) validEmailAddr(email string) (bool, string) {
	if email == "" {
		return false, "An email address is required."
	}
	if strings.ContainsAny(email, " \t\n\r") {
		return false, "Invalid email address (check for whitespace)."
	}
	if emailRe.MatchString(email) {
		return true, ""
	}
	return false, "Invalid email address (check for whitespace)."
}

func (d *VerificationDB) entryByEmail(email string) *VerificationEntry {
	return scanVerification(d.db.QueryRow(verificationSelect+` WHERE email = ?`, email))
}

func (d *VerificationDB) entryByUserID(userID int) *VerificationEntry {
	return scanVerification(d.db.QueryRow(verificationSelect+` WHERE user_id = ?`, userID))
}

// checkAndSend mirrors check_and_send.
func (d *VerificationDB) checkAndSend(userID int, email string, digits int, reason string) (bool, string) {
	if !d.active() {
		return true, ""
	}
	good, validityReason := d.validEmailAddr(email)
	if !good {
		return false, validityReason
	}
	if dbblacklist := server.banDB.checkBlacklist(email); dbblacklist != nil {
		return false, dbblacklist.Domain + " is blacklisted: " + dbblacklist.Reason
	}
	now := time.Now()
	if emailEntry := d.entryByEmail(email); emailEntry != nil {
		if !now.After(emailEntry.Expiry) {
			return false, "A verification attempt is already active for " + email + ", use that or wait for it to expire (up to 24h)"
		}
		d.remove(emailEntry.UserID)
	}
	if entry := d.entryByUserID(userID); entry != nil {
		if entry.Email != email {
			return false, "A verification code is active for " + entry.Email + ", use that or wait for it to expire (up to 24h)"
		}
		if now.Before(entry.Expiry) {
			return false, "Already sent a verification code, please check your spam filter!"
		}
		d.remove(userID)
	}
	entry := d.create(userID, email, digits, reason)
	d.send(entry)
	return true, ""
}

// create mirrors create: the code is a uniform random digits-digit number
// and the entry expires two days out.
func (d *VerificationDB) create(userID int, email string, digits int, reason string) *VerificationEntry {
	low := int(math.Pow10(digits - 1))
	high := int(math.Pow10(digits)) - 1
	code := low + rand.Intn(high-low+1)
	expiry := time.Now().Add(48 * time.Hour)
	res, err := d.db.Exec(`INSERT INTO verifications (user_id, email, code, expiry, attempts, resends, reason) VALUES (?, ?, ?, ?, 0, 0, ?)`,
		userID, email, code, pyTime(expiry), reason)
	if err != nil {
		return &VerificationEntry{UserID: userID, Email: email, Code: code, Expiry: expiry, Reason: reason}
	}
	id, _ := res.LastInsertId()
	return &VerificationEntry{ID: int(id), UserID: userID, Email: email, Code: code, Expiry: expiry, Reason: reason}
}

// resend mirrors resend.
func (d *VerificationDB) resend(userID int, email string) (bool, string) {
	if !d.active() {
		return true, ""
	}
	entry := d.entryByUserID(userID)
	if entry == nil {
		return false, "You do not have an active verification code, request a new one"
	}
	if entry.Email != email {
		return false, "Your verification code for " + entry.Email + " cannot be re-sent to a different email address, use it or wait for it to expire (up to 48h)"
	}
	if entry.Resends >= 5 {
		return false, "Too many resends, please try again later"
	}
	if !time.Now().Before(entry.Expiry) {
		return false, "Your verification code for " + entry.Email + " has expired, please request a new one"
	}
	entry.Resends++
	d.db.Exec(`UPDATE verifications SET resends = ? WHERE id = ?`, entry.Resends, entry.ID)
	d.send(entry)
	return true, ""
}

// send mirrors send: the email goes out on a separate goroutine and the
// "sent" log line happens after launch, as in python.
func (d *VerificationDB) send(entry *VerificationEntry) {
	if !d.active() {
		return
	}
	body := "You are recieving this email because you recently " + entry.Reason + ".\r\n" +
		"Your email verification code is " + strconv.Itoa(entry.Code) + "\r\n\r\n" +
		"This verification code will expire on " + entry.Expiry.Format("2006-01-02") + " at " + entry.Expiry.Format("15:04") + " CET."
	go d.sendEmail(server.mailUser, entry.Email, "SpringRTS verification code", body)
	username := ""
	if dbuser := server.userDB.getClientFromID(entry.UserID); dbuser != nil {
		username = dbuser.Username()
	}
	log.Printf("Sent verification code for <%s> to %s", username, entry.Email)
}

// sendEmail mirrors _send_email: SMTP on localhost:25, with the python
// quirks kept (leading comma in the To: header, us-ascii charset).
func (d *VerificationDB) sendEmail(sentFrom, to, subject, body string) {
	if !d.active() {
		log.Printf("Attempt to send email (subject: %s) failed, verifications handler is inactive", subject)
		return
	}
	body += "\r\n\r\nIf you received this message in error, please contact us at https://springrts.com. Direct replies to this message will be automatically deleted."
	msg := "Subject: " + subject + "\r\n" +
		"From: SpringRTS <" + sentFrom + ">\r\n" +
		"To: ," + to + "\r\n" +
		"Content-Type: text/plain; charset=\"us-ascii\"\r\n" +
		"\r\n" + body
	conn, err := smtp.Dial("localhost:25")
	if err == nil {
		if err = conn.Mail(sentFrom); err == nil {
			err = conn.Rcpt(to)
		}
		if err == nil {
			var w io.Writer
			if w, err = conn.Data(); err == nil {
				_, err = w.Write([]byte(msg))
				if err == nil {
					if c, ok := w.(io.Closer); ok {
						err = c.Close()
					}
				}
			}
		}
		conn.Close()
	}
	if err != nil {
		log.Printf("Failed to send email from %s to %s", sentFrom, to)
		log.Printf("%s", err)
		return
	}
	log.Printf("Sent email to %s", to)
}

// verify mirrors verify.
func (d *VerificationDB) verify(userID int, email, code string) (bool, string) {
	if !d.active() {
		return true, ""
	}
	if code == "" {
		return false, "A verification code is required -- check your email"
	}
	entry := d.entryByUserID(userID)
	if entry == nil {
		log.Printf("Unexpected verification attempt: %d, %s", userID, code)
		return false, "Unexpected verification attempt, please request a verification code"
	}
	if !entry.Expiry.After(time.Now()) {
		return false, "Your verification code for " + entry.Email + " has expired, please request a new one"
	}
	if entry.Attempts >= 3 {
		return false, "Too many attempts, please try again later"
	}
	if entry.Email != email {
		return false, "Failed to match email addresses"
	}
	codeInt, err := strconv.Atoi(code)
	if err == nil && entry.Code == codeInt {
		username := ""
		if dbuser := server.userDB.getClientFromID(userID); dbuser != nil {
			username = dbuser.Username()
		}
		log.Printf("Successful verification code for <%s> %s", username, entry.Email)
		d.remove(userID)
		return true, ""
	}
	entry.Attempts++
	d.db.Exec(`UPDATE verifications SET attempts = ? WHERE id = ?`, entry.Attempts, entry.ID)
	if err != nil {
		return false, fmt.Sprintf("Incorrect verification code, %v, %d/3 attempts remaining", err, 3-entry.Attempts)
	}
	return false, fmt.Sprintf("Incorrect verification code, %d/3 attempts remaining", 3-entry.Attempts)
}

// remove mirrors remove.
func (d *VerificationDB) remove(userID int) {
	d.db.Exec(`DELETE FROM verifications WHERE user_id = ?`, userID)
}

// clean mirrors clean.
func (d *VerificationDB) clean() {
	d.db.Exec(`DELETE FROM verifications WHERE expiry < ?`, pyTime(time.Now()))
}

// resetPasswordCharset mirrors the python charset; the pound sign makes
// it non-ascii, so it is indexed by rune, not byte.
var resetPasswordCharset = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!£$%^&*?")

// resetPassword mirrors reset_password.
func (d *VerificationDB) resetPassword(userID int, emailToUser bool) {
	raw := make([]rune, 0, 10)
	for i := 0; i < 10; i++ {
		raw = append(raw, resetPasswordCharset[rand.Intn(len(resetPasswordCharset))])
	}
	rawPassword := string(raw)
	sum := md5.Sum([]byte(rawPassword))
	d.db.Exec(`UPDATE users SET password = ? WHERE id = ?`, base64.StdEncoding.EncodeToString(sum[:]), userID)
	if emailToUser {
		dbuser := server.userDB.getClientFromID(userID)
		if dbuser == nil || dbuser.Email == "" {
			return
		}
		go d.sendResetPasswordEmail(dbuser.Email, dbuser.Username(), rawPassword)
	}
}

// sendResetPasswordEmail mirrors _send_reset_password_email.
func (d *VerificationDB) sendResetPasswordEmail(email, username, password string) {
	subject := "SpringRTS account recovery"
	body := "You are recieving this email because you recently requested to recover the account <" + username + "> at the SpringRTS lobby server.\r\nYour new password is " + password
	d.sendEmail(server.mailUser, email, subject, body)
}

func toBool(v any) bool {
	switch n := v.(type) {
	case int64:
		return n != 0
	case bool:
		return n
	}
	return false
}

const channelSelect = `SELECT id, name, "key", owner_user_id, topic, topic_user_id, antispam, censor, store_history, last_used FROM channels`

// ChannelRow mirrors a SQLUsers.Channel row.
type ChannelRow struct {
	ID           int
	Name         string
	Key          *string
	OwnerUserID  *int
	Topic        *string
	TopicUserID  *int
	Antispam     bool
	Censor       bool
	StoreHistory bool
	LastUsed     time.Time
}

func scanChannel(row scanner) *ChannelRow {
	var c ChannelRow
	var key, owner, topic, topicUser, lastUsed any
	var antispam, censor, storeHistory any
	if err := row.Scan(&c.ID, &c.Name, &key, &owner, &topic, &topicUser,
		&antispam, &censor, &storeHistory, &lastUsed); err != nil {
		return nil
	}
	if s, ok := key.(string); ok && s != "" {
		c.Key = &s
	}
	if s, ok := topic.(string); ok && s != "" {
		c.Topic = &s
	}
	if v, ok := owner.(int64); ok {
		i := int(v)
		c.OwnerUserID = &i
	}
	if v, ok := topicUser.(int64); ok {
		i := int(v)
		c.TopicUserID = &i
	}
	c.Antispam = toBool(antispam)
	c.Censor = toBool(censor)
	c.StoreHistory = toBool(storeHistory)
	c.LastUsed = toTime(lastUsed)
	return &c
}

// ChannelDB mirrors SQLUsers.ChannelsHandler.
type ChannelDB struct {
	db *sql.DB
}

// channelFromName mirrors channel_from_name.
func (d *ChannelDB) channelFromName(name string) *ChannelRow {
	return scanChannel(d.db.QueryRow(channelSelect+` WHERE name = ?`, name))
}

// channelFromID mirrors channel_from_id.
func (d *ChannelDB) channelFromID(id int) *ChannelRow {
	return scanChannel(d.db.QueryRow(channelSelect+` WHERE id = ?`, id))
}

// allChannels mirrors all_channels (the python dict additionally carries
// 'operator': [] and 'chanserv': True, which the server fills in itself;
// like the python, 'censor' is not part of it).
func (d *ChannelDB) allChannels() map[string]*ChannelRow {
	rows, err := d.db.Query(channelSelect)
	if err != nil {
		return nil
	}
	defer rows.Close()
	channels := map[string]*ChannelRow{}
	for rows.Next() {
		if c := scanChannel(rows); c != nil {
			channels[c.Name] = c
		}
	}
	return channels
}

// OperatorRow mirrors an all_operators dict entry.
type OperatorRow struct {
	ChannelID int
	UserID    int
}

// allOperators mirrors all_operators.
func (d *ChannelDB) allOperators() []OperatorRow {
	rows, err := d.db.Query(`SELECT channel_id, user_id FROM channel_ops`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []OperatorRow
	for rows.Next() {
		var o OperatorRow
		if rows.Scan(&o.ChannelID, &o.UserID) == nil {
			list = append(list, o)
		}
	}
	return list
}

// ChannelBanRow mirrors an all_bans dict entry.
type ChannelBanRow struct {
	ChannelID    int
	IssuerUserID *int
	UserID       int
	IPAddress    string
	Expires      time.Time
	Reason       string
}

// allBans mirrors all_bans.
func (d *ChannelDB) allBans() []ChannelBanRow {
	rows, err := d.db.Query(`SELECT channel_id, issuer_user_id, user_id, ip_address, expires, reason FROM channel_bans`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []ChannelBanRow
	for rows.Next() {
		var b ChannelBanRow
		var issuer sql.NullInt64
		var ip, reason any
		var expires any
		if rows.Scan(&b.ChannelID, &issuer, &b.UserID, &ip, &expires, &reason) != nil {
			continue
		}
		if issuer.Valid {
			v := int(issuer.Int64)
			b.IssuerUserID = &v
		}
		if s, ok := ip.(string); ok {
			b.IPAddress = s
		}
		b.Expires = toTime(expires)
		if s, ok := reason.(string); ok {
			b.Reason = s
		}
		list = append(list, b)
	}
	return list
}

// ChannelBridgedBanRow mirrors an all_bridged_bans dict entry.
type ChannelBridgedBanRow struct {
	ChannelID    int
	BridgedID    int
	IssuerUserID *int
	Expires      time.Time
	Reason       string
}

// allBridgedBans mirrors all_bridged_bans.
func (d *ChannelDB) allBridgedBans() []ChannelBridgedBanRow {
	rows, err := d.db.Query(`SELECT channel_id, bridged_id, issuer_user_id, expires, reason FROM channel_bridged_bans`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []ChannelBridgedBanRow
	for rows.Next() {
		var b ChannelBridgedBanRow
		var issuer sql.NullInt64
		var expires, reason any
		if rows.Scan(&b.ChannelID, &b.BridgedID, &issuer, &expires, &reason) != nil {
			continue
		}
		if issuer.Valid {
			v := int(issuer.Int64)
			b.IssuerUserID = &v
		}
		b.Expires = toTime(expires)
		if s, ok := reason.(string); ok {
			b.Reason = s
		}
		list = append(list, b)
	}
	return list
}

// ChannelMuteRow mirrors an all_mutes dict entry.
type ChannelMuteRow struct {
	ChannelID    int
	IssuerUserID *int
	UserID       int
	Expires      time.Time
	Reason       string
}

// allMutes mirrors all_mutes.
func (d *ChannelDB) allMutes() []ChannelMuteRow {
	rows, err := d.db.Query(`SELECT channel_id, issuer_user_id, user_id, expires, reason FROM channel_mutes`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []ChannelMuteRow
	for rows.Next() {
		var m ChannelMuteRow
		var issuer sql.NullInt64
		var expires, reason any
		if rows.Scan(&m.ChannelID, &issuer, &m.UserID, &expires, &reason) != nil {
			continue
		}
		if issuer.Valid {
			v := int(issuer.Int64)
			m.IssuerUserID = &v
		}
		m.Expires = toTime(expires)
		if s, ok := reason.(string); ok {
			m.Reason = s
		}
		list = append(list, m)
	}
	return list
}

// ForwardRow mirrors an all_forwards dict entry.
type ForwardRow struct {
	FromID int
	ToID   int
}

// allForwards mirrors all_forwards.
func (d *ChannelDB) allForwards() []ForwardRow {
	rows, err := d.db.Query(`SELECT channel_from_id, channel_to_id FROM channel_forwards`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []ForwardRow
	for rows.Next() {
		var f ForwardRow
		if rows.Scan(&f.FromID, &f.ToID) == nil {
			list = append(list, f)
		}
	}
	return list
}

// recordUse mirrors recordUse.
func (d *ChannelDB) recordUse(name string) {
	d.db.Exec(`UPDATE channels SET last_used = ? WHERE name = ?`, pyTime(time.Now()), name)
}

// setTopic mirrors setTopic.
func (d *ChannelDB) setTopic(name, topic string, topicUserID int) {
	d.db.Exec(`UPDATE channels SET topic = ?, topic_user_id = ? WHERE name = ?`, topic, topicUserID, name)
}

// setKey mirrors setKey.
func (d *ChannelDB) setKey(name string, key *string) {
	d.db.Exec(`UPDATE channels SET "key" = ? WHERE name = ?`, key, name)
}

// setFounder mirrors setFounder.
func (d *ChannelDB) setFounder(name string, ownerUserID int) {
	d.db.Exec(`UPDATE channels SET owner_user_id = ? WHERE name = ?`, ownerUserID, name)
}

// setAntispam mirrors setAntispam.
func (d *ChannelDB) setAntispam(name string, antispam bool) {
	d.db.Exec(`UPDATE channels SET antispam = ? WHERE name = ?`, pyInt(antispam), name)
}

// opUser mirrors opUser.
func (d *ChannelDB) opUser(channelID, userID int) {
	d.db.Exec(`INSERT INTO channel_ops (channel_id, user_id) VALUES (?, ?)`, channelID, userID)
}

// deopUser mirrors deopUser.
func (d *ChannelDB) deopUser(channelID, userID int) {
	d.db.Exec(`DELETE FROM channel_ops WHERE user_id = ? AND channel_id = ?`, userID, channelID)
}

// banBridgedUser mirrors banBridgedUser.
func (d *ChannelDB) banBridgedUser(channelID int, issuerUserID *int, bridgedID int, expires time.Time, reason string) {
	d.db.Exec(`INSERT INTO channel_bridged_bans (channel_id, issuer_user_id, bridged_id, expires, reason) VALUES (?, ?, ?, ?, ?)`,
		channelID, issuerUserID, bridgedID, pyTime(expires), reason)
}

// unbanBridgedUser mirrors unbanBridgedUser.
func (d *ChannelDB) unbanBridgedUser(channelID, bridgedID int) {
	d.db.Exec(`DELETE FROM channel_bridged_bans WHERE bridged_id = ? AND channel_id = ?`, bridgedID, channelID)
}

// banUser mirrors banUser.
func (d *ChannelDB) banUser(channelID int, issuerUserID *int, userID int, ip string, expires time.Time, reason string) {
	d.db.Exec(`INSERT INTO channel_bans (channel_id, issuer_user_id, user_id, ip_address, expires, reason) VALUES (?, ?, ?, ?, ?, ?)`,
		channelID, issuerUserID, userID, ip, pyTime(expires), reason)
}

// unbanUser mirrors unbanUser.
func (d *ChannelDB) unbanUser(channelID, userID int) {
	d.db.Exec(`DELETE FROM channel_bans WHERE user_id = ? AND channel_id = ?`, userID, channelID)
}

// muteUser mirrors muteUser.
func (d *ChannelDB) muteUser(channelID int, issuerUserID *int, userID int, expires time.Time, reason string) {
	d.db.Exec(`INSERT INTO channel_mutes (channel_id, issuer_user_id, user_id, expires, reason) VALUES (?, ?, ?, ?, ?)`,
		channelID, issuerUserID, userID, pyTime(expires), reason)
}

// unmuteUser mirrors unmuteUser.
func (d *ChannelDB) unmuteUser(channelID, userID int) {
	d.db.Exec(`DELETE FROM channel_mutes WHERE user_id = ? AND channel_id = ?`, userID, channelID)
}

// setHistory mirrors setHistory.
func (d *ChannelDB) setHistory(name string, enable bool) {
	d.db.Exec(`UPDATE channels SET store_history = ? WHERE name = ?`, pyInt(enable), name)
}

// addForward mirrors addForward.
func (d *ChannelDB) addForward(fromID, toID int) {
	d.db.Exec(`INSERT INTO channel_forwards (channel_from_id, channel_to_id) VALUES (?, ?)`, fromID, toID)
}

// removeForward mirrors removeForward.
func (d *ChannelDB) removeForward(fromID, toID int) {
	d.db.Exec(`DELETE FROM channel_forwards WHERE channel_from_id = ? AND channel_to_id = ?`, fromID, toID)
}

// register mirrors register: upserts the channel by name, sets the topic
// only when the in-memory channel has one, and returns the stored row.
func (d *ChannelDB) register(name, topic string, ownerUserID int) *ChannelRow {
	now := time.Now()
	if d.channelFromName(name) == nil {
		d.db.Exec(`INSERT INTO channels (name, last_used) VALUES (?, ?)`, name, pyTime(now))
	}
	if topic != "" {
		d.db.Exec(`UPDATE channels SET topic = ?, topic_user_id = ? WHERE name = ?`, topic, ownerUserID, name)
	}
	d.db.Exec(`UPDATE channels SET owner_user_id = ?, last_used = ? WHERE name = ?`, ownerUserID, pyTime(time.Now()), name)
	return d.channelFromName(name)
}

// unRegister mirrors unRegister.
func (d *ChannelDB) unRegister(name string) {
	d.db.Exec(`DELETE FROM channels WHERE name = ?`, name)
}

// registered mirrors registered.
func (d *ChannelDB) registered(name string) bool {
	return d.channelFromName(name) != nil
}

// clean mirrors ChannelsHandler.clean.
func (d *ChannelDB) clean() {
	now := time.Now()
	d.db.Exec(`DELETE FROM channel_mutes WHERE expires < ?`, pyTime(now))
	d.db.Exec(`DELETE FROM channel_bans WHERE expires < ?`, pyTime(now))
	d.db.Exec(`DELETE FROM channel_bridged_bans WHERE expires < ?`, pyTime(now))
	d.db.Exec(`DELETE FROM channels WHERE last_used < ?`, pyTime(now.AddDate(0, 0, -180)))
}

const bridgedSelect = `SELECT id, location, external_id, external_username, last_bridged FROM bridged_users`

// scanBridged mirrors OfflineBridgedClient: the db fields plus the
// derived username and empty in-memory state.
func scanBridged(row scanner) *BridgedClient {
	var b BridgedClient
	var lastBridged any
	if err := row.Scan(&b.bridgedID, &b.location, &b.externalID, &b.externalUsername, &lastBridged); err != nil {
		return nil
	}
	b.lastBridged = toTime(lastBridged)
	b.username = b.externalUsername + ":" + b.location
	b.channels = map[string]bool{}
	return &b
}

// BridgedUserDB mirrors SQLUsers.BridgedUsersHandler.
type BridgedUserDB struct {
	db *sql.DB
}

// bridgedClient mirrors bridgedClient.
func (d *BridgedUserDB) bridgedClient(location, externalID string) *BridgedClient {
	return scanBridged(d.db.QueryRow(bridgedSelect+` WHERE external_id = ? AND location = ?`, externalID, location))
}

// bridgedClientFromID mirrors bridgedClientFromID.
func (d *BridgedUserDB) bridgedClientFromID(bridgedID int) *BridgedClient {
	return scanBridged(d.db.QueryRow(bridgedSelect+` WHERE id = ?`, bridgedID))
}

// bridgedClientFromUsername mirrors bridgedClientFromUsername; the python
// crashes on usernames without a ':' separator, this returns nil instead.
func (d *BridgedUserDB) bridgedClientFromUsername(username string) *BridgedClient {
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	return scanBridged(d.db.QueryRow(bridgedSelect+` WHERE external_username = ? AND location = ?`, parts[0], parts[1]))
}

// newBridgedUser mirrors new_bridge_user.
func (d *BridgedUserDB) newBridgedUser(location, externalID, externalUsername string) *BridgedClient {
	res, err := d.db.Exec(`INSERT INTO bridged_users (location, external_id, external_username, last_bridged) VALUES (?, ?, ?, ?)`,
		location, externalID, externalUsername, pyTime(time.Now()))
	if err != nil {
		return nil
	}
	id, _ := res.LastInsertId()
	return d.bridgedClientFromID(int(id))
}

// bridgeUser mirrors bridge_user.
func (d *BridgedUserDB) bridgeUser(location, externalID, externalUsername string) (bool, *BridgedClient, string) {
	bridgedUser := d.bridgedClient(location, externalID)
	entry := scanBridged(d.db.QueryRow(bridgedSelect+` WHERE external_username = ? AND location = ?`, externalUsername, location))
	if entry != nil && entry.externalID != externalID {
		return false, nil, fmt.Sprintf("Another bridged user (external_id '%s') with location '%s' is currently associated to the external username '%s'",
			entry.externalID, location, externalUsername)
	}
	if bridgedUser == nil {
		return true, d.newBridgedUser(location, externalID, externalUsername), ""
	}
	now := time.Now()
	d.db.Exec(`UPDATE bridged_users SET external_username = ?, last_bridged = ? WHERE id = ?`, externalUsername, pyTime(now), bridgedUser.bridgedID)
	bridgedUser.externalUsername = externalUsername
	bridgedUser.lastBridged = now
	return true, bridgedUser, ""
}

// clean mirrors BridgedUsersHandler.clean.
func (d *BridgedUserDB) clean() {
	d.db.Exec(`DELETE FROM bridged_users WHERE last_bridged < ? AND id NOT IN (SELECT DISTINCT bridged_id FROM channel_bridged_bans)`,
		pyTime(time.Now().AddDate(0, 0, -30)))
}

// ContentDB mirrors SQLUsers.ContentHandler.
type ContentDB struct {
	db *sql.DB
}

// setMinSpringVersion mirrors set_min_spring_version.
func (d *ContentDB) setMinSpringVersion(version string) {
	d.db.Exec(`DELETE FROM min_spring_version`)
	d.db.Exec(`INSERT INTO min_spring_version (min_spring_version, start_time) VALUES (?, ?)`, version, pyTime(time.Now()))
}

// getMinSpringVersion mirrors get_min_spring_version.
func (d *ContentDB) getMinSpringVersion() string {
	var v string
	if err := d.db.QueryRow(`SELECT min_spring_version FROM min_spring_version LIMIT 1`).Scan(&v); err != nil {
		return "*"
	}
	return v
}

// newDB opens the database at the given url and returns all the handler
// structs, mirroring DataHandler's construction of the five handlers.
func newDB(dbURL string, requireVerification bool) (*UserDB, *BanDB, *VerificationDB, *ChannelDB, *BridgedUserDB, *ContentDB, error) {
	db, err := openDB(dbURL)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return &UserDB{db: db},
		&BanDB{db: db},
		&VerificationDB{db: db, requireVerification: requireVerification},
		&ChannelDB{db: db},
		&BridgedUserDB{db: db},
		&ContentDB{db: db},
		nil
}
