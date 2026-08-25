package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

// isoFormat mirrors python's datetime.isoformat(): 'YYYY-MM-DDTHH:MM:SS',
// with the '.ffffff' microsecond part only when the time has microseconds.
func isoFormat(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if t.Nanosecond() != 0 {
		s += fmt.Sprintf(".%06d", t.Nanosecond()/1000)
	}
	return s
}

// inGetUserID mirrors Protocol.in_GETUSERID.
func (p *Protocol) inGetUserID(c *Client, args []string) {
	username := args[0]
	ref := p.root.clientFromUsernameDB(username)
	if ref == nil {
		p.outServerMsg(c, "User not found.", false)
		return
	}
	var lastMacID, lastSysID string
	switch u := ref.(type) {
	case *Client:
		lastMacID, lastSysID = u.lastMacID, u.lastSysID
	case *OfflineUser:
		lastMacID, lastSysID = u.LastMacID, u.LastSysID
	}
	p.outServerMsg(c, fmt.Sprintf("The ID for <%s> is %s %s", username, lastMacID, lastSysID), false)
}

// inFindIP mirrors Protocol.in_FINDIP.
func (p *Protocol) inFindIP(c *Client, args []string) {
	address := args[0]
	for _, entry := range server.userDB.findIP(address) {
		if _, online := p.root.usernames[entry.username]; online {
			p.outServerMsg(c, fmt.Sprintf("<%s> is currently bound to %s.", entry.username, address), false)
		} else {
			lastlogin := "Unknown"
			if !entry.LastLogin.IsZero() {
				lastlogin = isoFormat(entry.LastLogin)
			}
			p.outServerMsg(c, fmt.Sprintf("<%s> was recently bound to %s at %s", entry.username, address, lastlogin), false)
		}
	}
}

// inGetIP mirrors Protocol.in_GETIP.
func (p *Protocol) inGetIP(c *Client, args []string) {
	username := args[0]
	if target := p.root.clientFromUsername(username); target != nil {
		ip := target.ipAddress
		if p.root.trustedProxies[target.ipAddress] {
			ip = fmt.Sprintf("%s via proxy %s", target.localIP, target.ipAddress)
		}
		p.outServerMsg(c, fmt.Sprintf("<%s> is currently bound to %s", username, ip), false)
		return
	}
	if ip := server.userDB.getIP(username); ip != nil {
		p.outServerMsg(c, fmt.Sprintf("<%s> was recently bound to %s", username, *ip), false)
	}
}

// inSetBotMode mirrors Protocol.in_SETBOTMODE.
func (p *Protocol) inSetBotMode(c *Client, args []string) {
	username, mode := args[0], args[1]
	onlineClient := p.root.clientFromUsername(username)
	var offlineUser *OfflineUser
	if onlineClient == nil {
		if ref := p.root.clientFromUsernameDB(username); ref != nil {
			offlineUser = ref.(*OfflineUser)
		}
	}
	if onlineClient == nil && offlineUser == nil {
		return
	}
	bot := strings.ToLower(mode) == "true" || strings.ToLower(mode) == "yes" || strings.ToLower(mode) == "1"
	if onlineClient != nil {
		onlineClient.bot = bot
		server.userDB.saveUser(onlineClient)
		p.calcStatus(onlineClient, onlineClient.status)
		p.root.broadcast(fmt.Sprintf("CLIENTSTATUS %s %d", onlineClient.username, onlineClient.status), "", nil, nil, "", "")
	} else {
		offlineUser.bot = pyInt(bot)
		server.userDB.saveUserDB(offlineUser)
	}
	botStr := "False"
	if bot {
		botStr = "True"
	}
	p.outServerMsg(c, fmt.Sprintf("Botmode for <%s> successfully changed to %s", username, botStr), false)
	if bot {
		p.broadcastModerator(fmt.Sprintf("New bot: <%s> created by <%s>", username, c.username))
	} else {
		p.broadcastModerator(fmt.Sprintf("User <%s> had botflag removed by <%s>", username, c.username))
	}
}

// inBroadcast mirrors Protocol.in_BROADCAST.
func (p *Protocol) inBroadcast(c *Client, args []string) {
	p.root.broadcast("BROADCAST "+args[0], "", nil, nil, "", "")
}

// inBroadcastEx mirrors Protocol.in_BROADCASTEX.
func (p *Protocol) inBroadcastEx(c *Client, args []string) {
	p.root.broadcast("SERVERMSGBOX "+args[0], "", nil, nil, "", "")
}

// inAdminBroadcast mirrors Protocol.in_ADMINBROADCAST.
func (p *Protocol) inAdminBroadcast(c *Client, args []string) {
	p.root.adminBroadcast(args[0])
}

// inSetMinSpringVersion mirrors Protocol.in_SETMINSPRINGVERSION.
func (p *Protocol) inSetMinSpringVersion(c *Client, args []string) {
	version := args[0]
	p.root.minSpringVersion = version
	server.contentDB.setMinSpringVersion(version)
	var legacyBattleIDs []int
	for battleID, battle := range p.root.battles {
		if battle.hasBotflag() && !p.validEngineVersion(battle.engine, battle.version) {
			legacyBattleIDs = append(legacyBattleIDs, battleID)
			hostName := ""
			if host := p.root.clientFromSession(battle.host); host != nil {
				hostName = host.username
			}
			p.broadcastSendBattle(battle, fmt.Sprintf("SAIDBATTLEEX %s -- This battle will close -- Spring %s or later is now required by the server. Please join a battle with the new Spring version!", hostName, version), nil, "", "u")
			p.broadcastSendBattle(battle, fmt.Sprintf("SAIDEX %s %s -- This battle will close -- Spring %s or later is now required by the server. Please join a battle with the new Spring version!", battle.name, hostName, version), nil, "u", "")
		}
	}
	for _, battleID := range legacyBattleIDs {
		p.root.battles[battleID].removeBattle()
		delete(p.root.battles, battleID)
	}
	p.outServerMsg(c, "Set Spring engine version to "+version, false)
}

// inKick mirrors Protocol.in_KICK.
func (p *Protocol) inKick(c *Client, args []string) {
	username := args[0]
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}
	kickedUser := p.root.clientFromUsername(username)
	if kickedUser == nil {
		p.outServerMsg(c, fmt.Sprintf("User <%s> was not online", username), false)
		return
	}
	if battle := p.getCurrentBattle(kickedUser); battle != nil {
		host := p.root.clientFromSession(battle.host)
		host.Send(fmt.Sprintf("KICKFROMBATTLE %d %s", battle.battleID, username))
	}
	p.outServerMsg(kickedUser, fmt.Sprintf("You were kicked from the server (%s)", reason), false)
	kickedUser.Send("SERVERMSGBOX You were kicked from the server (" + reason + ")")
	p.outServerMsg(c, fmt.Sprintf("Kicked <%s> from the server", username), false)
	kickedUser.remove(fmt.Sprintf("was kicked from server by <%s> (%s)", c.username, reason))
}

// inBan mirrors Protocol.in_BAN.
func (p *Protocol) inBan(c *Client, args []string) {
	username, duration, reason := args[0], args[1], args[2]
	good, response := server.banDB.ban(c, duration, reason, username)
	if good {
		if target := p.root.clientFromUsername(username); target != nil {
			p.inKick(c, []string{target.username, "banned"})
		}
		p.broadcastModerator(fmt.Sprintf("%s banned <%s> for %s days (%s)", c.username, username, duration, reason))
	}
	if response != "" {
		p.outServerMsg(c, response, false)
	}
}

// inBanSpecific mirrors Protocol.in_BANSPECIFIC.
func (p *Protocol) inBanSpecific(c *Client, args []string) {
	arg, duration, reason := args[0], args[1], args[2]
	good, response := server.banDB.banSpecific(c, duration, reason, arg)
	if good {
		p.broadcastModerator(fmt.Sprintf("%s banned-specific <%s> for %s days (%s)", c.username, arg, duration, reason))
	}
	if response != "" {
		p.outServerMsg(c, response, false)
	}
}

// inUnban mirrors Protocol.in_UNBAN.
func (p *Protocol) inUnban(c *Client, args []string) {
	arg := args[0]
	good, response := server.banDB.unban(c, arg)
	if good {
		p.broadcastModerator(fmt.Sprintf("%s unbanned <%s>", c.username, arg))
	}
	if response != "" {
		p.outServerMsg(c, response, false)
	}
}

// inBlacklist mirrors Protocol.in_BLACKLIST.
func (p *Protocol) inBlacklist(c *Client, args []string) {
	domain := args[0]
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}
	good, response := server.banDB.blacklist(c, domain, reason)
	if good {
		p.broadcastModerator(fmt.Sprintf("%s blacklisted '%s' (%s)", c.username, domain, reason))
	}
	if response != "" {
		p.outServerMsg(c, response, false)
	}
}

// inUnblacklist mirrors Protocol.in_UNBLACKLIST.
func (p *Protocol) inUnblacklist(c *Client, args []string) {
	domain := args[0]
	good, response := server.banDB.unblacklist(c, domain)
	if good {
		p.broadcastModerator(fmt.Sprintf("%s un-blacklisted '%s'", c.username, domain))
	}
	if response != "" {
		p.outServerMsg(c, response, false)
	}
}

// inListBans mirrors Protocol.in_LISTBANS.
func (p *Protocol) inListBans(c *Client, args []string) {
	banlist := server.banDB.listBans()
	if len(banlist) > 0 {
		p.outServerMsg(c, "-- Banlist --", false)
		for _, entry := range banlist {
			p.outServerMsg(c, fmt.Sprintf("%s, %s, %s :: '%s' :: ends %s (%s)", entry.Username, entry.IP, entry.Email, entry.Reason, entry.EndDate, entry.Issuer), false)
		}
		p.outServerMsg(c, "-- End Banlist --", false)
		return
	}
	p.outServerMsg(c, "Banlist is empty", false)
}

// inListBlacklist mirrors Protocol.in_LISTBLACKLIST.
func (p *Protocol) inListBlacklist(c *Client, args []string) {
	blacklist := server.banDB.listBlacklist()
	if len(blacklist) > 0 {
		p.outServerMsg(c, "-- Blacklist --", false)
		for _, entry := range blacklist {
			p.outServerMsg(c, fmt.Sprintf("%s :: '%s' (%s)", entry.Domain, entry.Reason, entry.Issuer), false)
		}
		p.outServerMsg(c, "-- End Blacklist--", false)
		return
	}
	p.outServerMsg(c, "Blacklist is empty", false)
}

// inSetAccess mirrors Protocol.in_SETACCESS.
func (p *Protocol) inSetAccess(c *Client, args []string) {
	username, access := args[0], args[1]
	ref := p.root.clientFromUsernameDB(username)
	if ref == nil {
		p.outServerMsg(c, "User not found.", false)
		return
	}
	if access != "user" && access != "mod" && access != "admin" {
		p.outServerMsg(c, "Invalid access mode, only user, mod, admin is valid.", false)
		return
	}
	switch u := ref.(type) {
	case *Client:
		u.access = access
		p.calcAccessStatus(u)
		p.root.broadcast(fmt.Sprintf("CLIENTSTATUS %s %d", u.username, u.status), "", nil, nil, "", "")
		server.userDB.saveUser(u)
	case *OfflineUser:
		u.access = access
		server.userDB.saveUserDB(u)
	}
	p.outOK(c, "SETACCESS")
	if access == "mod" || access == "admin" {
		for _, ignoredID := range server.userDB.globallyUnignoreUser(ref.UserID()) {
			if u := p.root.clientFromID(ignoredID); u != nil {
				delete(u.ignored, ref.UserID())
				u.Send("UNIGNORE userName=" + username)
			}
		}
	}
}

// inListMods mirrors Protocol.in_LISTMODS.
func (p *Protocol) inListMods(c *Client, args []string) {
	if !c.accessLevels["mod"] {
		return
	}
	admins, mods := server.userDB.listMods()
	p.outServerMsg(c, "Admins: "+admins, false)
	p.outServerMsg(c, "Mods: "+mods, false)
}

// inCleanup mirrors Protocol.in_CLEANUP.
func (p *Protocol) inCleanup(c *Client, args []string) {
	if !c.accessLevels["admin"] {
		return
	}
	p.cleanup(c)
}

// cleanup mirrors Protocol.cleanup: keep calm, delete all inconsistencies,
// and carry on.
func (p *Protocol) cleanup(client *Client) {
	if client != nil {
		p.broadcastModerator("Cleanup initiated by <" + client.username + ">")
		log.Printf("Cleanup initiated by <%s>", client.username)
	} else {
		p.broadcastModerator("Cleanup initiated by server error")
		log.Printf("Cleanup initiated by server error")
	}

	nClient := 0
	nUsername := 0
	nUserID := 0

	nBridgedLocation := 0
	nBridgedUsername := 0
	nBridgedUserID := 0

	nBridgeExternalID := 0
	nBridgeLocation := 0

	nBattle := 0
	nBattleUser := 0
	nBattlePendingUser := 0

	nChannel := 0
	nChannelUser := 0
	nChannelBridgedUser := 0

	nMismatch := 0

	// the python code wraps the whole body in a try/except that logs
	// "Cleanup failed" and returns
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Cleanup failed: %v", r)
		}
	}()

	root := p.root

	// cleanup clients/sessions
	dupcheck := map[string]bool{}
	var todel []*Client
	for _, c := range root.clients {
		if c.removeReason != "" {
			log.Printf("client not connected: %s %d", c.username, c.sessionID)
			todel = append(todel, c)
			continue
		}
		if dupcheck[c.username] {
			log.Printf("client username failed dup check: %s %d", c.username, c.sessionID)
			todel = append(todel, c)
			continue
		}
		dupcheck[c.username] = true
		if _, ok := root.usernames[c.username]; !ok {
			log.Printf("client with missing username: %s %d", c.username, c.sessionID)
			todel = append(todel, c)
			continue
		}
		if d := root.usernames[c.username]; d.sessionID != c.sessionID {
			log.Printf("missmatched session_id: (%s %d) (%s %d)", c.username, c.sessionID, d.username, d.sessionID)
		}
	}
	for _, c := range todel {
		delete(root.clients, c.sessionID)
		log.Printf("deleted invalid client: %s %d", c.username, c.sessionID)
		nClient++
	}

	// cleanup usernames
	var todelUsernames []string
	for username, c := range root.usernames {
		if _, ok := root.clients[c.sessionID]; !ok {
			log.Printf("username with missing client: %s %d", c.username, c.sessionID)
			todelUsernames = append(todelUsernames, username)
			continue
		}
		if d := root.clients[c.sessionID]; d.username != c.username {
			log.Printf("missmatched username: (%s %d) (%s %d)", d.username, d.sessionID, c.username, c.sessionID)
			nMismatch++
		}
	}
	for _, username := range todelUsernames {
		delete(root.usernames, username)
		log.Printf("deleted invalid username: %s", username)
		nUsername++
	}

	// cleanup user_ids
	var todelUserIDs []int
	for userID, c := range root.userIDs {
		if _, ok := root.clients[c.sessionID]; !ok {
			log.Printf("user_id with missing client: %d<%s> %d", c.userID, c.username, c.sessionID)
			todelUserIDs = append(todelUserIDs, userID)
			continue
		}
		if d := root.clients[c.sessionID]; d.userID != c.userID {
			log.Printf("missmatched user_id: (%d<%s> %d) (%d<%s> %d)", d.userID, d.username, d.sessionID, c.userID, c.username, c.sessionID)
			nMismatch++
		}
	}
	for _, userID := range todelUserIDs {
		delete(root.userIDs, userID)
		log.Printf("deleted invalid user_id: %d", userID)
		nUserID++
	}

	// cleanup bridged locations
	var todelLocations []string
	for location, bridgeUserID := range root.bridgedLocations {
		c := root.userIDs[bridgeUserID]
		// python crashed here when the bridge user was missing; the
		// location is still deleted
		if c == nil {
			log.Printf("location with missing bridge: %s %d", location, bridgeUserID)
			todelLocations = append(todelLocations, location)
			continue
		}
		if _, ok := c.bridge[location]; !ok {
			log.Printf("location with missing bridge: %s %s", location, c.username)
			todelLocations = append(todelLocations, location)
		}
	}
	for _, location := range todelLocations {
		delete(root.bridgedLocations, location)
		log.Printf("deleted invalid bridged location: %s", location)
		nBridgedLocation++
	}

	// cleanup bridge locations
	for _, c := range root.clients {
		var todel []string
		for location := range c.bridge {
			if _, ok := root.bridgedLocations[location]; !ok {
				log.Printf("bridge contains invalid location: %s %s", c.username, location)
				todel = append(todel, location)
			}
		}
		for _, location := range todel {
			delete(c.bridge, location)
			log.Printf("deleted invalid location from bridge: %s %s", c.username, location)
			nBridgeLocation++
		}
	}

	// cleanup bridged usernames
	var todelBridgedUsernames []string
	for bridgedUsername, b := range root.bridgedUsernames {
		bridgeUser, ok := root.userIDs[b.bridgeUserID]
		if b.bridgeUserID == 0 || !ok {
			log.Printf("bridged username with missing bridge: %s %d", b.username, b.bridgeUserID)
			todelBridgedUsernames = append(todelBridgedUsernames, bridgedUsername)
			continue
		}
		if _, ok := bridgeUser.bridge[b.location]; !ok {
			log.Printf("bridged_username has location missing from bridge: %d<%s> %s %s %s", b.bridgedID, b.username, b.location, b.externalID, bridgeUser.username)
			todelBridgedUsernames = append(todelBridgedUsernames, bridgedUsername)
			continue
		}
		if _, ok := bridgeUser.bridge[b.location][b.externalID]; !ok {
			log.Printf("bridged_username has external_id missing from bridge: %d<%s> %s %s %s", b.bridgedID, b.username, b.location, b.externalID, bridgeUser.username)
			todelBridgedUsernames = append(todelBridgedUsernames, bridgedUsername)
		}
	}
	for _, bridgedUsername := range todelBridgedUsernames {
		delete(root.bridgedUsernames, bridgedUsername)
		log.Printf("deleted invalid bridged_username: %s", bridgedUsername)
		nBridgedUsername++
	}

	// cleanup bridged_ids
	var todelBridgedIDs []int
	for bridgedID, b := range root.bridgedIDs {
		bridgeUser, ok := root.userIDs[b.bridgeUserID]
		if b.bridgeUserID == 0 || !ok {
			log.Printf("bridged_id with missing bridge: %d<%s> %d", b.bridgedID, b.username, b.bridgeUserID)
			todelBridgedIDs = append(todelBridgedIDs, bridgedID)
			continue
		}
		if _, ok := bridgeUser.bridge[b.location]; !ok {
			log.Printf("bridged_id has location missing from bridge: %d<%s> %s %s %s", b.bridgedID, b.username, b.location, b.externalID, bridgeUser.username)
			todelBridgedIDs = append(todelBridgedIDs, bridgedID)
			continue
		}
		if _, ok := bridgeUser.bridge[b.location][b.externalID]; !ok {
			log.Printf("bridged_id has external_id missing from bridge: %d<%s> %s %s %s", b.bridgedID, b.username, b.location, b.externalID, bridgeUser.username)
			todelBridgedIDs = append(todelBridgedIDs, bridgedID)
		}
	}
	for _, bridgedID := range todelBridgedIDs {
		delete(root.bridgedIDs, bridgedID)
		log.Printf("deleted invalid bridged_id: %d", bridgedID)
		nBridgedUserID++
	}

	// cleanup bridge external_ids
	for _, c := range root.clients {
		for location, extIDs := range c.bridge {
			var todel []string
			for externalID, bridgedID := range extIDs {
				if _, ok := root.bridgedIDs[bridgedID]; !ok {
					log.Printf("bridge has external_id with missing bridged_id: %s %s %s %d", c.username, location, externalID, bridgedID)
					todel = append(todel, externalID)
				}
			}
			for _, externalID := range todel {
				delete(c.bridge[location], externalID)
				log.Printf("deleted invalid external_id from bridge: %s %s %s", c.username, location, externalID)
				nBridgeExternalID++
			}
		}
	}

	// cleanup battle users
	for battleID, battle := range root.battles {
		for sessionID := range battle.users {
			if _, ok := root.clients[sessionID]; !ok {
				delete(battle.users, sessionID)
				log.Printf("deleted invalid session %d from battle %d", sessionID, battleID)
				nBattleUser++
			}
		}
		for sessionID := range battle.pendingUsers {
			if _, ok := root.clients[sessionID]; !ok {
				delete(battle.pendingUsers, sessionID)
				log.Printf("deleted invalid session %d from pending users for battle %d", sessionID, battleID)
				nBattlePendingUser++
			}
		}
	}

	// cleanup battles
	for battleID, battle := range root.battles {
		if _, ok := root.clients[battle.host]; !ok {
			delete(root.battles, battleID)
			log.Printf("deleted battle %d with invalid host %d", battleID, battle.host)
			nBattle++
			continue
		}
		if len(battle.users) == 0 {
			delete(root.battles, battleID)
			log.Printf("deleted battle %d, empty", battleID)
			nBattle++
		}
	}

	// cleanup channel users & channels
	for chanName, channel := range root.channels {
		for sessionID := range channel.users {
			if _, ok := root.clients[sessionID]; !ok {
				delete(channel.users, sessionID)
				log.Printf("deleted invalid session_id %d from channel %s", sessionID, chanName)
				nChannelUser++
			}
		}
		for bridgedID := range channel.bridgedUsers {
			if _, ok := root.bridgedIDs[bridgedID]; !ok {
				delete(channel.bridgedUsers, bridgedID)
				log.Printf("deleted invalid bridged_id %d from channel %s", bridgedID, chanName)
				nChannelBridgedUser++
			}
		}
		if len(channel.users) == 0 {
			if len(channel.bridgedUsers) > 0 {
				log.Printf("warning: empty channel %s contains %d bridged users", chanName, len(channel.bridgedUsers))
			}
			delete(root.channels, chanName)
			log.Printf("deleted empty channel %s", chanName)
			nChannel++
		}
	}

	cleanedInfo := "deleted:"
	cleanedInfo += fmt.Sprintf("\n %d clients, %d usernames, %d user_ids", nClient, nUsername, nUserID)
	cleanedInfo += fmt.Sprintf("\n %d bridged_locations, %d bridged_usernames, %d bridged_user_ids, %d bridge_external_ids, %d bridge_locations", nBridgedLocation, nBridgedUsername, nBridgedUserID, nBridgeExternalID, nBridgeLocation)
	cleanedInfo += fmt.Sprintf("\n %d battles, %d battle_users, %d battle_pending_users", nBattle, nBattleUser, nBattlePendingUser)
	cleanedInfo += fmt.Sprintf("\n %d channels, %d channel_users, %d channel_bridged_users", nChannel, nChannelUser, nChannelBridgedUser)
	cleanedInfo += fmt.Sprintf("\n found %d mismatches", nMismatch)
	log.Printf("%s", cleanedInfo)

	nDelete := nClient + nUsername + nUserID + nBridgedLocation + nBridgedUsername + nBridgedUserID + nBridgeExternalID + nBridgeLocation + nBattle + nBattleUser + nBattlePendingUser + nChannel + nChannelUser + nChannelBridgedUser
	cleanedMsg := fmt.Sprintf("Cleanup complete: %d deletions, %d mismatches", nDelete, nMismatch)
	if client != nil {
		p.outServerMsg(client, cleanedMsg, false)
	}
	p.broadcastModerator(cleanedMsg)
}

// inResetUserPassword mirrors Protocol.in_RESETUSERPASSWORD.
func (p *Protocol) inResetUserPassword(c *Client, args []string) {
	username := args[0]
	newmail := ""
	if len(args) > 1 {
		newmail = args[1]
	}
	if !server.verificationDB.active() {
		// python called out_SERVERMSG without the client arg here
		// (TypeError); the message is sent to the caller instead
		p.outServerMsg(c, "Email verification is currently turned off, account recovery is disabled", false)
		return
	}
	ref := p.root.clientFromUsernameDB(username)
	if ref == nil {
		p.outServerMsg(c, fmt.Sprintf("User <%s> does not exist", username), false)
		return
	}
	email := ""
	switch u := ref.(type) {
	case *Client:
		email = u.email
	case *OfflineUser:
		email = u.Email
	}
	good, _ := server.verificationDB.validEmailAddr(email)
	if good && newmail != "" {
		p.outServerMsg(c, fmt.Sprintf("User <%s> already has a valid email address (%s), please try again without specifying an email address", username, email), false)
		return
	}
	if !good && newmail == "" {
		p.outServerMsg(c, fmt.Sprintf("User <%s> does not have a valid email address, please specify an email address to add to their account", username), false)
		return
	}
	if !good && newmail != "" {
		goodNew, reasonNew := server.verificationDB.validEmailAddr(newmail)
		if !goodNew {
			p.outServerMsg(c, fmt.Sprintf("The email address '%s' is not valid: %s", newmail, reasonNew), false)
			return
		}
		email = newmail
		switch u := ref.(type) {
		case *Client:
			u.email = newmail
			server.userDB.saveUser(u)
		case *OfflineUser:
			u.Email = newmail
			server.userDB.saveUserDB(u)
		}
	}
	server.verificationDB.resetPassword(ref.UserID(), true)
	p.outServerMsg(c, fmt.Sprintf("An email was sent to '%s' containing a new password for <%s>", email, ref.Username()), true)
}

// inDeleteAccount mirrors Protocol.in_DELETEACCOUNT.
func (p *Protocol) inDeleteAccount(c *Client, args []string) {
	username := args[0]
	ref := p.root.clientFromUsernameDB(username)
	if ref == nil {
		p.outServerMsg(c, fmt.Sprintf("User <%s> does not exist", username), false)
		return
	}
	email := ""
	switch u := ref.(type) {
	case *Client:
		email = u.email
	case *OfflineUser:
		email = u.Email
	}
	if email != "" {
		p.inBanSpecific(c, []string{email, "28", "account deletion request scheduled"})
	}
	p.inKick(c, []string{username, "account deletion request"})
	switch u := ref.(type) {
	case *Client:
		u.ingameTime = 0
		u.bot = false
		u.access = "user"
		u.email = ""
		server.userDB.saveUser(u)
	case *OfflineUser:
		u.IngameTime = 0
		u.bot = 0
		u.access = "user"
		u.Email = ""
		server.userDB.saveUserDB(u)
	}
	server.verificationDB.resetPassword(ref.UserID(), false)
	p.outServerMsg(c, fmt.Sprintf("Account deletion of <%s> scheduled by <%s>", ref.Username(), c.username), true)
}

const createBotPasswordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// createBotPassword mirrors the python random password: 16 chars from
// ascii_letters + digits.
func createBotPassword(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = createBotPasswordCharset[rand.Intn(len(createBotPasswordCharset))]
	}
	return string(b)
}

// inCreateBotAccount mirrors Protocol.in_CREATEBOTACCOUNT.
func (p *Protocol) inCreateBotAccount(c *Client, args []string) {
	username := args[0]
	password := ""
	founderUsername := ""
	if len(args) > 1 {
		password = args[1]
	}
	if len(args) > 2 {
		founderUsername = args[2]
	}
	good, _ := p.validUsernameSyntax(username)
	if !good {
		p.outFailed(c, "CREATEBOTACCOUNT", fmt.Sprintf("Invalid username '%s'", username), true)
		return
	}
	generatedPassword := ""
	if password == "" {
		password = createBotPassword(16)
		generatedPassword = password
	}
	sum := md5.Sum([]byte(password))
	password = base64.StdEncoding.EncodeToString(sum[:])
	good, reason := server.userDB.checkRegisterUser(username, "", "")
	if !good {
		p.outFailed(c, "CREATEBOTACCOUNT", reason, true)
		return
	}
	var founder userRef
	if founderUsername != "" {
		founder = p.root.clientFromUsernameDB(founderUsername)
		if founder == nil {
			p.outFailed(c, "CREATEBOTACCOUNT", fmt.Sprintf("User does not exist '%s'", founderUsername), true)
			return
		}
		// python crashed here (bot_client not defined yet, and the
		// chanserv :register pipeline is not ported); the battle
		// registration for the founder is skipped
		log.Printf("CREATEBOTACCOUNT: skipping battle registration for founder %s", founderUsername)
	}
	server.userDB.registerUser(username, password, "127.0.0.1", "", "")
	botClient := p.root.clientFromUsernameDB(username)
	switch u := botClient.(type) {
	case *Client:
		u.access = "user"
		u.bot = true
		server.userDB.saveUser(u)
	case *OfflineUser:
		u.access = "user"
		u.bot = 1
		server.userDB.saveUserDB(u)
	}
	p.broadcastModerator(fmt.Sprintf("New bot: <%s> created by <%s>", username, c.username))
	msg := fmt.Sprintf("A new bot account <%s> has been created", botClient.Username())
	if founder != nil {
		msg += fmt.Sprintf(", and battle founder <%s>", founder.Username())
	}
	if generatedPassword != "" {
		msg += fmt.Sprintf(", Bot auto-generated password is %s", generatedPassword)
	}
	p.outServerMsg(c, msg, false)
}
