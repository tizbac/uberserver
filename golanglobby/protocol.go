package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ranks mirrors the module-level ranks tuple in Protocol.py.
var ranks = []int{5, 15, 30, 100, 300, 1000, 3000}

// ipv4Re mirrors Protocol.ipRegex (IPv4 dotted-quad, no leading zeros).
var ipv4Re = regexp.MustCompile(`^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$`)

func setOf(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

// restricted mirrors Protocol.restricted: which access level may run which
// command.
var restricted = map[string]map[string]bool{
	"disabled": {},
	"everyone": setOf(
		"EXIT", "PING", "LISTCOMPFLAGS",
		"RESENDVERIFICATION", "RESETPASSWORD", "RESETPASSWORDREQUEST",
		"STARTTLS", "STLS",
	),
	"fresh": setOf(
		"LOGIN", "REGISTER",
	),
	"agreement": setOf(
		"CONFIRMAGREEMENT",
	),
	"user": setOf(
		"ADDBOT", "ADDSTARTRECT", "DISABLEUNITS", "ENABLEUNITS", "ENABLEALLUNITS",
		"FORCEALLYNO", "FORCESPECTATORMODE", "FORCETEAMCOLOR", "FORCETEAMNO",
		"HANDICAP", "JOINBATTLE", "JOINBATTLEACCEPT", "JOINBATTLEDENY",
		"KICKFROMBATTLE", "LEAVEBATTLE", "MYBATTLESTATUS", "BATTLEHOSTMSG",
		"OPENBATTLE", "REMOVEBOT", "REMOVESCRIPTTAGS", "REMOVESTARTRECT",
		"RING", "SETSCRIPTTAGS", "UPDATEBATTLEINFO", "UPDATEBOT",
		"CHANNELS", "CHANNELTOPIC", "JOIN", "LEAVE", "SAY", "SAYEX",
		"SAYPRIVATE", "SAYPRIVATEEX", "GETCHANNELMESSAGES",
		"GETUSERINFO", "RENAMEACCOUNT", "CHANGEPASSWORD", "CHANGEEMAILREQUEST",
		"CHANGEEMAIL", "RESENDVERIFICATION",
		"IGNORE", "UNIGNORE", "IGNORELIST",
		"FRIENDREQUEST", "ACCEPTFRIENDREQUEST", "DECLINEFRIENDREQUEST",
		"UNFRIEND", "FRIENDLIST", "FRIENDREQUESTLIST",
		"MYSTATUS", "PORTTEST", "JSON",
		"BRIDGECLIENTFROM", "UNBRIDGECLIENTFROM", "JOINFROM", "LEAVEFROM",
		"SAYFROM",
		"MUTE", "MUTELIST", "SETCHANNELKEY", "UNMUTE", "SAYBATTLE",
		"SAYBATTLEEX", "SAYBATTLEPRIVATEEX", "FORCELEAVECHANNEL",
		"GETINGAMETIME",
	),
	"mod": setOf(
		"GETUSERID", "GETIP", "FINDIP", "SETBOTMODE", "CREATEBOTACCOUNT",
		"RESETUSERPASSWORD",
		"KICK", "BAN", "BANSPECIFIC", "UNBAN", "BLACKLIST", "UNBLACKLIST",
		"LISTBANS", "LISTBLACKLIST",
	),
	"admin": setOf(
		"ADMINBROADCAST", "BROADCAST", "BROADCASTEX", "SETMINSPRINGVERSION",
		"SETACCESS", "DELETEACCOUNT", "LISTMODS",
		"STATS", "RELOAD", "CLEANUP",
	),
}

// restrictedList mirrors Protocol.restricted_list (the union).
var restrictedList = func() map[string]bool {
	m := map[string]bool{}
	for _, cmds := range restricted {
		for cmd := range cmds {
			m[cmd] = true
		}
	}
	return m
}()

// flagMap mirrors Protocol.flag_map (python dict order: u, sp, b).
var flagMap = map[string]string{
	"u":  "say2",
	"sp": "scriptPassword",
	"b":  "battleAuth",
}

// compFlagOrder preserves python's flag_map iteration order for LISTCOMPFLAGS.
var compFlagOrder = []string{"u", "sp", "b"}

// optionalFlags mirrors Protocol.optional_flags.
var optionalFlags = map[string]bool{"b": true}

// deprecatedFlags mirrors Protocol.deprecated_flags.
var deprecatedFlags = map[string]bool{
	"cl": true, "t": true, "l": true, "a": true, "m": true, "p": true, "et": true,
}

// Protocol mirrors protocol/Protocol.py.
type Protocol struct {
	root     *Server
	commands map[string]commandSpec
}

// commandSpec mirrors the per-handler info python's get_function_args gets
// via inspect: total args (excluding client), how many of the trailing ones
// are optional (have defaults), and the "Expected: ..." hint.
type commandSpec struct {
	total    int
	optional int
	expected string
	fn       func(*Client, []string) // nil = not ported yet
}

func newProtocol(root *Server) *Protocol {
	p := &Protocol{root: root}
	p.commands = map[string]commandSpec{

		// everyone
		"EXIT":                 {total: 1, optional: 1, expected: "[reason]", fn: p.inExit},
		"LISTCOMPFLAGS":        {total: 0, expected: "", fn: p.inListCompFlags},
		"PING":                 {total: 1, optional: 1, expected: "[reply]", fn: p.inPing},
		"RESETPASSWORD":        {total: 2, expected: "email verification_code"},
		"RESETPASSWORDREQUEST": {total: 1, expected: "email"},
		"RESENDVERIFICATION":   {total: 1, expected: "newmail"},
		"STARTTLS":             {total: 0, expected: "", fn: p.inStartTLS},
		"STLS":                 {total: 0, expected: "", fn: p.inSTLS},

		// fresh
		"LOGIN":    {total: 5, optional: 3, expected: "username password [cpu] [local_ip] [sentence_args]", fn: p.inLogin},
		"REGISTER": {total: 3, optional: 1, expected: "username password [email]", fn: p.inRegister},

		// agreement
		"CONFIRMAGREEMENT": {total: 1, optional: 1, expected: "[verification_code]", fn: p.inConfirmAgreement},

		// user: battle
		"ADDBOT":             {total: 4, expected: "name battlestatus teamcolor AIDLL"},
		"ADDSTARTRECT":       {total: 5, expected: "allyno left top right bottom"},
		"BATTLEHOSTMSG":      {total: 3, expected: "battle_name username msg"},
		"DISABLEUNITS":       {total: 1, expected: "units"},
		"ENABLEALLUNITS":     {total: 0, expected: ""},
		"ENABLEUNITS":        {total: 1, expected: "units"},
		"FORCEALLYNO":        {total: 2, expected: "username allyno"},
		"FORCESPECTATORMODE": {total: 1, expected: "username"},
		"FORCETEAMCOLOR":     {total: 2, expected: "username teamcolor"},
		"FORCETEAMNO":        {total: 2, expected: "username teamno"},
		"HANDICAP":           {total: 2, expected: "username value"},
		"JOINBATTLE": {total: 3, optional: 2, expected: "battle_id [key] [scriptPassword]", fn: func(c *Client, a []string) {
			key, keySet := "", false
			if len(a) > 1 {
				key, keySet = a[1], true
			}
			scriptPassword := ""
			if len(a) > 2 {
				scriptPassword = a[2]
			}
			p.inJoinBattle(c, a[0], key, keySet, scriptPassword)
		}},
		"JOINBATTLEACCEPT": {total: 1, expected: "username", fn: func(c *Client, a []string) {
			p.inJoinBattleAccept(c, a[0])
		}},
		"JOINBATTLEDENY": {total: 2, optional: 1, expected: "username [reason]", fn: func(c *Client, a []string) {
			reason := ""
			if len(a) > 1 {
				reason = a[1]
			}
			p.inJoinBattleDeny(c, a[0], reason)
		}},
		"KICKFROMBATTLE": {total: 1, expected: "username"},
		"LEAVEBATTLE": {total: 0, expected: "", fn: func(c *Client, a []string) {
			p.inLeaveBattle(c)
		}},
		"MYBATTLESTATUS": {total: 2, expected: "_battlestatus _myteamcolor"},
		"OPENBATTLE": {total: 9, expected: "type natType key port maxplayers hashcode rank maphash sentence_args", fn: func(c *Client, a []string) {
			p.inOpenBattle(c, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
		}},
		"REMOVEBOT":        {total: 1, expected: "name"},
		"REMOVESCRIPTTAGS": {total: 1, expected: "tags"},
		"REMOVESTARTRECT":  {total: 1, expected: "allyno"},
		"RING":             {total: 1, expected: "username"},
		"SETSCRIPTTAGS":    {total: 1, expected: "scripttags"},
		"UPDATEBATTLEINFO": {total: 4, expected: "SpectatorCount locked maphash mapname"},
		"UPDATEBOT":        {total: 3, expected: "name battlestatus teamcolor"},

		// user: channel
		"CHANNELS": {total: 0, expected: "", fn: func(c *Client, a []string) {
			p.inChannels(c)
		}},
		"CHANNELTOPIC": {total: 2, expected: "chan topic", fn: func(c *Client, a []string) {
			p.inChannelTopic(c, a[0], a[1])
		}},
		"GETCHANNELMESSAGES": {total: 2, expected: "chan last_msg_id", fn: func(c *Client, a []string) {
			p.inGetChannelMessages(c, a[0], a[1])
		}},
		"JOIN": {total: 2, optional: 1, expected: "chan [key]", fn: func(c *Client, a []string) {
			key := ""
			if len(a) > 1 {
				key = a[1]
			}
			p.inJoin(c, a[0], key)
		}},
		"LEAVE": {total: 2, optional: 1, expected: "chan [reason]", fn: func(c *Client, a []string) {
			reason := ""
			if len(a) > 1 {
				reason = a[1]
			}
			p.inLeave(c, a[0], reason)
		}},
		"SAY": {total: 2, expected: "chan msg", fn: func(c *Client, a []string) {
			p.inSay(c, a[0], a[1])
		}},
		"SAYBATTLE": {total: 1, expected: "msg", fn: func(c *Client, a []string) {
			p.inSayBattle(c, a[0])
		}},
		"SAYBATTLEEX": {total: 1, expected: "msg", fn: func(c *Client, a []string) {
			p.inSayBattleEx(c, a[0])
		}},
		"SAYBATTLEPRIVATEEX": {total: 2, expected: "username msg", fn: func(c *Client, a []string) {
			p.inSayBattlePrivateEx(c, a[0], a[1])
		}},
		"SAYEX": {total: 2, expected: "chan msg", fn: func(c *Client, a []string) {
			p.inSayEx(c, a[0], a[1])
		}},
		"SAYPRIVATE": {total: 2, expected: "user msg", fn: func(c *Client, a []string) {
			p.inSayPrivate(c, a[0], a[1])
		}},
		"SAYPRIVATEEX": {total: 2, expected: "user msg", fn: func(c *Client, a []string) {
			p.inSayPrivateEx(c, a[0], a[1])
		}},

		// user: account management
		"CHANGEEMAIL":        {total: 2, optional: 1, expected: "newmail [verification_code]"},
		"CHANGEEMAILREQUEST": {total: 1, expected: "newmail"},
		"CHANGEPASSWORD":     {total: 2, expected: "cur_password new_password"},
		"GETUSERINFO":        {total: 1, optional: 1, expected: "[username]"},
		"RENAMEACCOUNT":      {total: 1, expected: "newname"},

		// user: ignore
		"IGNORE":     {total: 1, expected: "tags"},
		"IGNORELIST": {total: 0, expected: ""},
		"UNIGNORE":   {total: 1, expected: "tags"},

		// user: friend
		"ACCEPTFRIENDREQUEST":  {total: 1, expected: "tags"},
		"DECLINEFRIENDREQUEST": {total: 1, expected: "tags"},
		"FRIENDLIST":           {total: 0, expected: ""},
		"FRIENDREQUEST":        {total: 1, expected: "tags"},
		"FRIENDREQUESTLIST":    {total: 0, expected: ""},
		"UNFRIEND":             {total: 1, expected: "tags"},

		// user: meta
		"JSON":     {total: 1, expected: "rawcmd"},
		"MYSTATUS": {total: 1, expected: "_status"},
		"PORTTEST": {total: 1, expected: "port"},

		// user: bridge bots
		"BRIDGECLIENTFROM": {total: 3, expected: "location external_id external_username", fn: func(c *Client, a []string) {
			p.inBridgeClientFrom(c, a[0], a[1], a[2])
		}},
		"FORCELEAVECHANNEL": {total: 3, optional: 1, expected: "chan user [reason]"},
		"GETINGAMETIME":     {total: 0, expected: ""},
		"JOINFROM": {total: 3, expected: "chan location external_id", fn: func(c *Client, a []string) {
			p.inJoinFrom(c, a[0], a[1], a[2])
		}},
		"LEAVEFROM": {total: 3, expected: "chan location external_id", fn: func(c *Client, a []string) {
			p.inLeaveFrom(c, a[0], a[1], a[2])
		}},
		"MUTE":          {total: 3, optional: 1, expected: "chan user [duration]"},
		"MUTELIST":      {total: 1, expected: "chan"},
		"SETCHANNELKEY": {total: 2, optional: 1, expected: "chan [key]"},
		"SAYFROM": {total: 4, expected: "chan location external_id msg", fn: func(c *Client, a []string) {
			p.inSayFrom(c, a[0], a[1], a[2], a[3])
		}},
		"UNBRIDGECLIENTFROM": {total: 2, expected: "location external_id", fn: func(c *Client, a []string) {
			p.inUnbridgeClientFrom(c, a[0], a[1])
		}},
		"UNMUTE": {total: 2, expected: "chan user"},

		// mod
		"BLACKLIST":         {total: 2, optional: 1, expected: "domain [reason]", fn: p.inBlacklist},
		"BAN":               {total: 3, expected: "username duration reason", fn: p.inBan},
		"BANSPECIFIC":       {total: 3, expected: "arg duration reason", fn: p.inBanSpecific},
		"CREATEBOTACCOUNT":  {total: 3, optional: 2, expected: "username [password] [founder_username]", fn: p.inCreateBotAccount},
		"FINDIP":            {total: 1, expected: "address", fn: p.inFindIP},
		"GETIP":             {total: 1, expected: "username", fn: p.inGetIP},
		"GETUSERID":         {total: 1, expected: "username", fn: p.inGetUserID},
		"KICK":              {total: 2, optional: 1, expected: "username [reason]", fn: p.inKick},
		"LISTBANS":          {total: 0, expected: "", fn: p.inListBans},
		"LISTBLACKLIST":     {total: 0, expected: "", fn: p.inListBlacklist},
		"RESETUSERPASSWORD": {total: 2, optional: 1, expected: "username [newmail]", fn: p.inResetUserPassword},
		"SETBOTMODE":        {total: 2, expected: "username mode", fn: p.inSetBotMode},
		"UNBAN":             {total: 1, expected: "arg", fn: p.inUnban},
		"UNBLACKLIST":       {total: 1, expected: "domain", fn: p.inUnblacklist},

		// admin
		"ADMINBROADCAST":      {total: 1, expected: "msg", fn: p.inAdminBroadcast},
		"BROADCAST":           {total: 1, expected: "msg", fn: p.inBroadcast},
		"BROADCASTEX":         {total: 1, expected: "msg", fn: p.inBroadcastEx},
		"CLEANUP":             {total: 0, expected: "", fn: p.inCleanup},
		"DELETEACCOUNT":       {total: 1, expected: "username", fn: p.inDeleteAccount},
		"LISTMODS":            {total: 0, expected: "", fn: p.inListMods},
		"RELOAD":              {total: 0, expected: "", fn: p.inReload},
		"SETACCESS":           {total: 2, expected: "username access", fn: p.inSetAccess},
		"SETMINSPRINGVERSION": {total: 1, expected: "version", fn: p.inSetMinSpringVersion},
		"STATS":               {total: 0, expected: "", fn: p.inStats},
	}
	for cmd := range restrictedList {
		if _, ok := p.commands[cmd]; !ok {
			log.Printf("WARNING: restricted command %s has no handler spec", cmd)
		}
	}
	return p
}

// handle mirrors Protocol._handle: dispatch one protocol command from a
// client.
func (p *Protocol) handle(c *Client, msg string) {
	// client.Send() prepends client.msg_id if the current thread
	// is the same thread as the client's handler.
	// this works because handling is done in order for each ClientHandler thread
	// so we can be sure client.Send() was performed in the client's own handling code.
	msg = c.setMsgID(msg)
	numSpaces := strings.Count(msg, " ")

	var args string
	command := msg
	if numSpaces > 0 {
		parts := strings.SplitN(msg, " ", 2)
		command = parts[0]
		args = parts[1]
	}

	command = strings.ToUpper(command)

	if !restrictedList[command] {
		if args != "" && len(args) > 64 {
			args = args[:64] + "..."
		}
		p.outServerMsg(c, fmt.Sprintf("%s failed. Unknown command. (args='%s')", command, args), true)
		return
	}

	allowed := false
	for level := range c.accessLevels {
		if restricted[level][command] {
			allowed = true
			break
		}
	}
	if !allowed {
		p.outServerMsg(c, fmt.Sprintf("%s failed. Insufficient rights.", command), true)
		return
	}

	spec := p.commands[command]

	// update statistics
	p.root.inboundCommandStats[command]++

	// get_function_args: check we've got enough words for the required args
	required := spec.total - spec.optional
	if numSpaces < required {
		p.outServerMsg(c, fmt.Sprintf("%s failed. Incorrect arguments. Expected: %s", command, spec.expected), false)
		return
	}
	if spec.fn == nil {
		log.Printf("[protocol] (not yet ported) session %d: %s", c.sessionID, command)
		return
	}

	// bunch the last words together if there are too many of them
	var funArgs []string
	if numSpaces > 0 {
		if numSpaces > spec.total-1 {
			funArgs = strings.SplitN(args, " ", spec.total)
		} else {
			funArgs = strings.Split(args, " ")
		}
	}

	spec.fn(c, funArgs)
}

// broadcastModerator mirrors Protocol.broadcast_Moderator.
// TODO(full port): python calls in_SAY(chanserv, 'moderator', message).
func (p *Protocol) broadcastModerator(msg string) {
	log.Printf("[moderator] %s", msg)
}

// broadcastRemoveBattle mirrors Protocol.broadcast_RemoveBattle.
func (p *Protocol) broadcastRemoveBattle(b *Battle) {
	for _, client := range p.root.usernames {
		client.Send(fmt.Sprintf("BATTLECLOSED %d", b.battleID))
	}
}

// inStats mirrors Protocol.in_STATS.
func (p *Protocol) inStats(c *Client, args []string) {
	if !c.accessLevels["admin"] {
		return
	}
	p.root.stats()
	p.outServerMsg(c, "Stats were printed in the server logfile", false)
}

// prettyTimeDelta mirrors Protocol._pretty_time_delta: given a duration,
// return a human readable time format.
func (p *Protocol) prettyTimeDelta(d time.Duration) string {
	total := int(d / time.Second)
	days := total / 86400
	remainder := total % 86400
	hours := remainder / 3600
	minutes := (remainder % 3600) / 60
	seconds := (remainder % 3600) % 60
	if days > 900 {
		return "a long time"
	}
	var pretty string
	if days > 0 {
		pretty += fmt.Sprintf("%d days ", days)
	}
	if (days > 0 && minutes > 0) || hours > 0 {
		pretty += fmt.Sprintf("%d hours ", hours)
	}
	if (days > 0 && hours > 0) || minutes > 0 {
		pretty += fmt.Sprintf("%d minutes ", minutes)
	}
	if days == 0 && hours == 0 && minutes == 0 {
		pretty += fmt.Sprintf("%d seconds ", seconds)
	}
	return strings.TrimSpace(pretty)
}

// bin2dec mirrors Protocol._bin2dec.
func (p *Protocol) bin2dec(s string) string {
	n, err := strconv.ParseInt(s, 2, 64)
	if err != nil {
		return "0"
	}
	return strconv.FormatInt(n, 10)
}

// newClient mirrors Protocol._new: send the login screen on connect.
// Must run inside a state section (see main.handleConnection).
func (p *Protocol) newClient(client *Client) {
	loginString := fmt.Sprintf("%s %s * %d 0", p.root.serverName, p.root.serverVersion, p.root.natPort)
	if p.root.redirect != "" {
		loginString += "\nREDIRECT " + p.root.redirect
	}
	client.Send(loginString)
	if p.root.redirect != "" {
		// this will make the server not accepting any commands
		// the client will be disconnected with "Connection timed out, didn't login"
		client.removing = true
	}
	log.Printf("[%d] Client connected from %s:%d", client.sessionID, client.ipAddress, client.port)
}

// inStartTLS mirrors Protocol.in_STARTTLS: upgrade the connection to TLS
// and resend the login screen over the secure channel. The handshake is
// connection I/O, so the state lock is released for its duration.
func (p *Protocol) inStartTLS(c *Client, args []string) {
	if server.tlsConfig == nil {
		log.Printf("Error in handling data from client: no TLS certificates loaded")
		c.remove("TLS failed")
		return
	}
	server.stateUnlock()
	c.startTLS()
	server.stateLock()
	if !c.tls {
		return
	}
	c.flushBuffer()
	c.Send(fmt.Sprintf("%s %s * %d 0", p.root.serverName, p.root.serverVersion, p.root.natPort))
}

// inSTLS mirrors Protocol.in_STLS: compatibility acknowledgement only.
func (p *Protocol) inSTLS(c *Client, args []string) {
	c.Send("OK cmd=STLS")
}

// removeClient mirrors Protocol._remove: drop all references to a
// disconnecting client. Must run inside a state section.
func (p *Protocol) removeClient(client *Client, reason string) {
	if client.static {
		return // static clients don't disconnect
	}
	if !client.loggedIn {
		log.Printf("[%d] disconnected from %s: %s", client.sessionID, client.ipAddress, reason)
		return
	}
	log.Printf("[%d] <%s> disconnected from %s: %s", client.sessionID, client.username, client.ipAddress, reason)

	// remove all references related to the client
	for location, extIDs := range client.bridge {
		for _, externalID := range mapKeys(extIDs) {
			bridgedClient := p.root.bridgedClientFromID(extIDs[externalID], false)
			if bridgedClient == nil {
				continue
			}
			for _, chanName := range mapKeys(bridgedClient.channels) {
				p.inLeaveFrom(client, chanName, bridgedClient.location, bridgedClient.externalID)
			}
			p.inUnbridgeClientFrom(client, bridgedClient.location, bridgedClient.externalID)
		}
		delete(p.root.bridgedLocations, location)
	}

	p.removePendingBattle(client)
	if client.currentBattle != nil {
		p.inLeaveBattle(client)
	}
	for _, chanName := range mapKeys(client.channels) {
		p.inLeave(client, chanName, "disconnected")
	}

	delete(p.root.usernames, client.username)
	delete(p.root.userIDs, client.userID)
	// note: p.root.clients is managed by main.go

	p.root.userDB.endSession(client.userID)

	// inform that the client left
	p.broadcastRemoveUser(client)
}

// removePendingBattle mirrors Protocol.removePendingBattle.
func (p *Protocol) removePendingBattle(client *Client) {
	if client.pendingBattle != nil {
		if pendingBattle, ok := p.root.battles[*client.pendingBattle]; ok {
			delete(pendingBattle.pendingUsers, client.sessionID)
		}
		client.pendingBattle = nil
	}
}

// getCurrentBattle mirrors Protocol.getCurrentBattle.
func (p *Protocol) getCurrentBattle(client *Client) *Battle {
	if client.currentBattle == nil {
		return nil
	}
	battleID := *client.currentBattle
	battle, ok := p.root.battles[battleID]
	if !ok {
		log.Printf("Invalid battle (id %d) stored for client %d %s", battleID, client.sessionID, client.username)
		return nil
	}
	return battle
}

// inLeave mirrors Protocol.in_LEAVE: leave target channel.
func (p *Protocol) inLeave(client *Client, chanName, reason string) {
	channel, ok := p.root.channels[chanName]
	if !ok {
		return
	}
	if channel.identity == "battle" && client.username != "ChanServ" {
		p.outFailed(client, "LEAVE", fmt.Sprintf("%s is a battle, use LEAVEBATTLE to leave it", chanName), true)
		return
	}
	if !channel.users[client.sessionID] {
		p.outFailed(client, "LEAVE", "not in channel "+chanName, true)
		return
	}
	channel.removeUser(client, reason)
	if !channel.registered() && len(channel.users) == 0 && len(channel.bridgedUsers) == 0 {
		delete(p.root.channels, chanName)
	}
}

// inLeaveBattle mirrors Protocol.in_LEAVEBATTLE: leave current battle.
func (p *Protocol) inLeaveBattle(client *Client) {
	battle := p.getCurrentBattle(client)
	if battle == nil {
		p.outFailed(client, "LEAVEBATTLE", "not in battle", false)
		return
	}
	if _, ok := p.root.battles[battle.battleID]; !ok {
		p.outFailed(client, "LEAVEBATTLE", "couldn't find battle", false)
		return
	}
	if battle.host == client.sessionID {
		if !battle.registered() {
			delete(p.root.channels, battle.name)
		}
		delete(p.root.battles, battle.battleID)
		battle.removeBattle()
		return
	}
	battle.leaveBattle(client)
}

// inLeaveFrom mirrors Protocol.in_LEAVEFROM: bridged client leaves a channel.
func (p *Protocol) inLeaveFrom(client *Client, chanName, location, externalID string) {
	if !client.compat["u"] {
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		p.outFailed(client, "LEAVEFROM", fmt.Sprintf("Channel '%s' not found", chanName), false)
		return
	}
	bridgedClient := p.root.bridgedClient(location, externalID, false)
	if bridgedClient == nil {
		p.outFailed(client, "LEAVEFROM", fmt.Sprintf("Bridged user (%s,%s) not found", location, externalID), false)
		return
	}
	if bridgedClient.bridgeUserID != client.userID {
		p.outFailed(client, "LEAVEFROM", fmt.Sprintf("Bridged user <%s> is on a different bridge (got %d, expected %d)", bridgedClient.username, bridgedClient.bridgeUserID, client.userID), false)
		return
	}
	channel.removeBridgedUser(client, bridgedClient, "")
}

// inUnbridgeClientFrom mirrors Protocol.in_UNBRIDGECLIENTFROM: tell the
// server that a currently bridged client is gone.
func (p *Protocol) inUnbridgeClientFrom(client *Client, location, externalID string) {
	if !client.compat["u"] {
		return
	}
	bridgedClient := p.root.bridgedClient(location, externalID, false)
	if bridgedClient == nil {
		p.outFailed(client, "UNBRIDGECLIENTFROM", fmt.Sprintf("Bridged client (%s,%s) not found", location, externalID), true)
		return
	}
	if bridgedClient.bridgeUserID != client.userID {
		// python bug list: python's message used an undefined name
		// (dbridgedClient) here; this fixes the typo.
		p.outFailed(client, "UNBRIDGECLIENTFROM", fmt.Sprintf("Bridged client <%s> is on a different bridge (got %d, expected %d)", bridgedClient.username, bridgedClient.bridgeUserID, client.userID), true)
		return
	}
	for _, chanName := range mapKeys(bridgedClient.channels) {
		p.inLeaveFrom(client, chanName, bridgedClient.location, bridgedClient.externalID)
	}
	delete(client.bridge[location], externalID)
	delete(p.root.bridgedIDs, bridgedClient.bridgedID)
	delete(p.root.bridgedUsernames, bridgedClient.username)
	client.Send(fmt.Sprintf("UNBRIDGEDCLIENTFROM %s %s", bridgedClient.location, bridgedClient.externalID))
}

// broadcastRemoveUser mirrors Protocol.broadcast_RemoveUser.
func (p *Protocol) broadcastRemoveUser(client *Client) {
	for _, receiver := range p.root.usernames {
		if client.static {
			continue
		}
		if receiver.username != client.username {
			p.clientRemoveUser(receiver, client)
		}
	}
}

// clientRemoveUser mirrors Protocol.client_RemoveUser.
func (p *Protocol) clientRemoveUser(receiver, user *Client) {
	receiver.Send("REMOVEUSER " + user.username)
}

// validChannelSyntax mirrors Protocol._validChannelSyntax.
func (p *Protocol) validChannelSyntax(channel string) (bool, string) {
	for _, r := range channel {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwzyx[]_1234567890", unicode.ToLower(r)) {
			return false, "Only ASCII chars, [], _, 0-9 are allowed in channel names."
		}
	}
	if utf8.RuneCountInString(channel) > 20 {
		return false, fmt.Sprintf("Channel name '%s' is too long, max is 20 chars.", channel)
	}
	return true, ""
}

// isIgnored mirrors Protocol.is_ignored: does the first client ignore the
// second one? Online clients carry their ignore list in memory; the database
// fallback mirrors python's check for objects without an .ignored attribute.
func (p *Protocol) isIgnored(ignorer, ignored *Client) bool {
	if ignorer.ignored != nil {
		return ignorer.ignored[ignored.userID]
	}
	return p.root.userDB.isIgnored(ignorer.userID, ignored.userID)
}

// inJoin mirrors Protocol.in_JOIN: attempt to join target channel.
func (p *Protocol) inJoin(client *Client, chanName, key string) {
	chanName = strings.TrimLeft(chanName, "#")
	if ok, reason := p.validChannelSyntax(chanName); !ok {
		client.Send("JOINFAILED " + reason)
		return
	}
	// FIXME: unhardcode this
	// python quirk: `chan in ("newbies")` is a substring test, not an equality
	if (client.bot || strings.HasPrefix(client.agent, "SPADS")) && strings.Contains(chanName, "newbies") && client.username != "ChanServ" {
		//client.Send('JOINFAILED %s No bots allowed in #%s!' %(chan, chan))
		return
	}
	if chanName == "moderator" && !client.accessLevels["mod"] {
		p.outFailed(client, "JOIN", fmt.Sprintf("Only moderators allowed in this channel! access=%s", client.access), true)
		return
	}
	if chanName == "" {
		p.outFailed(client, "JOIN", "Invalid channel", false)
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		if strings.HasPrefix(chanName, "__battle__") {
			p.outFailed(client, "JOIN", fmt.Sprintf("cannot create channel %s with prefix __battle__, these names are reserved for battles", chanName), false)
			return
		}
		channel = newChannel(chanName)
		p.root.channels[chanName] = channel
	}
	if channel.users[client.sessionID] {
		// https://github.com/springlobby/springlobby/issues/782
		return
	}
	if channel.identity == "battle" && client.username != "ChanServ" && !client.bot {
		client.Send(fmt.Sprintf("JOINFAILED Channel '%s' is associated to a battle, please use JOINBATTLE to access it", chanName))
		return
	}
	if !channel.isFounder(client) && !client.accessLevels["mod"] {
		if channel.ban[client.userID] != nil || channel.banIP[client.ipAddress] != nil {
			client.Send("JOINFAILED " + chanName + " " + channel.getBanMessage(client))
			return
		}
		// python: channel.key and not channel.key in (key, None, '*', '');
		// setKey normalizes '*' and '' to no key, so this is just a mismatch
		if channel.key != nil && *channel.key != key {
			client.Send("JOINFAILED " + chanName + " Invalid key")
			return
		}
	}
	channel.addUser(client)
}

// broadcastSendBattle mirrors Protocol.broadcast_SendBattle. The
// sourceClient is only sent for SAY*, and RING commands.
// python bug: endtime is the whole mute dict, so `endtime > datetime.now()`
// is a TypeError (twisted then drops the connection), and
// `mutelist.remove[user_id]` would be too. This compares the mute expiry
// properly and deletes the stale entry.
func (p *Protocol) broadcastSendBattle(battle *Battle, data string, sourceClient *Client, flag, notFlag string) {
	if sourceClient != nil {
		if mute, ok := battle.muteList[sourceClient.userID]; ok {
			if mute.expires.After(time.Now()) {
				p.outServerMsg(sourceClient, fmt.Sprintf("SAY You are muted in this battle until %s!", mute.expires), false)
			} else {
				delete(battle.muteList, sourceClient.userID)
			}
		}
	}
	for sessionID := range battle.users {
		other := p.root.clientFromSession(sessionID)
		if other == nil {
			continue
		}
		if flag != "" && !other.compat[flag] {
			continue
		}
		if notFlag != "" && other.compat[notFlag] {
			continue
		}
		if sourceClient == nil || !other.ignored[sourceClient.userID] {
			other.Send(data)
		}
	}
}

// inSay mirrors Protocol.in_SAY: send a message to all users in the
// specified channel. The client must be in the channel to send it.
func (p *Protocol) inSay(client *Client, chanName, msg string) {
	if msg == "" {
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		p.outFailed(client, "SAY", "Channel "+chanName+" does not exist", false)
		return
	}
	if !channel.users[client.sessionID] {
		p.outFailed(client, "SAY", "Not present in channel "+chanName, false)
		return
	}
	msg = sayHooks.hookSay(client, channel, msg)
	if msg == "" || strings.TrimSpace(msg) == "" {
		return
	}
	if channel.isMuted(client) {
		client.Send(fmt.Sprintf("CHANNELMESSAGE %s You are %s.", chanName, channel.getMuteMessage(client)))
		return
	}
	if channel.storeHistory {
		p.root.userDB.addChannelMessage(channel.id, client.userID, nil, msg, false, time.Time{})
	}

	p.root.broadcast(fmt.Sprintf("SAID %s %s %s", chanName, client.username, msg), chanName, nil, client, "u", "")

	// backwards compat
	if client.currentBattle != nil {
		// python would KeyError (and drop the connection) if the battle is
		// gone; here we just fall through to the final broadcast
		if battle, ok := p.root.battles[*client.currentBattle]; ok && battle.name == chanName {
			p.broadcastSendBattle(battle, fmt.Sprintf("SAIDBATTLE %s %s", client.username, msg), client, "", "u")
			return
		}
	}
	p.root.broadcast(fmt.Sprintf("SAID %s %s %s", chanName, client.username, msg), chanName, nil, client, "", "u")
}

// inSayEx mirrors Protocol.in_SAYEX: send an action to all users in the
// specified channel. The client must be in the channel to show an action.
func (p *Protocol) inSayEx(client *Client, chanName, msg string) {
	if msg == "" {
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		p.outFailed(client, "SAYEX", "Channel "+chanName+" does not exist", false)
		return
	}
	if !channel.users[client.sessionID] {
		p.outFailed(client, "SAYEX", "Not present in channel "+chanName, false)
		return
	}
	msg = sayHooks.hookSay(client, channel, msg)
	if msg == "" || strings.TrimSpace(msg) == "" {
		return
	}
	if channel.isMuted(client) {
		client.Send(fmt.Sprintf("CHANNELMESSAGE %s You are %s.", chanName, channel.getMuteMessage(client)))
		return
	}
	if channel.storeHistory {
		p.root.userDB.addChannelMessage(channel.id, client.userID, nil, msg, true, time.Time{})
	}

	p.root.broadcast(fmt.Sprintf("SAIDEX %s %s %s", chanName, client.username, msg), chanName, nil, client, "u", "")

	// backwards compat
	if client.currentBattle != nil {
		if battle, ok := p.root.battles[*client.currentBattle]; ok && battle.name == chanName {
			p.broadcastSendBattle(battle, fmt.Sprintf("SAIDBATTLEEX %s %s", client.username, msg), client, "", "u")
			return
		}
	}
	p.root.broadcast(fmt.Sprintf("SAIDEX %s %s %s", chanName, client.username, msg), chanName, nil, client, "", "u")
}

// inSayPrivate mirrors Protocol.in_SAYPRIVATE: send a message in private to
// another user.
func (p *Protocol) inSayPrivate(client *Client, user, msg string) {
	if msg == "" {
		return
	}
	receiver := p.root.clientFromUsername(user)
	if receiver == nil {
		log.Printf("[%d] <%s>: user to pm is not online: %s", client.sessionID, client.username, user)
		return
	}
	client.Send("SAYPRIVATE " + user + " " + msg)
	if !p.isIgnored(receiver, client) {
		receiver.Send(fmt.Sprintf("SAIDPRIVATE %s %s", client.username, msg))
	}
}

// inSayPrivateEx mirrors Protocol.in_SAYPRIVATEEX: send an action in private
// to another user.
func (p *Protocol) inSayPrivateEx(client *Client, user, msg string) {
	if msg == "" {
		return
	}
	receiver := p.root.clientFromUsername(user)
	if receiver == nil {
		return
	}
	client.Send("SAYPRIVATEEX " + user + " " + msg)
	if !p.isIgnored(receiver, client) {
		receiver.Send(fmt.Sprintf("SAIDPRIVATEEX %s %s", client.username, msg))
	}
}

// inChannels mirrors Protocol.in_CHANNELS: return a listing of all channels
// on the server.
func (p *Protocol) inChannels(client *Client) {
	for _, name := range sortedStringKeys(p.root.channels) {
		channel := p.root.channels[name]
		if channel.key != nil {
			continue
		}
		top := ""
		if channel.topic != nil {
			top = *channel.topic
		}
		client.Send(fmt.Sprintf("CHANNEL %s %d %s", channel.name, len(channel.users), top))
	}
	client.Send("ENDOFCHANNELS")
}

// inChannelTopic mirrors Protocol.in_CHANNELTOPIC: set the topic in target
// channel. [operator]
func (p *Protocol) inChannelTopic(client *Client, chanName, topic string) {
	channel, ok := p.root.channels[chanName]
	if !ok {
		return
	}
	if channel.isOp(client) {
		channel.setTopic(client, topic)
	}
}

// saidJSON mirrors the dict python's out_JSON builds for SAID; the struct
// field order keeps the json.dumps key order stable.
type saidJSON struct {
	ChanName string `json:"chanName"`
	Time     string `json:"time"`
	UserName string `json:"userName"`
	Msg      string `json:"msg"`
	ExMsg    int    `json:"ex_msg"`
	ID       int    `json:"id"`
}

// outJSON mirrors Protocol.out_JSON.
func (p *Protocol) outJSON(client *Client, cmd string, v any) {
	data, _ := json.Marshal(map[string]any{cmd: v})
	client.Send("JSON " + string(data))
}

// inGetChannelMessages mirrors Protocol.in_GETCHANNELMESSAGES: get historical
// messages from the channel since the specified id.
func (p *Protocol) inGetChannelMessages(client *Client, chanName, lastMsgID string) {
	channel, ok := p.root.channels[chanName]
	if !ok {
		return
	}
	if channel.id == 0 {
		return // unregistered channels use id 0
	}
	if !channel.users[client.sessionID] {
		p.outFailed(client, "GETCHANNELMESSAGES", "Can't get channel messages when not joined", true)
		return
	}
	id, err := strconv.Atoi(lastMsgID)
	if err != nil {
		p.outFailed(client, "GETCHANNELMESSAGES", "Invalid id", true)
		return
	}
	for _, m := range p.root.userDB.getChannelMessages(channel.id, id) {
		p.outJSON(client, "SAID", saidJSON{
			ChanName: chanName,
			Time:     strconv.FormatInt(m.Time.Unix(), 10),
			UserName: m.Username,
			Msg:      m.Msg,
			ExMsg:    pyInt(m.ExMsg),
			ID:       m.ID,
		})
	}
}

// versionTuple mirrors Protocol._versiontuple: parse a version string into a
// comparable tuple, dropping everything after the first non [0-9.] char.
func (p *Protocol) versionTuple(version string) []int {
	v := ""
	for _, c := range version {
		if (c < '0' || c > '9') && c != '.' {
			break
		}
		v += string(c)
	}
	parts := strings.Split(v, ".")
	tuple := make([]int, 0, len(parts))
	for _, part := range parts {
		n, _ := strconv.Atoi(part)
		tuple = append(tuple, n)
	}
	if len(tuple) == 1 {
		tuple = append(tuple, 0)
	}
	return tuple
}

// validEngineVersion mirrors Protocol._validEngineVersion.
func (p *Protocol) validEngineVersion(engine, version string) bool {
	if engine != "spring" {
		return false
	}
	minver := p.root.minSpringVersion
	if minver == "*" {
		return true
	}
	if version == "" {
		return false
	}
	a, b := p.versionTuple(version), p.versionTuple(minver)
	for i := 0; i < len(a) || i < len(b); i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return av > bv
		}
	}
	return true
}

// validBridgeSyntax mirrors Protocol._validBridgeSyntax.
func (p *Protocol) validBridgeSyntax(location, externalID, externalUsername string) (bool, string) {
	if externalID == "" {
		return false, "external_id is blank."
	}
	if location == "" {
		return false, "location is blank."
	}
	if externalUsername == "" {
		return false, "external_username is blank."
	}
	for _, r := range externalUsername {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwzyx[]_1234567890#", unicode.ToLower(r)) {
			return false, fmt.Sprintf("external_username '%s' is invalid: only ASCII chars, [], _, 0-9 and # are allowed in bridged usernames.", externalUsername)
		}
	}
	if utf8.RuneCountInString(externalUsername) > 20 {
		return false, fmt.Sprintf("external_username '%s' is too long, max is 20 chars.", externalUsername)
	}
	if strings.Contains(externalID, ":") {
		return false, "Char : is not allowed in external_id"
	}
	for _, r := range location {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwzyx[]_1234567890.", unicode.ToLower(r)) {
			return false, "Only ASCII chars, [], _, 0-9 and . are allowed in location names."
		}
	}
	if utf8.RuneCountInString(externalID) > 20 {
		return false, fmt.Sprintf("external_id '%s' is too long, max is 20 chars.", externalID)
	}
	if utf8.RuneCountInString(location) > 20 {
		return false, fmt.Sprintf("location '%s' is too long, max is 20 chars.", location)
	}
	return true, ""
}

// getNextBattleID mirrors Protocol._getNextBattleId.
func (p *Protocol) getNextBattleID() int {
	p.root.nextBattle++
	return p.root.nextBattle
}

// addPendingBattle mirrors Protocol.addPendingBattle.
func (p *Protocol) addPendingBattle(client *Client, battle *Battle) {
	p.removePendingBattle(client)
	battle.pendingUsers[client.sessionID] = true
	bid := battle.battleID
	client.pendingBattle = &bid
}

// broadcastAddBattle mirrors Protocol.broadcast_AddBattle (logged-in users
// only, like python's self._root.usernames).
func (p *Protocol) broadcastAddBattle(battle *Battle) {
	for _, client := range p.root.usernames {
		client.Send(p.clientAddBattle(client, battle))
	}
}

// outOpenBattleFailed mirrors Protocol.out_OPENBATTLEFAILED.
func (p *Protocol) outOpenBattleFailed(client *Client, reason string) {
	client.Send("OPENBATTLEFAILED " + reason)
	log.Printf("[%d] <%s> OPENBATTLEFAILED: %s", client.sessionID, client.username, reason)
}

// inOpenBattle mirrors Protocol.in_OPENBATTLE: host a new battle.
func (p *Protocol) inOpenBattle(client *Client, typ, natType, key, portStr, maxPlayers, hashcode, rank, maphash, sentenceArgs string) {
	if client.currentBattle != nil {
		p.inLeaveBattle(client)
	}

	engine, version, mapName, title, modname := "", "", "", "", ""
	tabcount := strings.Count(sentenceArgs, "\t")
	if tabcount == 4 {
		parts := strings.SplitN(sentenceArgs, "\t", 5)
		engine, version, mapName, title, modname = parts[0], parts[1], parts[2], parts[3], parts[4]
	} else {
		p.outOpenBattleFailed(client, fmt.Sprintf("Invalid arguments (%d): %s", tabcount, sentenceArgs))
		return
	}

	titleCensored, ok := sayHooks.hookOpenBattle(client, title)
	if !ok {
		// python crashes here (None.strip()) and twisted drops the
		// connection; we reject gracefully instead
		p.outOpenBattleFailed(client, "Invalid title")
		return
	}
	title = strings.TrimSpace(titleCensored)

	checkvars := [][2]string{
		{engine, "No engine specified."},
		{version, "No engine version specified."},
		{mapName, "No map name specified"},
		{title, "No title specified"},
		{modname, "No game name specified"},
	}
	for _, cv := range checkvars {
		if cv[0] == "" {
			p.outOpenBattleFailed(client, cv[1])
			return
		}
	}

	if client.bot && !p.validEngineVersion(engine, version) {
		p.outOpenBattleFailed(client, fmt.Sprintf("Engine version specified (%s,%s) is invalid: Spring %s or later is required!", engine, version, p.root.minSpringVersion))
		return
	}

	battleID := p.getNextBattleID()

	typeID, nat, port, mapHash, gameHash, maxPl := 0, 0, 0, int32(0), int32(0), int32(0)
	var parseErr error
	if typeID, parseErr = strconv.Atoi(typ); parseErr == nil {
		if nat, parseErr = strconv.Atoi(natType); parseErr == nil {
			if port, parseErr = strconv.Atoi(portStr); parseErr == nil {
				if v, e := strconv.ParseInt(maphash, 10, 32); e != nil {
					parseErr = e
				} else {
					mapHash = int32(v)
				}
			}
			if parseErr == nil {
				if v, e := strconv.ParseInt(hashcode, 10, 32); e != nil {
					parseErr = e
				} else {
					gameHash = int32(v)
				}
			}
			if parseErr == nil {
				if v, e := strconv.ParseInt(maxPlayers, 10, 32); e != nil {
					parseErr = e
				} else {
					maxPl = int32(v)
				}
			}
		}
	}
	if parseErr != nil {
		p.outOpenBattleFailed(client, fmt.Sprintf("Invalid argument type, send this to your lobby dev: id=%d type=%s natType=%s key=%s port=%s maphash=%s gamehash=%s - %s",
			battleID, typ, natType, key, portStr, maphash, hashcode, strings.ReplaceAll(parseErr.Error(), "\n", "")))
		return
	}

	if port < 1 || port > 65535 {
		p.outOpenBattleFailed(client, fmt.Sprintf("Port is out of range: 1-65535: %d", port))
		return
	}

	if gameHash == 0 {
		p.outOpenBattleFailed(client, "Invalid game hash 0")
		return
	}

	if !client.tls {
		p.outServerMsg(client, "A TLS connection is required to host battles. Please upgrade your client.", false)
		return
	}

	noflagLimit := 8
	if !client.bot && int(maxPl) > noflagLimit {
		maxPl = int32(noflagLimit)
		p.outServerMsg(client, fmt.Sprintf("A botflag is required to host battles with > %d players. Your battle was restricted to %d players", noflagLimit, noflagLimit), false)
	}

	battleName := "__battle__" + strconv.Itoa(client.userID)
	var battle *Battle
	if c, exists := p.root.channels[battleName]; exists {
		battle = c.battle
	}
	if battle == nil {
		battle = newBattle(battleName)
		p.root.channels[battleName] = battle.Channel
	}

	battle.battleID = battleID
	battle.host = client.sessionID
	battleKey := key
	battle.key = &battleKey
	battle.bType = strconv.Itoa(typeID)
	battle.natType = nat
	battle.port = port
	battle.title = title
	battle.mapName = mapName
	mapHashStr := strconv.FormatInt(int64(mapHash), 10)
	battle.mapHash = &mapHashStr
	battle.modName = modname
	gameHashStr := strconv.FormatInt(int64(gameHash), 10)
	battle.hashCode = &gameHashStr
	battle.engine = engine
	battle.version = version
	battle.rank = rank
	battle.maxPlayers = int(maxPl)

	p.root.battles[battle.battleID] = battle
	p.broadcastAddBattle(battle)

	client.Send("OPENBATTLE " + strconv.Itoa(battle.battleID))
	battle.joinBattle(client)
}

// inJoinBattle mirrors Protocol.in_JOINBATTLE: attempt to join target battle.
func (p *Protocol) inJoinBattle(client *Client, battleIDStr, key string, keySet bool, scriptPassword string) {
	if scriptPassword != "" {
		client.scriptPassword = &scriptPassword
	}
	battleID, err := strconv.ParseInt(battleIDStr, 10, 32)
	if err != nil {
		client.Send(fmt.Sprintf("JOINBATTLEFAILED Invalid battle id: %s.", battleIDStr))
		return
	}
	if client.currentBattle != nil {
		if _, inBattle := p.root.battles[*client.currentBattle]; inBattle {
			client.Send("JOINBATTLEFAILED You are already in a battle")
			return
		}
	}
	battle, ok := p.root.battles[int(battleID)]
	if !ok {
		client.Send("JOINBATTLEFAILED Battle does not exist")
		return
	}
	if battle.users[client.sessionID] {
		client.Send("JOINBATTLEFAILED Client is already in battle")
		return
	}
	host := p.root.clientFromSession(battle.host)
	if !battle.isFounder(client) && !client.accessLevels["mod"] {
		noKey := battle.key == nil || *battle.key == "*"
		// python compares against None when no key was sent, so a battle
		// with an empty key only accepts an explicitly empty key
		if !noKey && !(keySet && *battle.key == key) {
			client.Send("JOINBATTLEFAILED Incorrect password")
			return
		}
		if battle.ban[client.userID] != nil {
			client.Send("JOINBATTLEFAILED You are banned from the battle")
			return
		}
		if battle.locked {
			client.Send("JOINBATTLEFAILED Battle is locked")
			return
		}
	}
	if host != nil && host.compat["b"] && !client.accessLevels["mod"] { // use battleAuth
		if battle.pendingUsers[client.sessionID] {
			client.Send("JOINBATTLEFAILED Waiting for JOINBATTLEACCEPT/JOINBATTLEDENIED from host")
		} else {
			p.addPendingBattle(client, battle)
		}
		clientIP := client.ipAddress
		if p.root.trustedProxies[client.ipAddress] {
			clientIP = client.localIP
		}
		host.Send(fmt.Sprintf("JOINBATTLEREQUEST %s %s", client.username, clientIP))
		return
	}
	p.removePendingBattle(client)
	battle.joinBattle(client)
}

// inJoinBattleAccept mirrors Protocol.in_JOINBATTLEACCEPT: allow a user to
// join your battle, sent as a response to JOINBATTLEREQUEST. [host]
func (p *Protocol) inJoinBattleAccept(client *Client, username string) {
	user := p.root.clientFromUsername(username)
	if user == nil {
		p.outFailed(client, "JOINBATTLEACCEPT", fmt.Sprintf("Couldn't find user %s", username), true)
		return
	}
	battle := p.getCurrentBattle(client)
	if battle == nil {
		// python would crash here (None.host) and drop the connection
		return
	}
	if client.sessionID != battle.host {
		p.outFailed(client, "JOINBATTLEACCEPT", fmt.Sprintf("Client isn't the specified host, %d vs %d", client.sessionID, battle.host), true)
		return
	}
	if !battle.pendingUsers[user.sessionID] {
		return
	}
	p.removePendingBattle(user)
	battle.joinBattle(user)
}

// inJoinBattleDeny mirrors Protocol.in_JOINBATTLEDENY: deny a user from
// joining your battle, sent as a response to JOINBATTLEREQUEST. [host]
func (p *Protocol) inJoinBattleDeny(client *Client, username, reason string) {
	user := p.root.clientFromUsername(username)
	if user == nil {
		return
	}
	battle := p.getCurrentBattle(client)
	if battle == nil {
		return
	}
	if client.sessionID != battle.host {
		return
	}
	if !battle.pendingUsers[user.sessionID] {
		return
	}
	p.removePendingBattle(user)
	if reason != "" {
		reason = " (" + reason + ")"
	}
	user.Send("JOINBATTLEFAILED Access denied by host" + reason)
}

// inSayBattle mirrors Protocol.in_SAYBATTLE: send a message to all users in
// the current battle.
func (p *Protocol) inSayBattle(client *Client, msg string) {
	battle := p.getCurrentBattle(client)
	if battle == nil {
		return
	}
	p.inSay(client, battle.name, msg)
}

// inSayBattleEx mirrors Protocol.in_SAYBATTLEEX: send an action to all users
// in the current battle.
func (p *Protocol) inSayBattleEx(client *Client, msg string) {
	battle := p.getCurrentBattle(client)
	if battle == nil {
		return
	}
	p.inSayEx(client, battle.name, msg)
}

// inSayBattlePrivateEx mirrors Protocol.in_SAYBATTLEPRIVATEEX: send an
// action in private to another user in the current battle.
func (p *Protocol) inSayBattlePrivateEx(client *Client, username, msg string) {
	if username == "" {
		return
	}
	battle := p.getCurrentBattle(client)
	if battle == nil {
		return
	}
	p.inBattleHostMsg(client, battle.name, username, msg)
}

// inBattleHostMsg mirrors Protocol.in_BATTLEHOSTMSG: battle host sends a
// 'servermsg' style message, within a battle, to a single user.
func (p *Protocol) inBattleHostMsg(client *Client, battleName, username, msg string) {
	battle := p.getCurrentBattle(client)
	if battle == nil {
		return
	}
	if client.sessionID != battle.host {
		return
	}
	if battle.name != battleName {
		return
	}
	user := p.root.clientFromUsername(username)
	if user == nil {
		return
	}
	if !battle.users[user.sessionID] {
		return
	}
	if p.isIgnored(user, client) || battle.muteList[client.userID] != nil {
		return
	}
	if !user.compat["u"] {
		user.Send(fmt.Sprintf("SAIDBATTLEEX %s %s", client.username, msg))
		return
	}
	user.Send(fmt.Sprintf("SAIDEX %s %s %s", battle.name, client.username, msg))
}

// inBridgeClientFrom mirrors Protocol.in_BRIDGECLIENTFROM: add external user
// to the bridge.
func (p *Protocol) inBridgeClientFrom(client *Client, location, externalID, externalUsername string) {
	if !client.compat["u"] {
		p.outFailed(client, "BRIDGECLIENTFROM", "You need the 'u' compatibility flag to bridge clients", true)
		return
	}
	if !client.bot {
		if !client.isHosting() {
			p.outFailed(client, "BRIDGECLIENTFROM", "Only bot users and battle hosts can bridge clients", true)
			return
		}
		if location != client.username {
			p.outFailed(client, "BRIDGECLIENTFROM", fmt.Sprintf("You are only allowed to bridge clients with location '%s'", client.username), true)
			return
		}
	}
	if good, reason := p.validBridgeSyntax(location, externalID, externalUsername); !good {
		p.outFailed(client, "BRIDGECLIENTFROM", "Invalid syntax: "+reason, true)
		return
	}
	locationClient := p.root.clientFromUsernameDB(location)
	if locationClient != nil && locationClient.Bot() && location != client.username {
		p.outFailed(client, "BRIDGECLIENTFROM", "You cannot bridge from a location named after another bot user", true)
		return
	}
	if _, exists := p.root.bridgedLocations[location]; !exists {
		p.root.bridgedLocations[location] = client.userID
		client.bridge[location] = map[string]int{}
		p.outServerMsg(client, fmt.Sprintf("You are now the bridge bot for location '%s'", location), false)
	}
	if p.root.bridgedLocations[location] != client.userID {
		existing := p.root.clientFromID(p.root.bridgedLocations[location])
		// python would crash on .username if the bridge bot is offline
		existingName := "None"
		if existing != nil {
			existingName = existing.username
		}
		p.outFailed(client, "BRIDGECLIENTFROM", fmt.Sprintf("The location '%s' is already in use by bridge bot %s", location, existingName), true)
		return
	}
	if _, exists := client.bridge[location]; !exists {
		client.bridge[location] = map[string]int{}
	}
	if !client.bot && len(client.bridge[location]) > 256 {
		p.outFailed(client, "BRIDGECLIENTFROM", "You have reached your maximum allowed number (256) of bridged clients", true)
		return
	}

	good, bridgedClient, response := p.root.bridgedUserDB.bridgeUser(location, externalID, externalUsername)
	if !good {
		p.outFailed(client, "BRIDGECLIENTFROM", response, true)
		return
	}
	if _, exists := p.root.bridgedIDs[bridgedClient.bridgedID]; exists {
		p.outFailed(client, "BRIDGECLIENTFROM", fmt.Sprintf("The client already exists on the bridge (%s,%s)", bridgedClient.location, bridgedClient.externalID), true)
		return
	}

	// copy db values to our local bridged client
	local := newBridgedClient()
	local.bridgedID = bridgedClient.bridgedID
	local.externalID = bridgedClient.externalID
	local.location = bridgedClient.location
	local.lastBridged = bridgedClient.lastBridged
	local.username = bridgedClient.username
	local.externalUsername = bridgedClient.externalUsername
	local.channels = map[string]bool{}
	local.bridgeUserID = client.userID
	client.bridge[location][local.externalID] = local.bridgedID
	p.root.bridgedIDs[local.bridgedID] = local
	p.root.bridgedUsernames[local.username] = local
	client.Send(fmt.Sprintf("BRIDGEDCLIENTFROM %s %s %s", local.location, local.externalID, local.externalUsername))
}

// inJoinFrom mirrors Protocol.in_JOINFROM: bridged client joins a channel.
func (p *Protocol) inJoinFrom(client *Client, chanName, location, externalID string) {
	if !client.compat["u"] {
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Channel '%s' not found", chanName), false)
		return
	}
	isBattleHost := channel.identity == "battle" && channel.battle != nil && client.sessionID == channel.battle.host
	if channel.hasKey() && !isBattleHost {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Cannot bridge to #%s, this channel has a password", chanName), false)
		return
	}
	if channel.identity != "battle" && !client.bot {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("A botflag is needed to bridge clients into #%s", chanName), false)
		return
	}
	if channel.identity == "battle" && !isBattleHost {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Only the battle host can bridge clients into #%s", chanName), false)
		return
	}
	bridgedClient := p.root.bridgedClient(location, externalID, false)
	if bridgedClient == nil {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Bridged user (%s,%s) not found", location, externalID), false)
		return
	}
	if bridgedClient.bridgeUserID != client.userID {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Bridged client <%s> is on a different bridge (got %d, expected %d)", bridgedClient.username, bridgedClient.bridgeUserID, client.userID), false)
		return
	}
	if channel.bridgedBan[bridgedClient.bridgedID] != nil {
		p.outFailed(client, "JOINFROM", fmt.Sprintf("Bridged user <%s> is banned from channel #%s", bridgedClient.username, chanName), false)
		return
	}
	channel.addBridgedUser(client, bridgedClient)
}

// inSayFrom mirrors Protocol.in_SAYFROM: bridged client speaks in a channel.
func (p *Protocol) inSayFrom(client *Client, chanName, location, externalID, msg string) {
	if msg == "" {
		return
	}
	channel, ok := p.root.channels[chanName]
	if !ok {
		return
	}
	bridgedClient := p.root.bridgedClient(location, externalID, false)
	if bridgedClient == nil || bridgedClient.bridgeUserID != client.userID {
		return
	}
	if !channel.bridgedUsers[bridgedClient.bridgedID] {
		p.outFailed(client, "SAYFROM", fmt.Sprintf("Bridged user <%s> not present in channel", bridgedClient.username), false)
		return
	}
	if channel.storeHistory {
		p.root.userDB.addChannelMessage(channel.id, client.userID, &bridgedClient.bridgedID, msg, false, time.Time{})
	}

	p.root.broadcast(fmt.Sprintf("SAIDFROM %s %s %s", chanName, bridgedClient.username, msg), chanName, nil, client, "u", "")

	// backwards compat
	compatMsg := "<" + bridgedClient.username + "> " + msg
	if channel.identity == "battle" {
		p.root.broadcast(fmt.Sprintf("SAIDBATTLE %s %s", client.username, compatMsg), chanName, nil, client, "", "u")
	} else {
		p.root.broadcast(fmt.Sprintf("SAID %s %s %s", chanName, client.username, compatMsg), chanName, nil, client, "", "u")
	}
}

// outFailed mirrors Protocol.out_FAILED.
func (p *Protocol) outFailed(client *Client, cmd, message string, logIt bool) {
	client.Send(fmt.Sprintf("FAILED msg=%s\tcmd=%s", message, cmd))
	if logIt {
		log.Printf("[%d] <%s>: %s %s", client.sessionID, client.username, cmd, message)
	}
}

// outServerMsg mirrors Protocol.out_SERVERMSG.
func (p *Protocol) outServerMsg(client *Client, message string, logIt bool) {
	client.Send("SERVERMSG " + message)
	if logIt {
		log.Printf("[%d] <%s>: %s", client.sessionID, client.username, message)
	}
}

// outOK mirrors Protocol.out_OK.
func (p *Protocol) outOK(client *Client, cmd string) {
	client.Send("OK cmd=" + cmd)
}

// inPing mirrors Protocol.in_PING.
func (p *Protocol) inPing(c *Client, args []string) {
	reply := ""
	if len(args) > 0 {
		reply = args[0]
	}
	if reply != "" {
		c.Send("PONG " + reply)
	}
}

// inExit mirrors Protocol.in_EXIT.
func (p *Protocol) inExit(c *Client, args []string) {
	reason := "Exiting"
	if len(args) > 0 {
		reason = args[0]
	}
	if reason != "" {
		reason = "Quit: " + reason
	} else {
		reason = "Quit"
	}
	c.remove(reason)
}

// inListCompFlags mirrors Protocol.in_LISTCOMPFLAGS.
func (p *Protocol) inListCompFlags(c *Client, args []string) {
	c.Send("COMPFLAGS " + strings.Join(compFlagOrder, " "))
}

// inReload mirrors Protocol.in_RELOAD.
func (p *Protocol) inReload(c *Client, args []string) {
	p.broadcastModerator("Reload initiated by <" + c.username + ">")
	if !c.accessLevels["admin"] {
		return
	}
	ret := p.root.reload(c)
	p.broadcastModerator(ret)
	p.outServerMsg(c, ret, false)
}

// dec2bin mirrors Protocol._dec2bin: decimal to a zero-padded binary string
// (MSB first).
func (p *Protocol) dec2bin(i, bits int) string {
	b := ""
	for i > 0 {
		b = strconv.Itoa(i&1) + b
		i >>= 1
	}
	for len(b) < bits {
		b = "0" + b
	}
	return b
}

// validateIP mirrors Protocol._validateIP.
func (p *Protocol) validateIP(ip string) bool {
	return ipv4Re.MatchString(ip)
}

// validLegacyPasswordSyntax mirrors Protocol._validLegacyPasswordSyntax.
func (p *Protocol) validLegacyPasswordSyntax(password string) (bool, string) {
	if password == "" {
		return false, "Empty passwords are not allowed."
	}
	md5hash, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return false, "Invalid base64-encoding: " + err.Error()
	}
	if string(md5hash) == password {
		return false, "Invalid base64-encoding."
	}
	if len(md5hash) != 16 {
		return false, "Invalid MD5-checksum."
	}
	return true, ""
}

// validPasswordSyntax mirrors Protocol._validPasswordSyntax.
func (p *Protocol) validPasswordSyntax(password string) (bool, string) {
	if password == "" {
		return false, "Empty password."
	}
	return p.validLegacyPasswordSyntax(password)
}

// validUsernameSyntax mirrors Protocol._validUsernameSyntax.
func (p *Protocol) validUsernameSyntax(username string) (bool, string) {
	if username == "" {
		return false, "Username is blank."
	}
	for _, r := range username {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwzyx[]_1234567890", unicode.ToLower(r)) {
			return false, "Only ASCII chars, [], _, 0-9 are allowed in usernames."
		}
	}
	length := utf8.RuneCountInString(username)
	if length < 3 {
		return false, "Username is too short, must be at least 3 characters."
	}
	if length > 20 {
		return false, "Username is too long, max 20 characters."
	}
	return true, ""
}

// validLoginSentence mirrors Protocol._validLoginSentence.
func (p *Protocol) validLoginSentence(sentence string) bool {
	if strings.Count(sentence, "\t") != 2 {
		return false
	}
	parts := strings.SplitN(sentence, "\t", 3)
	lo, la, fl := parts[0], parts[1], parts[2]
	if utf8.RuneCountInString(lo) > 64 || utf8.RuneCountInString(la) > 40 {
		return false
	}
	i := la
	if idx := strings.Index(la, " "); idx >= 0 {
		i = la[:idx]
		m := la[idx+1:]
		if utf8.RuneCountInString(m) > 16 {
			return false
		}
		if _, err := strconv.ParseInt(m, 16, 64); err != nil {
			return false
		}
	}
	v, err := strconv.ParseInt(strings.TrimSpace(i), 10, 64)
	if err != nil || v < 0 || v > 4294967296 {
		return false
	}
	for _, r := range fl {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwzyx ", r) {
			return false
		}
	}
	return true
}

// checkDelayRegistration mirrors Protocol._check_delayed_registration.
func (p *Protocol) checkDelayRegistration(c *Client) (bool, string) {
	if p.root.nonResRegistrations[c.userID] {
		timeWaited := time.Since(c.registerDate)
		totalSeconds := int64(timeWaited / time.Second)
		days := int(math.Floor(float64(totalSeconds) / 86400))
		seconds := totalSeconds - int64(days)*86400
		if days == 0 && seconds < 24*3600 {
			timeRemaining := 24*time.Hour - timeWaited
			return true, "Your registration was detected as a non-residential IP address and will be delayed for 24 hours. Time remaining: " + p.prettyTimeDelta(timeRemaining)
		}
		delete(p.root.nonResRegistrations, c.userID)
	}
	return false, ""
}

// outDenied mirrors Protocol.out_DENIED.
func (p *Protocol) outDenied(c *Client, username, reason string) {
	c.Send("DENIED " + reason)
	log.Printf("[%d] Failed to log in user <%s>: %s", c.sessionID, username, reason)
}

// calcStatus mirrors Protocol._calc_status.
func (p *Protocol) calcStatus(c *Client, status int) {
	statusBits := p.dec2bin(status, 7)
	away := statusBits[5:6]
	ingame := statusBits[6:7]
	accessList := map[string]int{"user": 0, "mod": 1, "admin": 1}
	accessInt, ok := accessList[c.access]
	if !ok {
		accessInt = 0
	}
	botInt := 0
	if c.bot {
		botInt = 1
	}
	ingameTime := c.ingameTime / 60 // hours
	rank := 0
	for _, t := range ranks {
		if ingameTime >= t {
			rank++
		}
	}
	rankBits := p.dec2bin(rank, 3)
	c.isInGame = ingame == "1"
	// Python also sets client.away here, but it is never read (dead store).
	c.status, _ = strconv.Atoi(p.bin2dec(strconv.Itoa(botInt) + strconv.Itoa(accessInt) + rankBits + away + ingame))
}

// calcAccessStatus mirrors Protocol._calc_access_status.
func (p *Protocol) calcAccessStatus(c *Client) {
	c.calcAccess()
	p.calcStatus(c, c.status)
}

// getMotdString mirrors Protocol._get_motd_string.
func (p *Protocol) getMotdString(c *Client) string {
	replaceVars := [][2]string{
		{"{USERNAME}", c.username},
		{"{CLIENTS}", strconv.Itoa(len(p.root.clients))},
		{"{CHANNELS}", strconv.Itoa(len(p.root.channels))},
		{"{BATTLES}", strconv.Itoa(len(p.root.battles))},
		{"{UPTIME}", p.prettyTimeDelta(time.Since(p.root.startTime))},
		{"{MINSPRINGVERSION}", p.root.minSpringVersion},
	}
	var motdString string
	if len(p.root.motd) > 0 {
		for _, line := range p.root.motd {
			for _, kv := range replaceVars {
				line = strings.ReplaceAll(line, kv[0], kv[1])
			}
			motdString += line + "\n"
		}
	} else {
		motdString += "[MOTD]"
	}
	return motdString
}

// sendMotd mirrors Protocol._sendMotd.
func (p *Protocol) sendMotd(c *Client, motdString string) {
	for _, line := range strings.Split(motdString, "\n") {
		c.Send("MOTD " + line)
	}
}

// checkCompat mirrors Protocol._checkCompat.
func (p *Protocol) checkCompat(c *Client) {
	missingTLS := !c.tls

	missingFlags := ""
	for _, flag := range compFlagOrder {
		if _, optional := optionalFlags[flag]; !optional && !c.compat[flag] {
			missingFlags += " " + flag
		}
	}

	deprecFlags := ""
	unknownFlags := ""
	for _, flag := range sortedStringKeys(c.compat) {
		if _, deprecated := deprecatedFlags[flag]; deprecated {
			deprecFlags += " " + flag
			continue
		}
		if _, known := flagMap[flag]; !known {
			unknownFlags += " " + flag
		}
	}

	c.Send("MOTD Server version: " + p.root.serverVersion)

	compatError := len(missingFlags) > 0 || len(deprecFlags) > 0 || len(unknownFlags) > 0
	if !missingTLS && !compatError {
		return
	}

	c.Send("MOTD  -- WARNING --")

	if missingTLS {
		c.Send("MOTD Your client did not use TLS. Your connection is not secure.")
		c.Send("MOTD  -- -- - -- --")
		log.Printf("[%d] <%s> client %q logged in without TLS", c.sessionID, c.username, c.agent)
	}

	if compatError {
		c.Send("MOTD Your client has compatibility errors")
		if len(missingFlags) > 0 {
			c.Send("MOTD   missing flags:" + missingFlags)
		}
		if len(deprecFlags) > 0 {
			c.Send("MOTD   deprecated flags:" + deprecFlags)
		}
		if len(unknownFlags) > 0 {
			c.Send("MOTD   unknown flags:" + unknownFlags)
		}
		c.Send("MOTD  -- -- - -- --")
		log.Printf("[%d] <%s> client %q sent incorrect compat flags %v -- missing:%s, deprecated:%s, unknown:%s",
			c.sessionID, c.username, c.agent, c.compat, missingFlags, deprecFlags, unknownFlags)
	}

	c.Send("MOTD Please update your client / report these issues.")
	c.Send("MOTD  -- -- - -- --")
}

// broadcastAddUser mirrors Protocol.broadcast_AddUser.
func (p *Protocol) broadcastAddUser(c *Client) {
	for _, username := range sortedStringKeys(p.root.usernames) {
		receiver := p.root.usernames[username]
		if c.sessionID == receiver.sessionID {
			continue
		}
		if c.username == receiver.username {
			log.Printf("Tried to send adduser to self: %s!", c.username)
			continue
		}
		receiver.Send(p.clientAddUser(receiver, c))
	}
}

// clientAddUser mirrors Protocol.client_AddUser.
func (p *Protocol) clientAddUser(receiver, user *Client) string {
	return "ADDUSER " + user.username + " " + user.countryCode + " " + strconv.Itoa(user.userID) + " " + user.agent
}

// clientAddBattle mirrors Protocol.client_AddBattle.
func (p *Protocol) clientAddBattle(c *Client, battle *Battle) string {
	host := p.root.clientFromSession(battle.host)
	translatedIP := host.ipAddress
	if host.ipAddress == c.ipAddress {
		translatedIP = host.localIP
	}
	battle.ip = translatedIP
	battle.host = host.sessionID
	if c.compat["u"] {
		return fmt.Sprintf("BATTLEOPENED %d %s %d %s %s %d %d %d %s %s %s\t%s\t%s\t%s\t%s\t%s",
			battle.battleID, battle.bType, battle.natType, host.username, battle.ip, battle.port,
			battle.maxPlayers, battle.passworded(), battle.rank, nilStr(battle.mapHash),
			battle.engine, battle.version, battle.mapName, battle.title, battle.modName, battle.name)
	}
	return fmt.Sprintf("BATTLEOPENED %d %s %d %s %s %d %d %d %s %s %s\t%s\t%s\t%s\t%s",
		battle.battleID, battle.bType, battle.natType, host.username, battle.ip, battle.port,
		battle.maxPlayers, battle.passworded(), battle.rank, nilStr(battle.mapHash),
		battle.engine, battle.version, battle.mapName, battle.title, battle.modName)
}

// sendLoginInfo mirrors Protocol._SendLoginInfo.
func (p *Protocol) sendLoginInfo(c *Client) {
	p.calcStatus(c, 0)
	c.loggedIn = true
	c.bufferSend = true // enqueue all sends to client made from other threads until server state is send

	p.root.userIDs[c.userID] = c
	p.root.usernames[c.username] = c

	log.Printf("[%d] <%s> logged in (access=%s).", c.sessionID, c.username, c.access)
	c.ignored = map[int]bool{}
	for _, ignoredUserID := range p.root.userDB.getIgnoredUserIDs(c.userID) {
		c.ignored[ignoredUserID] = true
	}

	c.Send("ACCEPTED " + c.username)

	p.sendMotd(c, p.getMotdString(c))
	p.checkCompat(c)

	for _, sessionID := range sortedIntKeys(p.root.clients) {
		addClient := p.root.clients[sessionID]
		if !addClient.loggedIn {
			continue
		}
		c.Send(p.clientAddUser(c, addClient))
	}

	for _, battleID := range sortedIntKeys(p.root.battles) {
		battle := p.root.battles[battleID]
		c.Send(p.clientAddBattle(c, battle))
		locked := 0
		if battle.locked {
			locked = 1
		}
		c.Send(fmt.Sprintf("UPDATEBATTLEINFO %s %d %d %s %s", battle.battleIDStr(), battle.spectators, locked, nilStr(battle.mapHash), battle.mapName))
		for _, sessionID := range sortedIntKeys(battle.users) {
			battleClient := p.root.clientFromSession(sessionID)
			if battleClient.sessionID != battle.host {
				c.Send("JOINEDBATTLE " + strconv.Itoa(battle.battleID) + " " + battleClient.username)
			}
		}
	}

	// client status is sent last, so battle status is calculated correctly updated at clients
	for _, sessionID := range sortedIntKeys(p.root.clients) {
		addClient := p.root.clients[sessionID]
		if !addClient.loggedIn {
			continue
		}
		if addClient.status == 0 {
			continue
		}
		c.Send(fmt.Sprintf("CLIENTSTATUS %s %d", addClient.username, addClient.status))
	}

	c.Send("LOGININFOEND")
	c.flushBuffer()
	p.broadcastAddUser(c) // send ADDUSER to all clients except self
	if c.status != 0 {
		p.root.broadcast(fmt.Sprintf("CLIENTSTATUS %s %d", c.username, c.status), "", nil, nil, "", "") // broadcast current client status
	}
}

// inLogin mirrors Protocol.in_LOGIN.
func (p *Protocol) inLogin(c *Client, args []string) {
	username, password := args[0], args[1]
	var localIP string
	if len(args) > 3 {
		localIP = args[3]
	}
	sentenceArgs := ""
	if len(args) > 4 {
		sentenceArgs = args[4]
	}

	// well formed-ness tests
	good, reason := p.validUsernameSyntax(username)
	if !good {
		p.outDenied(c, username, reason)
		return
	}

	good, reason = p.validPasswordSyntax(password)
	if !good {
		p.outDenied(c, username, reason)
		return
	}

	if _, ok := p.root.usernames[username]; ok {
		p.outDenied(c, username, "Already logged in.")
		return
	}

	if sayHooks.isNasty(username) {
		p.outDenied(c, username, "Invalid username: '"+username+"'")
		return
	}

	good, reason = p.root.userDB.checkLoginUser(username, password)
	if !good {
		p.outDenied(c, username, reason)
		return
	}

	delay, reason := p.checkDelayRegistration(c)
	if delay {
		p.outDenied(c, username, reason)
		return
	}

	banned, reason := p.root.userDB.checkBanned(username, c.ipAddress)
	if banned {
		p.outDenied(c, username, reason)
		return
	}

	if sayHooks.isNasty(sentenceArgs) {
		p.outDenied(c, username, "Invalid sentence args")
		return
	}

	var agent, lastSysID, lastMacID string
	if strings.Count(sentenceArgs, "\t") == 0 { // fixme: backwards compat for Melbot / Statserv
		agent = sentenceArgs
		lastSysID = "0"
		lastMacID = "0"
	} else if !p.validLoginSentence(sentenceArgs) {
		log.Printf("WARNING: Invalid login sentence '%s' from <%s>", sentenceArgs, username)
		p.outDenied(c, username, "Invalid sentence format, please update your lobby client.")
		return
	} else {
		parts := strings.SplitN(sentenceArgs, "\t", 3)
		agent = parts[0]
		lastID := parts[1]
		compatFlags := parts[2]
		if idx := strings.Index(lastID, " "); idx >= 0 {
			lastMacID = lastID[:idx]
			lastSysID = lastID[idx+1:]
		} else {
			lastMacID = lastID
			lastSysID = "0" // backwards compat for SL<0.269
		}
		for _, flag := range strings.Split(compatFlags, " ") {
			c.compat[flag] = true
		}
	}

	// login checks complete
	dbuser := p.root.userDB.loginUser(username, password, c.ipAddress, agent, lastSysID, lastMacID, localIP, c.countryCode)

	// update local client fields from DB User values
	c.access = dbuser.access
	c.calcAccess()
	c.username = dbuser.username
	c.password = dbuser.Password
	c.userID = dbuser.userID
	c.bot = dbuser.bot != 0
	c.lastIP = dbuser.lastIP
	c.lastAgent = dbuser.LastAgent
	c.lastSysID = dbuser.LastSysID
	c.lastMacID = dbuser.LastMacID
	c.registerDate = dbuser.RegisterDate
	c.lastLogin = dbuser.LastLogin
	c.ingameTime = dbuser.IngameTime
	c.email = dbuser.Email
	c.agent = agent

	if c.access == "agreement" {
		log.Printf("[%d] Sent user <%s> the terms of service on session.", c.sessionID, dbuser.username)
		if p.root.verificationDB.active() {
			c.Send("AGREEMENT A verification code has been sent to your email address. Please read our terms of service and then enter your four digit code below.")
			c.Send("AGREEMENT ")
		}
		for _, line := range p.root.agreement {
			c.Send("AGREEMENT " + line)
		}
		c.Send("AGREEMENTEND")
		return
	}

	c.localIP = localIP
	if strings.HasPrefix(localIP, "127.") || !p.validateIP(localIP) {
		c.localIP = c.ipAddress
	}

	if p.root.trustedProxies[c.ipAddress] {
		c.setFlagByIP(localIP, false)
	}

	if username != c.username || p.root.userIDs[c.userID] != nil || p.root.usernames[c.username] != nil {
		log.Printf("ERROR: Exception from LOGIN asserts: %s %s %d", username, c.username, c.userID)
	}

	p.root.clientLoginStats(c)
	p.sendLoginInfo(c)
}

// inRegister mirrors Protocol.in_REGISTER.
func (p *Protocol) inRegister(c *Client, args []string) {
	username, password := args[0], args[1]
	email := ""
	if len(args) > 2 {
		email = args[2]
	}

	if p.root.disableSignupURL != "" {
		c.Send("REGISTRATIONURL " + p.root.disableSignupURL)
		c.Send("REGISTRATIONDENIED To register please visit " + p.root.disableSignupURL)
		return
	}

	// well formed-ness tests
	good, reason := p.validUsernameSyntax(username)
	if !good {
		c.Send("REGISTRATIONDENIED " + reason)
		return
	}

	good, reason = p.validPasswordSyntax(password)
	if !good {
		c.Send("REGISTRATIONDENIED " + reason)
		return
	}

	// test if user would be OK on db side (e.g. duplication)
	email = strings.ToLower(email)
	good, reason = p.root.userDB.checkRegisterUser(username, email, c.ipAddress)
	if !good {
		log.Printf("[%d] Registration failed for user <%s>: %s", c.sessionID, username, reason)
		c.Send("REGISTRATIONDENIED " + reason)
		return
	}

	// require a valid looking email address, if we are going to require verification
	if p.root.verificationDB.active() {
		good, reason = p.root.verificationDB.validEmailAddr(email)
		if !good {
			if email == "" {
				reason += " -- If you were not asked to enter one, please update your lobby client!"
			}
			c.Send("REGISTRATIONDENIED " + reason)
			return
		}
	} else {
		email = "" // avoid triggering uniqueness constraint with empty strings
	}

	// rate limit per ip
	recentRegs := p.root.recentRegistrations[c.ipAddress]
	if recentRegs >= 3 && c.ipAddress != p.root.onlineIP {
		c.Send("REGISTRATIONDENIED too many recent registration attempts, please try again later")
		return
	}
	p.root.recentRegistrations[c.ipAddress] = recentRegs + 1

	// save user to db
	// (python ignores register_user's failure and then crashes on a nil
	// lookup; here we deny instead)
	if good, reason = p.root.userDB.registerUser(username, password, c.ipAddress, email, "user"); !good {
		log.Printf("[%d] Registration of <%s> failed: %s", c.sessionID, username, reason)
		c.Send("REGISTRATIONDENIED " + reason)
		return
	}
	clientFromDB := p.root.clientFromUsernameDB(username)
	if clientFromDB == nil {
		log.Printf("[%d] Registration of <%s> failed: user vanished", c.sessionID, username)
		c.Send("REGISTRATIONDENIED user vanished")
		return
	}

	// verification
	verifReason := fmt.Sprintf("registered an account on the SpringRTS lobbyserver (username: %s)", username)
	good, reason = p.root.verificationDB.checkAndSend(clientFromDB.UserID(), email, 4, verifReason)
	if !good {
		c.Send("REGISTRATIONDENIED verification failed: " + reason)
		return
	}

	// declare success
	c.access = "agreement"
	c.Send("REGISTRATIONACCEPTED")

	go p.checkNonresidentialIP(clientFromDB.UserID(), clientFromDB.Username(), c.ipAddress)

	log.Printf("[%d] Successfully registered user <%s>.", c.sessionID, username)
	ipStr := c.ipAddress
	if c.localIP != c.ipAddress {
		ipStr += " " + c.localIP
	}
	p.broadcastModerator(fmt.Sprintf("New: %s %s %s", username, ipStr, c.countryCode))
}

// checkNonresidentialIP mirrors Protocol._check_nonresidential_ip. Python runs
// it in a thread because it does network I/O; here it is a goroutine. The
// network call happens outside any state section; shared state is touched in
// short sections (a section lock taken while the registering command's
// section is still active simply waits for it to finish).
func (p *Protocol) checkNonresidentialIP(userID int, username, ipAddress string) {
	if p.root.iphubXkey == "" {
		return
	}
	var block int
	if ipAddress == p.root.onlineIP {
		block = -1
	} else {
		p.root.stateLock()
		cached, ok := p.root.ipTypeCache[ipAddress]
		p.root.stateUnlock()
		if ok {
			block = cached
		} else {
			req, err := http.NewRequest("GET", "http://v2.api.iphub.info/ip/"+ipAddress, nil)
			if err != nil {
				log.Printf("Failed to check ip info for %s: %s", ipAddress, err)
				return
			}
			req.Header.Set("X-Key", p.root.iphubXkey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("Failed to check ip info for %s: %s", ipAddress, err)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to check ip info for %s: %s", ipAddress, err)
				return
			}
			var parsed struct {
				Block int `json:"block"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				log.Printf("Failed to check ip info for %s: %s", ipAddress, err)
				return
			}
			block = parsed.Block
			p.root.stateLock()
			p.root.ipTypeCache[ipAddress] = block
			p.root.stateUnlock()
		}
	}
	log.Printf("<%s> ip %s has type %d", username, ipAddress, block)
	if block == 1 {
		p.root.stateLock()
		p.root.nonResRegistrations[userID] = true
		p.root.stateUnlock()
	}
}

// inConfirmAgreement mirrors Protocol.in_CONFIRMAGREEMENT.
func (p *Protocol) inConfirmAgreement(c *Client, args []string) {
	verificationCode := ""
	if len(args) > 0 {
		verificationCode = args[0]
	}

	if c.access != "agreement" {
		return
	}

	// python: time_waited.days == 0 and time_waited.seconds < 2;
	// timedelta.seconds is the whole-seconds floor, so this rejects
	// exactly the first 3 seconds
	if timeWaited := time.Since(c.registerDate); timeWaited >= 0 && timeWaited < 3*time.Second {
		p.outDenied(c, c.username, "Please take at least a few seconds to read our terms of service!")
		return
	}

	delay, reason := p.checkDelayRegistration(c)
	if delay {
		p.outDenied(c, c.username, reason)
		return
	}

	good, reason := p.root.verificationDB.verify(c.userID, c.email, verificationCode)
	if !good {
		p.outDenied(c, c.username, reason)
		return
	}

	ipString := ""
	if c.ipAddress != c.lastIP {
		ipString = c.ipAddress + " "
	}
	p.broadcastModerator(fmt.Sprintf("Agr: %s %s %s %s %s", c.username, ipString, c.lastSysID, c.lastMacID, c.agent))
	c.access = "user"
	p.root.userDB.saveUser(c)
	c.calcAccess()
	p.calcStatus(c, c.status)
	p.sendLoginInfo(c)
}
