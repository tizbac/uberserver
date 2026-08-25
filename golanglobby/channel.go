package main

import (
	"fmt"
	"strconv"
	"time"
)

// pyBool renders a bool the way Python's str() does.
func pyBool(v bool) string {
	if v {
		return "True"
	}
	return "False"
}

// nilStr renders a *string the way Python's '%s' % value does (None -> "None").
func nilStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

var maxDateTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// ChannelMute mirrors the mute dict entries in Channel.mutelist.
type ChannelMute struct {
	userID       int
	expires      time.Time
	reason       string
	issuerUserID int
}

// ChannelBan mirrors the ban dict entries in Channel.ban / Channel.ban_ip.
type ChannelBan struct {
	userID       int
	ipAddress    string
	expires      time.Time
	reason       string
	issuerUserID int
}

// BridgedBan mirrors the ban dict entries in Channel.bridged_ban.
type BridgedBan struct {
	bridgedID    int
	expires      time.Time
	reason       string
	issuerUserID int
}

// channelUser is anything nameable as a channel user: an online *Client or
// an offline *OfflineUser read from the db (mirrors the python duck typing
// on .user_id/.username/.last_ip in the Channel methods).
type channelUser interface {
	UserID() int
	Username() string
	LastIP() string
}

// Channel mirrors protocol/Channel.py.
type Channel struct {
	identity string

	// battle is set when this channel is a battle (python's Battle subclass);
	// nil for regular channels.
	battle *Battle

	// db fields
	id           int // id 0 is used for all unregistered channels
	name         string
	key          *string
	ownerUserID  *int // 'founder'
	topic        *string
	topicUserID  *int
	antispam     bool
	censor       bool
	storeHistory bool
	lastUsed     time.Time

	// non-db fields
	operators    map[int]bool // user_ids
	users        map[int]bool // session_ids
	bridgedUsers map[int]bool // bridged_ids

	topicUsername string
	muteList      map[int]*ChannelMute   // user_id -> mute
	ban           map[int]*ChannelBan    // user_id -> ban
	banIP         map[string]*ChannelBan // ip -> ban
	bridgedBan    map[int]*BridgedBan    // bridged_id -> ban

	forwards map[string]bool // channel_names
}

func newChannel(name string) *Channel {
	topic := ""
	return &Channel{
		identity:     "channel",
		name:         name,
		topic:        &topic,
		operators:    map[int]bool{},
		users:        map[int]bool{},
		bridgedUsers: map[int]bool{},
		muteList:     map[int]*ChannelMute{},
		ban:          map[int]*ChannelBan{},
		banIP:        map[string]*ChannelBan{},
		bridgedBan:   map[int]*BridgedBan{},
		forwards:     map[string]bool{},
	}
}

func (c *Channel) broadcast(message string, ignore map[int]bool, flag, notFlag string) {
	server.broadcast(message, c.name, ignore, nil, flag, notFlag)
}

func (c *Channel) channelMessage(message string) {
	if c.identity == "battle" { // backwards compat for clients lacking 'u'
		c.broadcast("CHANNELMESSAGE "+c.name+" "+message, nil, "u", "")
		return
	}
	c.broadcast("CHANNELMESSAGE "+c.name+" "+message, nil, "", "")
}

func (c *Channel) register(client, target *Client) {
	c.setFounder(client, target)
	var topic string
	if c.topic != nil {
		topic = *c.topic
	}
	server.channelDB.register(c.name, topic, target.userID)
	c.recordUse()
}

func (c *Channel) recordUse() {
	c.lastUsed = time.Now()
	server.channelDB.recordUse(c.name)
}

func (c *Channel) unregister(client *Client) {
	c.ownerUserID = nil
	c.topic = nil
	c.operators = map[int]bool{}
	c.channelMessage(fmt.Sprintf("This channel has been unregistered by <%s>", client.username))
	server.channelDB.unRegister(c.name)
}

func (c *Channel) registered() bool {
	return server.channelDB.registered(c.name)
}

func (c *Channel) addUser(client *Client) {
	if c.users[client.sessionID] {
		return
	}
	c.users[client.sessionID] = true
	client.channels[c.name] = true
	if !client.static {
		c.recordUse()
	}

	flag := "" // for legacy clients without 'u', who are not told that they and others are in the __battle__ channel!
	if c.identity == "battle" {
		flag = "u"
	}
	if flag != "" && !client.compat[flag] {
		c.broadcast(fmt.Sprintf("JOINED %s %s", c.name, client.username), nil, flag, "")
		return
	}
	client.Send("JOIN " + c.name)
	c.broadcast(fmt.Sprintf("JOINED %s %s", c.name, client.username), nil, flag, "")

	topicUsername := "ChanServ"
	if c.topicUserID != nil {
		if tc := server.clientFromID(*c.topicUserID); tc != nil {
			topicUsername = tc.username
		} else if u := server.userDB.getClientFromID(*c.topicUserID); u != nil {
			topicUsername = u.Username()
		}
	}
	client.Send(fmt.Sprintf("CHANNELTOPIC %s %s %s", c.name, topicUsername, nilStr(c.topic)))

	if client.compat["u"] {
		bridgedClients := map[string]string{}
		for bridgedID := range c.bridgedUsers {
			bc := server.bridgedClientFromID(bridgedID, false)
			if bc == nil {
				continue
			}
			bridge := server.clientFromID(bc.bridgeUserID)
			if bridge == nil {
				continue
			}
			if bridgedClients[bridge.username] != "" {
				bridgedClients[bridge.username] += " "
			}
			bridgedClients[bridge.username] += bc.username
		}
		for bridgeUsername, names := range bridgedClients {
			client.Send(fmt.Sprintf("CLIENTSFROM %s %s %s", c.name, bridgeUsername, names))
		}
	}

	clientlist := ""
	for sessionID := range c.users {
		if clientlist != "" {
			clientlist += " "
		}
		channelUser := server.clientFromSession(sessionID)
		if channelUser == nil {
			continue
		}
		clientlist += channelUser.username
	}
	client.Send("CLIENTS " + c.name + " " + clientlist)
}

func (c *Channel) removeUser(client *Client, reason string) {
	delete(client.channels, c.name)
	if !c.users[client.sessionID] {
		return
	}

	flag := "" // for legacy clients without 'u'
	if c.identity == "battle" {
		flag = "u"
	}
	if reason != "" {
		c.broadcast(fmt.Sprintf("LEFT %s %s %s", c.name, client.username, reason), nil, flag, "")
	} else {
		c.broadcast(fmt.Sprintf("LEFT %s %s", c.name, client.username), nil, flag, "")
	}
	delete(c.users, client.sessionID)
	if !client.static {
		c.recordUse()
	}
}

func (c *Channel) addBridgedUser(client *Client, bc *BridgedClient) {
	if c.bridgedUsers[bc.bridgedID] {
		return
	}
	c.bridgedUsers[bc.bridgedID] = true
	bc.channels[c.name] = true
	bridge := server.clientFromID(bc.bridgeUserID)
	c.broadcast(fmt.Sprintf("JOINEDFROM %s %s %s", c.name, bridge.username, bc.username), nil, "u", "")
}

func (c *Channel) removeBridgedUser(client channelUser, bc *BridgedClient, reason string) {
	if !c.bridgedUsers[bc.bridgedID] {
		return
	}
	delete(c.bridgedUsers, bc.bridgedID)
	delete(bc.channels, c.name)
	c.broadcast(fmt.Sprintf("LEFTFROM %s %s %s", c.name, bc.username, reason), nil, "u", "")
}

func (c *Channel) isAdmin(client *Client) bool {
	return client != nil && client.accessLevels["admin"]
}

func (c *Channel) isMod(client *Client) bool {
	return client != nil && (client.accessLevels["mod"] || c.isAdmin(client))
}

func (c *Channel) isFounder(client *Client) bool {
	return client != nil && (c.ownerUserID != nil && client.userID == *c.ownerUserID) || c.isMod(client)
}

func (c *Channel) isOp(client *Client) bool {
	return client != nil && (c.operators[client.userID] || c.isFounder(client))
}

func (c *Channel) getAccess(client *Client) string {
	if c.isMod(client) {
		return "mod"
	}
	if c.isFounder(client) {
		return "founder"
	}
	if c.isOp(client) {
		return "op"
	}
	return "normal"
}

func (c *Channel) isMuted(client *Client) bool {
	_, ok := c.muteList[client.userID]
	return ok
}

func (c *Channel) setTopic(client *Client, topic string) {
	if topic == "*" || topic == "" {
		topic = ""
	}
	cur := c.topic
	if cur != nil && topic == *cur {
		return
	}
	if (cur == nil || *cur == "") && topic == "" {
		return
	}
	t := topic
	c.topic = &t
	server.channelDB.setTopic(c.name, topic, client.userID)

	c.broadcast(fmt.Sprintf("CHANNELTOPIC %s %s %s", c.name, client.username, topic), nil, "", "")
	if topic == "" {
		c.channelMessage("Topic removed.")
	} else {
		c.channelMessage("Topic changed.")
	}
}

func (c *Channel) setFounder(client, target *Client) {
	id := target.userID
	c.ownerUserID = &id
	server.channelDB.setFounder(c.name, target.userID)
	c.channelMessage(fmt.Sprintf("<%s> has been set as this %s's founder by <%s>", target.username, c.identity, client.username))
}

func (c *Channel) setAntispam(client *Client, val bool) {
	c.antispam = val
	server.channelDB.setAntispam(c.name, val)
	c.channelMessage(fmt.Sprintf("Anti-spam protection was set to %s by <%s>", pyBool(val), client.username))
}

func (c *Channel) setHistory(client *Client, val bool) {
	c.storeHistory = val
	server.channelDB.setHistory(c.name, val)
	c.channelMessage(fmt.Sprintf("History retention was set to %s by <%s>", pyBool(val), client.username))
}

func (c *Channel) setKey(client *Client, key string) {
	k := key
	server.channelDB.setKey(c.name, &k)
	if key == "*" || key == "" {
		if c.key != nil {
			c.key = nil
			c.channelMessage(fmt.Sprintf("<%s> removed the password of this %s", client.username, c.identity))
		}
	} else {
		k := key
		c.key = &k
		c.channelMessage(fmt.Sprintf("<%s> set a new password for this %s", client.username, c.identity))
	}
}

func (c *Channel) hasKey() bool {
	return c.key != nil && *c.key != "*"
}

func (c *Channel) opUser(client *Client, target channelUser) {
	if c.operators[target.UserID()] {
		return
	}
	c.operators[target.UserID()] = true
	server.channelDB.opUser(c.id, target.UserID())
	c.channelMessage(fmt.Sprintf("<%s> has been added to this %s's operator list by <%s>", target.Username(), c.identity, client.username))

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.opUser(client, target)
		}
	}
}

func (c *Channel) deopUser(client *Client, target channelUser) {
	if !c.operators[target.UserID()] {
		return
	}
	delete(c.operators, target.UserID())
	server.channelDB.deopUser(c.id, target.UserID())
	c.channelMessage(fmt.Sprintf("<%s> has been removed from this %s's operator list by <%s>", target.Username(), c.identity, client.username))

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.deopUser(client, target)
		}
	}
}

func (c *Channel) kickUser(client channelUser, target channelUser) {
	// mirrors hasattr(target, "session_id"): only online clients are removed
	if tc, ok := target.(*Client); ok && c.users[tc.sessionID] {
		c.channelMessage(fmt.Sprintf("<%s> has been removed from this %s by <%s>", tc.username, c.identity, client.Username()))
		c.removeUser(tc, "")
	}

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.kickUser(client, target)
		}
	}
}

func (c *Channel) banUser(client channelUser, target channelUser, expires time.Time, reason string, duration time.Duration) {
	if c.ban[target.UserID()] != nil {
		return
	}
	cb := &ChannelBan{userID: target.UserID(), ipAddress: target.LastIP(), expires: expires, reason: reason, issuerUserID: client.UserID()}
	c.ban[target.UserID()] = cb
	c.banIP[target.LastIP()] = cb
	issuerID := client.UserID()
	server.channelDB.banUser(c.id, &issuerID, target.UserID(), target.LastIP(), expires, reason)
	c.kickUser(client, target)

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.banUser(client, target, expires, reason, duration)
		}
	}
}

func (c *Channel) unbanUser(client *Client, target channelUser) {
	delete(c.ban, target.UserID())
	delete(c.banIP, target.LastIP())
	server.channelDB.unbanUser(c.id, target.UserID())

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.unbanUser(client, target)
		}
	}
}

func (c *Channel) banBridgedUser(client channelUser, bc *BridgedClient, expires time.Time, reason string, duration *time.Duration) {
	if c.bridgedBan[bc.bridgedID] != nil {
		return
	}
	if duration != nil {
		expires = time.Now().Add(*duration)
	} else {
		expires = maxDateTime
	}
	c.bridgedBan[bc.bridgedID] = &BridgedBan{bridgedID: bc.bridgedID, expires: expires, reason: reason, issuerUserID: client.UserID()}
	issuerID := client.UserID()
	server.channelDB.banBridgedUser(c.id, &issuerID, bc.bridgedID, expires, reason)
	c.removeBridgedUser(client, bc, "")
	if c.bridgedUsers[bc.bridgedID] {
		c.channelMessage(fmt.Sprintf("<%s> has been removed from this %s by <%s>", bc.username, c.identity, client.Username()))
	}

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.banBridgedUser(client, bc, expires, reason, duration)
		}
	}
}

func (c *Channel) getBanMessage(client *Client) string {
	var ban *ChannelBan
	if b, ok := c.ban[client.userID]; ok {
		ban = b
	} else if b, ok := c.banIP[client.ipAddress]; ok {
		ban = b
	} else {
		return "not banned"
	}
	return fmt.Sprintf("Cannot join channel '%s' (reason: %s, remaining: %s)", c.name, ban.reason, server.protocol.prettyTimeDelta(ban.expires.Sub(time.Now())))
}

func (c *Channel) unbanBridgedUser(client *Client, bc *BridgedClient) {
	if c.bridgedBan[bc.bridgedID] == nil {
		return
	}
	delete(c.bridgedBan, bc.bridgedID)
	server.channelDB.unbanBridgedUser(c.id, bc.bridgedID)

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.unbanBridgedUser(client, bc)
		}
	}
}

func (c *Channel) getMuteMessage(client *Client) string {
	if c.isMuted(client) {
		mute := c.muteList[client.userID]
		return "muted for " + server.protocol.prettyTimeDelta(mute.expires.Sub(time.Now()))
	}
	return "not muted"
}

func (c *Channel) muteUser(client channelUser, target channelUser, expires time.Time, reason string, duration *time.Duration) {
	if c.muteList[target.UserID()] != nil {
		return
	}
	if duration != nil {
		expires = time.Now().Add(*duration)
	} else {
		expires = maxDateTime
	}
	c.muteList[target.UserID()] = &ChannelMute{userID: target.UserID(), expires: expires, reason: reason, issuerUserID: client.UserID()}
	issuerID := client.UserID()
	server.channelDB.muteUser(c.id, &issuerID, target.UserID(), expires, reason)
	var shown time.Duration
	if duration != nil {
		shown = *duration
	}
	c.channelMessage(fmt.Sprintf("<%s> has been muted by <%s> for %s", client.Username(), target.Username(), server.protocol.prettyTimeDelta(shown)))

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.muteUser(client, target, expires, reason, duration)
		}
	}
}

func (c *Channel) unmuteUser(client *Client, target channelUser, reason string) {
	if c.muteList[target.UserID()] == nil {
		return
	}
	delete(c.muteList, target.UserID())
	server.channelDB.unmuteUser(c.id, target.UserID())
	c.channelMessage(fmt.Sprintf("<%s> has been unmuted by <%s>", target.Username(), client.username))

	for name := range c.forwards {
		if fc, ok := server.channels[name]; ok {
			fc.unmuteUser(client, target, reason)
		}
	}
}

func (c *Channel) addForward(client *Client, to *Channel) {
	c.forwards[to.name] = true
	server.channelDB.addForward(c.id, to.id)

	for userID := range c.operators {
		to.operators[userID] = true
	}
	for userID, m := range c.muteList {
		to.muteList[userID] = m
	}
	for userID, b := range c.ban {
		to.ban[userID] = b
	}
	for ip, b := range c.banIP {
		to.banIP[ip] = b
	}
	for bridgedID, b := range c.bridgedBan {
		to.bridgedBan[bridgedID] = b
	}
	c.channelMessage(fmt.Sprintf("<%s> added forwarding to #%s", client.username, to.name))
	to.channelMessage(fmt.Sprintf("<%s> added forwarding to #%s", client.username, to.name))
}

func (c *Channel) removeForward(client *Client, to *Channel) {
	if !c.forwards[to.name] {
		return
	}
	delete(c.forwards, to.name)
	server.channelDB.removeForward(c.id, to.id)

	c.channelMessage(fmt.Sprintf("<%s> removed forwarding to #%s", client.username, to.name))
	to.channelMessage(fmt.Sprintf("<%s> removed forwarding to #%s", client.username, to.name))
}

// Bot mirrors the bot dict entries in Battle.bots.
type Bot struct {
	owner        string
	battleStatus string
	teamColor    string
	aidll        string
}

// StartRect mirrors the startrect dict entries in Battle.startrects.
type StartRect struct {
	left   string
	top    string
	right  string
	bottom string
}

// Battle mirrors protocol/Battle.py.
type Battle struct {
	*Channel
	battleID   int
	host       int // session_id
	ip         string
	bType      string
	natType    int
	port       int
	title      string
	mapName    string
	mapHash    *string
	modName    string
	hashCode   *string
	engine     string
	version    string
	rank       string // python never int()s this; it is sent back as-is
	maxPlayers int
	spectators int
	locked     bool

	pendingUsers map[int]bool // users who asked to join, waiting for host response

	bots                map[string]*Bot
	scriptTags          map[string]string
	startRects          map[int]*StartRect
	disabledUnits       []string
	replayScript        map[string]string
	replay              bool
	sendingReplayScript bool
}

func newBattle(name string) *Battle {
	b := &Battle{Channel: newChannel(name)}
	b.Channel.battle = b
	b.initBattle()
	return b
}

// initBattle mirrors Battle.__init__Battle__; resets the battle part of the
// channel, leaving channel settings intact.
func (b *Battle) initBattle() {
	b.identity = "battle"
	b.battleID = 0
	b.host = 0
	b.bType = ""
	b.natType = 0
	b.port = 0
	b.title = ""
	b.mapName = ""
	b.mapHash = nil
	b.modName = ""
	b.hashCode = nil
	b.engine = ""
	b.version = ""
	b.rank = ""
	b.maxPlayers = 0
	b.spectators = 0
	b.locked = false
	b.pendingUsers = map[int]bool{}
	b.bots = map[string]*Bot{}
	b.scriptTags = map[string]string{}
	b.startRects = map[int]*StartRect{}
	b.disabledUnits = []string{}
	b.replayScript = map[string]string{}
	b.replay = false
	b.sendingReplayScript = false
}

func (b *Battle) battleIDStr() string {
	if b.battleID == 0 {
		return "None"
	}
	return strconv.Itoa(b.battleID)
}

// joinBattle mirrors Battle.joinBattle (client joins battle + notifies others).
func (b *Battle) joinBattle(client *Client) {
	if client.compat["u"] {
		client.Send(fmt.Sprintf("JOINBATTLE %s %s %s", b.battleIDStr(), nilStr(b.hashCode), b.name))
	} else {
		client.Send(fmt.Sprintf("JOINBATTLE %s %s", b.battleIDStr(), nilStr(b.hashCode)))
	}
	b.addUser(client)

	host := server.clientFromSession(b.host)
	if client != host {
		ignore := map[int]bool{b.host: true, client.sessionID: true}
		server.broadcast(fmt.Sprintf("JOINEDBATTLE %s %s", b.battleIDStr(), client.username), "", ignore, nil, "", "")
		if client.scriptPassword != nil && host.compat["sp"] {
			host.Send(fmt.Sprintf("JOINEDBATTLE %s %s %s", b.battleIDStr(), client.username, *client.scriptPassword))
			client.Send(fmt.Sprintf("JOINEDBATTLE %s %s %s", b.battleIDStr(), client.username, *client.scriptPassword))
		} else {
			host.Send(fmt.Sprintf("JOINEDBATTLE %s %s", b.battleIDStr(), client.username))
			client.Send(fmt.Sprintf("JOINEDBATTLE %s %s", b.battleIDStr(), client.username))
		}
	}

	scripttags := []string{}
	for tag, val := range b.scriptTags {
		scripttags = append(scripttags, tag+"="+val)
	}
	client.Send("SETSCRIPTTAGS " + joinTabs(scripttags))
	if len(b.disabledUnits) > 0 {
		client.Send("DISABLEUNITS " + joinSpaces(b.disabledUnits))
	}

	if b.natType > 0 && client.udpPort > 0 {
		host.Send(fmt.Sprintf("CLIENTIPPORT %s %s %d", client.username, client.ipAddress, client.udpPort))
	}

	specs := 0 // computed but not stored (mirrors Python)
	for sessionID := range b.users {
		battleClient := server.clientFromSession(sessionID)
		if battleClient != nil && battleClient.battleStatus["mode"] == "0" {
			specs++
		}
		battlestatus := b.calcBattleStatus(battleClient)
		client.Send(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", battleClient.username, battlestatus, battleClient.teamColor))
	}

	for name, bot := range b.bots {
		client.Send(fmt.Sprintf("ADDBOT %s %s %s %s %s %s", b.battleIDStr(), name, bot.owner, bot.battleStatus, bot.teamColor, bot.aidll))
	}

	for allyNo, rect := range b.startRects {
		client.Send(fmt.Sprintf("ADDSTARTRECT %d %s %s %s %s", allyNo, rect.left, rect.top, rect.right, rect.bottom))
	}

	client.battleStatus = map[string]string{"ready": "0", "id": "0000", "ally": "0000", "mode": "0", "sync": "00", "side": "00", "handicap": "0000000"}
	client.teamColor = "0"
	id := b.battleID
	client.currentBattle = &id
	client.Send("REQUESTBATTLESTATUS")
}

// leaveBattle mirrors Battle.leaveBattle (client leaves a battle + notifies others).
func (b *Battle) leaveBattle(client *Client) {
	b.removeUser(client, "")

	client.scriptPassword = nil
	client.currentBattle = nil
	client.hostPort = nil

	for bot := range client.battleBots {
		delete(client.battleBots, bot)
		if _, ok := b.bots[bot]; ok {
			delete(b.bots, bot)
			server.broadcastBattle(fmt.Sprintf("REMOVEBOT %s %s", b.battleIDStr(), bot), b.battleID, nil, nil, "", "")
		}
	}
	server.broadcast(fmt.Sprintf("LEFTBATTLE %s %s", b.battleIDStr(), client.username), "", nil, nil, "", "")
	if client.sessionID == b.host {
		return // safety
	}

	oldSpecs := b.spectators
	specs := 0
	for sessionID := range b.users {
		user := server.clientFromSession(sessionID)
		if user != nil && user.battleStatus["mode"] == "0" {
			specs++
		}
	}
	b.spectators = specs
	if oldSpecs != specs {
		locked := 0
		if b.locked {
			locked = 1
		}
		server.broadcast(fmt.Sprintf("UPDATEBATTLEINFO %s %d %d %s %s", b.battleIDStr(), b.spectators, locked, nilStr(b.mapHash), b.mapName), "", nil, nil, "", "")
	}
}

// removeBattle mirrors Battle.removeBattle: remove all users, announce the
// battle is closed, reset the battle part, but leave channel settings intact.
func (b *Battle) removeBattle() {
	for bridgedID := range b.bridgedUsers {
		bc := server.bridgedClientFromID(bridgedID, false)
		if bc == nil {
			continue
		}
		b.removeBridgedUser(server.ChanServ.Client, bc, "")
	}
	for sessionID := range b.pendingUsers {
		client := server.clientFromSession(sessionID)
		if client != nil {
			client.pendingBattle = nil
		}
	}
	for sessionID := range b.users {
		client := server.clientFromSession(sessionID)
		if client == nil {
			continue
		}
		client.scriptPassword = nil
		client.currentBattle = nil
		client.hostPort = nil
		client.battleBots = map[string]*Bot{}
		if client.username == "ChanServ" {
			continue
		}
		b.removeUser(client, "")
	}
	server.protocol.broadcastRemoveBattle(b)
	b.initBattle()
}

func (b *Battle) calcBattleStatus(client *Client) string {
	bs := client.battleStatus
	return server.protocol.bin2dec(fmt.Sprintf("0000%s%s0000%s%s%s%s%s0", bs["side"], bs["sync"], bs["handicap"], bs["mode"], bs["ally"], bs["id"], bs["ready"]))
}

// kickUser overrides Channel.kickUser (fixes the Python host.send bug).
func (b *Battle) kickUser(client *Client, target channelUser) {
	b.Channel.kickUser(client, target)
	host := server.clientFromSession(b.host)
	if host != nil {
		if tc, ok := target.(*Client); ok {
			host.Send(fmt.Sprintf("KICKFROMBATTLE %s %s", b.battleIDStr(), tc.username))
		}
	}
}

func (b *Battle) hasBotflag() bool {
	host := server.clientFromSession(b.host)
	return host != nil && host.bot
}

func (b *Battle) canChangeSettings(client *Client) bool {
	return client.sessionID == b.host
}

// setKey overrides Channel.setKey: battles cannot change their key.
func (b *Battle) setKey(client *Client, key string) {
}

func (b *Battle) passworded() int {
	if b.key == nil || *b.key == "*" {
		return 0
	}
	return 1
}

func joinTabs(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\t"
		}
		out += p
	}
	return out
}

func joinSpaces(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}
